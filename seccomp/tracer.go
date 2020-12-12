//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package seccomp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/elastic/gosigar/psnotify"
	"github.com/nestybox/sysbox-fs/domain"
	unixIpc "github.com/nestybox/sysbox-ipc/unix"
	libseccomp "github.com/nestybox/sysbox-libs/libseccomp-golang"
	utils "github.com/nestybox/sysbox-libs/utils"

	"github.com/sirupsen/logrus"
)

const seccompTracerSockAddr = "/run/sysbox/sysfs-seccomp.sock"

// libseccomp req/resp aliases.
type sysRequest = libseccomp.ScmpNotifReq
type sysResponse = libseccomp.ScmpNotifResp

// Slice of supported syscalls to monitor.
var monitoredSyscalls = []string{
	"mount",
	"umount2",
	"reboot",
	"swapon",
	"swapoff",
	"chown",
	"fchown",
	"fchownat",
}

//
// Seccomp's syscall-monitoring/trapping service struct. External packages
// will solely rely on this struct for their syscall-monitoring demands.
//

type SyscallMonitorService struct {
	nss    domain.NSenterServiceIface        // for nsenter functionality requirements
	css    domain.ContainerStateServiceIface // for container-state interactions
	hds    domain.HandlerServiceIface        // for handlerDB interactions
	prs    domain.ProcessServiceIface        // for process class interactions
	tracer *syscallTracer                    // pointer to actual syscall-tracer instance
}

func NewSyscallMonitorService() *SyscallMonitorService {
	return &SyscallMonitorService{}
}

func (scs *SyscallMonitorService) Setup(
	nss domain.NSenterServiceIface,
	css domain.ContainerStateServiceIface,
	hds domain.HandlerServiceIface,
	prs domain.ProcessServiceIface) {

	scs.nss = nss
	scs.css = css
	scs.hds = hds
	scs.prs = prs

	// Allocate a new syscall-tracer.
	scs.tracer = newSyscallTracer(scs)

	// Initialize and launch the syscall-tracer.
	if err := scs.tracer.start(); err != nil {
		logrus.Fatalf("syscallMonitorService initialization error (%v). Exiting ...",
			err)
	}
}

//
// SeccompSession holds state associated to every seccomp tracee session.
//

type seccompSession struct {
	pid uint32 // pid of the tracee process
	fd  int32  // tracee's seccomp-fd to allow kernel interaction
}

//
// seccompFdPidMap tracks alls processes associated with a given seccomp notify
// file descriptor (i.e., the original tracee plus all it's descendant processes)
//

type seccompFdPidMap struct {
	m map[int][]int // fd -> list of pids
}

func newSeccompFdPidMap() *seccompFdPidMap {
	return &seccompFdPidMap{
		m: make(map[int][]int),
	}
}

func (sfp *seccompFdPidMap) Add(fd int32, pid uint32) {
	sfp.m[int(fd)] = append(sfp.m[int(fd)], int(pid))
}

// Removes the given pid from the list of pids for fd. If the list becomes empty,
// the fd is removed from the map and return value "fdHasNoPids" is set to true.
func (sfp *seccompFdPidMap) Remove(fd int32, pid uint32) (bool, bool) {
	fdi := int(fd)

	pids, ok := sfp.m[fdi]
	if !ok {
		return false, false
	}

	if !utils.IntSliceContains(pids, int(pid)) {
		return false, false
	}

	pids = utils.IntSliceRemove(pids, []int{int(pid)})
	if len(pids) == 0 {
		delete(sfp.m, fdi)
		return true, true
	}

	sfp.m[fdi] = pids
	return false, true
}

//
// Seccomp's syscall-monitor/tracer.
//

type syscallTracer struct {
	sms              *SyscallMonitorService            // backpointer to syscall-monitor service
	srv              *unixIpc.Server                   // unix server listening to seccomp-notifs
	pollsrv          *unixIpc.PollServer               // unix pollserver for non-blocking i/o on seccomp-fd
	syscalls         map[libseccomp.ScmpSyscall]string // hashmap of supported syscalls indexed by id
	mountHelper      *mountHelper                      // generic methods/state utilized for (u)mount ops.
	seccompSessionCh chan seccompSession               // channel over which to communicate new tracee sessions
}

// syscallTracer constructor.
func newSyscallTracer(sms *SyscallMonitorService) *syscallTracer {

	tracer := &syscallTracer{
		sms:              sms,
		syscalls:         make(map[libseccomp.ScmpSyscall]string),
		seccompSessionCh: make(chan seccompSession),
	}

	// Populate hashmap of supported syscalls to monitor.
	for _, syscall := range monitoredSyscalls {
		syscallId, err := libseccomp.GetSyscallFromName(syscall)
		if err != nil {
			logrus.Warnf("Seccomp-tracer initialization error: unknown syscall (%v).",
				syscall)
			return nil
		}
		tracer.syscalls[syscallId] = syscall
	}

	// Populate bind-mounts hashmap. Note that handlers are not operating at
	// this point, so there's no need to acquire locks for this operation.
	handlerDB := sms.hds.HandlerDB()
	if handlerDB == nil {
		logrus.Warnf("Seccomp-tracer initialization error: missing handlerDB")
		return nil
	}
	tracer.mountHelper = newMountHelper(handlerDB)

	return tracer
}

// Start syscall tracer.
func (t *syscallTracer) start() error {

	// Enforce proper support of seccomp-monitoring capabilities by the existing
	// kernel; bail otherwise.
	api, err := libseccomp.GetApi()
	if err != nil {
		logrus.Errorf("Error while obtaining seccomp API level (%v).", err)
		return err
	} else if api < 5 {
		logrus.Errorf("Error: need seccomp API level >= 5; it's currently %d", api)
		return fmt.Errorf("Error: unsupported kernel")
	}

	// Launch a new server to listen to seccomp-tracer's socket. Incoming messages
	// will be handled through a separated / dedicated goroutine.
	srv, err := unixIpc.NewServer(seccompTracerSockAddr, t.connHandler)
	if err != nil {
		logrus.Errorf("Unable to initialize seccomp-tracer server")
		return err
	}
	t.srv = srv

	// Launch a pollServer where to register the fds associated to all the
	// seccomp-tracees.
	pollsrv, err := unixIpc.NewPollServer()
	if err != nil {
		logrus.Errorf("Unable to initialize seccomp-tracer pollserver")
		return err
	}
	t.pollsrv = pollsrv

	go t.sessionsMonitor()

	return nil
}

// Method keeps track of all the 'tracee' processes served by a syscall tracer.
// From a functional standpoint, this routine acts as a garbage-collector for
// this class. Note that no concurrency management is needed here as this
// method runs within its own execution context.
func (t *syscallTracer) sessionsMonitor() error {

	// Maps each process to it's associated seccomp notify fd; each process is
	// associated with exactly one fd
	seccompSessionMap := make(map[uint32]int32)

	// Maps each seccomp notify fd to the list of associated processeses; an fd
	// is associated with a process and all its descendants.
	seccompFdMap := newSeccompFdPidMap()

	// pm is a process event monitor; it tracks process forks and removal events.
	pm, err := psnotify.NewWatcher()
	if err != nil {
		logrus.Error("Could not initialize pid monitor: %s", err)
		return err
	}
	defer pm.Close()

	for {

		// XXX: DEBUG
		logrus.Infof("seccompSessionMap: %v", seccompSessionMap)
		logrus.Infof("seccompFdMap: %v", seccompFdMap)

		select {

		case elem := <-t.seccompSessionCh:
			// Trace syscalls on a new process

			logrus.Infof("Received 'add' notification for seccomp-tracee: %v", elem)

			if err := pm.Watch(int(elem.pid), psnotify.PROC_EVENT_FORK|psnotify.PROC_EVENT_EXIT); err != nil {

				// TODO: this error needs to be notified to whomever sent the
				// elem.pid via the seccompSessionCh; ideally that goes back to
				// sysbox-runc which fails the operation.

				logrus.Errorf("Failed to add process monitor for pid %d; syscall interception won't work for that process.", elem.pid)
			}

			seccompSessionMap[elem.pid] = elem.fd
			seccompFdMap.Add(elem.fd, elem.pid)

		case ev := <-pm.Fork:

			// The process monitor indicates a fork event. This may indicate an
			// actual fork (a new child process) or a reparenting of a child
			// process to another parent. For the former case, we track the new
			// child. For the latter, the child is already tracked, so nothing to
			// do. We can tell if a child process reparented when we find the child
			// in the seccompSessionMap (i.e., it's not a new child).

			logrus.Infof("Received 'fork' notification for seccomp-tracee: %v", ev)

			if _, reparented := seccompSessionMap[uint32(ev.ChildPid)]; reparented {
				continue
			}

			pFd, ok := seccompSessionMap[uint32(ev.ParentPid)]
			if !ok {
				logrus.Errorf("Unexpected error: file-descriptor not found for (parent) pid %d", ev.ParentPid)
				continue
			}

			if err := pm.Watch(ev.ChildPid, psnotify.PROC_EVENT_FORK|psnotify.PROC_EVENT_EXIT); err != nil {
				// TODO: handle this error correctly
				logrus.Errorf("Failed to add process monitor for pid %d; syscall interception won't work for that process.", ev.ChildPid)
				continue
			}

			cElem := seccompSession{
				pid: uint32(ev.ChildPid),
				fd:  pFd,
			}

			seccompSessionMap[cElem.pid] = cElem.fd
			seccompFdMap.Add(cElem.fd, cElem.pid)

		case ev := <-pm.Exit:
			// Remove pid from syscall tracee list
			logrus.Infof("Received 'delete' notification for seccomp-tracee: %v", ev.Pid)

			// Sometimes we get an exit event when the process hasn't really exited
			// but only reparented. Here we check if the process did indeed exit.

			// HERE: how come we are not exiting on all the intermediate processes spawned by Docker inside the container? do we need to wait sometime here?
			// ALSO: do we need to track all children? or can we just track the first child, to deal with the docker exec & case?

			pidExists, err := pidExists(ev.Pid)
			if err == nil && pidExists {
				logrus.Infof("Ignoring 'delete' notification for seccomp-tracee: %v (process continues to exist)", ev.Pid)

				if err := pm.Watch(ev.Pid, psnotify.PROC_EVENT_FORK|psnotify.PROC_EVENT_EXIT); err != nil {
					// TODO: handle this error correctly
					logrus.Errorf("Failed to add process monitor for pid %d; syscall interception won't work for that process.", ev.Pid)
				}

				continue

			} else if err != nil {
				logrus.Errorf("Unexpected error: failed to check if process %d exists: %v; will assume it doesn't exist", ev.Pid, err)
			}

			logrus.Infof("Deleting seccomp notification fd for seccomp-tracee: %v", ev.Pid)

			fd, ok := seccompSessionMap[uint32(ev.Pid)]
			if !ok {
				logrus.Errorf("Unexpected error: file-descriptor not found for pid %d", ev.Pid)
				continue
			}

			delete(seccompSessionMap, uint32(ev.Pid))

			fdHasNoPids, ok := seccompFdMap.Remove(fd, uint32(ev.Pid))
			if !ok {
				logrus.Errorf("Unexpected error: pid %v not found in list for fd %v", ev.Pid, fd)
				continue
			}

			if fdHasNoPids {
				if err := syscall.Close(int(fd)); err != nil {
					logrus.Fatal(err)
				}
				t.pollsrv.StopWait(fd)
			}

		case err := <-pm.Error:
			// TODO: deal with process monitor errors
			logrus.Errorf("Received 'error' notification for seccomp-tracee: %s", err)
		}
	}

	return nil
}

// Tracer's connection-handler method. Executed within a dedicated goroutine (one
// per connection).
func (t *syscallTracer) connHandler(c *net.UnixConn) error {

	// Obtain seccomp-notification's file-descriptor and associated context (cntr).
	pid, cntrID, fd, err := unixIpc.RecvSeccompInitMsg(c)
	if err != nil {
		return err
	}

	logrus.Infof("seccompTracer connection on fd %d from pid %d cntrId %s",
		fd, pid, cntrID)

	// Send seccompSession details to parent monitor-service for tracking purposes.
	t.seccompSessionCh <- seccompSession{uint32(pid), fd}

	// Send Ack message back to sysbox-runc.
	if err = unixIpc.SendSeccompInitAckMsg(c); err != nil {
		return err
	}

	for {
		// Wait for incoming seccomp-notification msg to be available.
		// Return here to exit this goroutine in case of error as that
		// implies that seccomp-fd is not valid anymore.
		if err := t.pollsrv.StartWaitRead(fd); err != nil {
			logrus.Infof("Seccomp-fd i/o error returned (%v). Exiting seccomp-tracer processing on fd %d pid %d",
				err, fd, pid)
			return err
		}

		// Retrieves seccomp-notification message.
		req, err := libseccomp.NotifReceive(libseccomp.ScmpFd(fd))
		if err != nil {
			if err == syscall.EINTR {
				logrus.Warnf("Incomplete NotifReceive() execution (%v) on fd %d pid %d",
					err, fd, pid)
				continue
			}

			logrus.Warnf("Unexpected error during NotifReceive() execution (%v) on fd %d pid %d",
				err, fd, pid)
			continue
		}

		// Process the incoming syscall and obtain response for seccomp-tracee.
		resp := t.process(req, fd, cntrID)

		// Responds to a previously received seccomp-notification.
		err = libseccomp.NotifRespond(libseccomp.ScmpFd(fd), resp)
		if err != nil {
			if err == syscall.EINTR {
				logrus.Warnf("Incomplete NotifRespond() execution (%v) on fd %d pid %d",
					err, fd, pid)
				continue
			}

			logrus.Warnf("Unexpected error during NotifRespond() execution (%v) on fd %d pid %d",
				err, fd, pid)
			continue
		}
	}

	return nil
}

// Syscall processing entrypoint. Returns the response to be delivered to the
// process (seccomp-tracee) generating the syscall.
func (t *syscallTracer) process(
	req *sysRequest,
	fd int32,
	cntrID string) *sysResponse {

	var (
		resp *sysResponse
		err  error
	)

	// Obtain container associated to the received containerId value.
	cntr := t.sms.css.ContainerLookupById(cntrID)
	if cntr == nil {
		logrus.Warnf("Received seccompNotifMsg generated by unknown container: %v",
			cntrID)
		return t.createErrorResponse(req.Id, syscall.Errno(syscall.EPERM))
	}

	syscallId := req.Data.Syscall
	syscallStr := t.syscalls[syscallId]

	switch syscallStr {
	case "mount":
		resp, err = t.processMount(req, fd, cntr)

	case "umount2":
		resp, err = t.processUmount(req, fd, cntr)

	case "reboot":
		resp, err = t.processReboot(req, fd, cntr)

	case "swapon":
		resp, err = t.processSwapon(req, fd, cntr)

	case "swapoff":
		resp, err = t.processSwapoff(req, fd, cntr)

	case "chown":
		resp, err = t.processChown(req, fd, cntr)

	case "fchown":
		resp, err = t.processFchown(req, fd, cntr)

	case "fchownat":
		resp, err = t.processFchownat(req, fd, cntr)

	default:
		logrus.Warnf("Unsupported syscall notification received (%v) on fd %d pid %d",
			syscallId, fd, req.Pid)
		return t.createErrorResponse(req.Id, syscall.EINVAL)
	}

	// If an 'infrastructure' error is encountered during syscall processing,
	// then return a common error back to tracee process. By 'infrastructure'
	// errors we are referring to problems beyond the end-user realm: EPERM
	// error during Open() doesn't qualify, whereas 'nsenter' operational
	// errors or inexistent "/proc/pid/mem" does.
	if err != nil {
		logrus.Warnf("Error during syscall \"%v\" processing on fd %d pid %d (%v)",
			syscallStr, fd, req.Pid, err)
		return t.createErrorResponse(req.Id, syscall.EINVAL)
	}

	// TOCTOU check.
	if err := libseccomp.NotifIdValid(libseccomp.ScmpFd(fd), req.Id); err != nil {
		logrus.Warnf("TOCTOU check failed on fd %d pid %d: req.Id is no longer valid (%s)",
			fd, req.Pid, err)
		return t.createErrorResponse(req.Id, err)
	}

	return resp
}

func (t *syscallTracer) processMount(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Infof("Received mount syscall from pid %d", req.Pid)

	argPtrs := []uint64{
		req.Data.Args[0],
		req.Data.Args[1],
		req.Data.Args[2],
		req.Data.Args[4],
	}
	args, err := t.processMemParse(req.Pid, argPtrs)
	if err != nil {
		return nil, err
	}

	mount := &mountSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		MountSyscallPayload: &domain.MountSyscallPayload{
			Source: args[0],
			Target: args[1],
			FsType: args[2],
			Data:   args[3],
			Flags:  req.Data.Args[3],
		},
	}

	logrus.Info(mount)

	// cap_sys_admin capability is required for mount operations.
	process := t.sms.prs.ProcessCreate(req.Pid, 0, 0)
	if !process.IsSysAdminCapabilitySet() {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	// Resolve mount target and verify that process has the proper rights to
	// access each of the components of the path.
	err = process.PathAccess(mount.Target, 0)
	if err != nil {
		return t.createErrorResponse(req.Id, err), nil
	}

	// Collect process attributes required for mount execution.
	mount.uid = process.Uid()
	mount.gid = process.Gid()
	mount.cwd = process.Cwd()
	mount.root = process.Root()

	// To simplify mount processing logic, convert to absolute path if dealing
	// with a relative path request.
	if !filepath.IsAbs(mount.Target) {
		mount.Target = filepath.Join(mount.cwd, mount.Target)
	}

	// Process mount syscall.
	return mount.process()
}

func (t *syscallTracer) processUmount(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Infof("Received umount syscall from pid %d", req.Pid)

	argPtrs := []uint64{req.Data.Args[0]}
	args, err := t.processMemParse(req.Pid, argPtrs)
	if err != nil {
		return nil, err
	}

	umount := &umountSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		UmountSyscallPayload: &domain.UmountSyscallPayload{
			Target: args[0],
			Flags:  req.Data.Args[1],
		},
	}

	logrus.Info(umount)

	// As per man's capabilities(7), cap_sys_admin capability is required for
	// umount operations. Otherwise, return here and let kernel handle the mount
	// instruction.
	process := t.sms.prs.ProcessCreate(req.Pid, 0, 0)
	if !(process.IsSysAdminCapabilitySet()) {
		return t.createErrorResponse(req.Id, syscall.EPERM), nil
	}

	// Resolve umount target and verify that process has the proper rights to
	// access each of the components of the path.
	err = process.PathAccess(umount.Target, 0)
	if err != nil {
		return t.createErrorResponse(req.Id, err), nil
	}

	// Collect process attributes required for umount execution.
	umount.uid = process.Uid()
	umount.gid = process.Gid()
	umount.cwd = process.Cwd()
	umount.root = process.Root()

	// To simplify umount processing logic, convert to absolute path if dealing
	// with a relative path request.
	if !filepath.IsAbs(umount.Target) {
		umount.Target = filepath.Join(umount.cwd, umount.Target)
	}

	// Process umount syscall.
	return umount.process()
}

func (t *syscallTracer) processChown(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	argPtrs := []uint64{req.Data.Args[0]}
	args, err := t.processMemParse(req.Pid, argPtrs)
	if err != nil {
		return nil, err
	}

	if len(args) < 1 {
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	path := args[0]
	uid := int64(req.Data.Args[1])
	gid := int64(req.Data.Args[2])

	chown := &chownSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		path:     path,
		ownerUid: uid,
		ownerGid: gid,
	}

	return chown.processChown()
}

func (t *syscallTracer) processFchown(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	// We trap fchown() for the same reason we trap chown() (see processChown()).

	pathFd := int32(req.Data.Args[0])
	uid := int64(req.Data.Args[1])
	gid := int64(req.Data.Args[2])

	chown := &chownSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		pathFd:   pathFd,
		ownerUid: uid,
		ownerGid: gid,
	}

	return chown.processChown()
}

func (t *syscallTracer) processFchownat(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	// We trap fchownat() for the same reason we trap chown() (see processChown()).

	// Get the path argument
	argPtrs := []uint64{req.Data.Args[1]}
	args, err := t.processMemParse(req.Pid, argPtrs)
	if err != nil {
		return nil, err
	}

	if len(args) < 1 {
		return t.createErrorResponse(req.Id, syscall.EINVAL), nil
	}

	path := args[0]

	// Get the other args
	dirFd := int32(req.Data.Args[0])
	uid := int64(req.Data.Args[2])
	gid := int64(req.Data.Args[3])
	flags := int(req.Data.Args[4])

	chown := &chownSyscallInfo{
		syscallCtx: syscallCtx{
			syscallNum: int32(req.Data.Syscall),
			reqId:      req.Id,
			pid:        req.Pid,
			cntr:       cntr,
			tracer:     t,
		},
		path:     path,
		ownerUid: uid,
		ownerGid: gid,
		dirFd:    dirFd,
		flags:    flags,
	}

	return chown.processFchownat()
}

func (t *syscallTracer) processReboot(
	req *sysRequest,
	fd int32,
	cntrID domain.ContainerIface) (*sysResponse, error) {

	logrus.Warnf("Received reboot syscall")

	return t.createSuccessResponse(req.Id), nil
}

func (t *syscallTracer) processSwapon(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Warnf("Received swapon syscall")

	return t.createSuccessResponse(req.Id), nil
}

func (t *syscallTracer) processSwapoff(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	logrus.Warnf("Received swapoff syscall")

	return t.createSuccessResponse(req.Id), nil
}

// processMemParser iterates through the tracee process' /proc/pid/mem file to
// identify the indirect arguments utilized by the syscall in transit. The
// assumption here is that the process instantiating the syscall is 'stopped'
// at the time that this routine is executed. That is, tracee runs within a
// a single execution context (single-thread), and thereby, its memory can be
// safely referenced.
func (t *syscallTracer) processMemParse(pid uint32, argPtrs []uint64) ([]string, error) {

	name := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %s", name, err)
	}
	defer f.Close()

	result := make([]string, len(argPtrs))

	reader := bufio.NewReader(f)
	var line string

	// Iterate through the memory locations passed by caller.
	for i, address := range argPtrs {
		if address == 0 {
			result[i] = ""
		} else {
			reader.Reset(f)
			_, err := f.Seek(int64(address), 0)
			if err != nil {
				return nil, fmt.Errorf("seek of %s failed: %s", name, err)
			}
			line, err = reader.ReadString('\x00')
			if err != nil {
				return nil, fmt.Errorf("read of %s at offset %d failed: %s", name, address, err)
			}
			result[i] = strings.TrimSuffix(line, "\x00")
		}
	}

	return result, nil
}

func (t *syscallTracer) createSuccessResponse(id uint64) *sysResponse {

	resp := &sysResponse{
		Id:    id,
		Error: 0,
		Val:   0,
		Flags: 0,
	}

	return resp
}

func (t *syscallTracer) createContinueResponse(id uint64) *sysResponse {

	resp := &sysResponse{
		Id:    id,
		Error: 0,
		Val:   0,
		Flags: libseccomp.NotifRespFlagContinue,
	}

	return resp
}

func (t *syscallTracer) createErrorResponse(id uint64, err error) *sysResponse {

	// Override the passed error if this one doesn't match the supported type.
	rcvdError, ok := err.(syscall.Errno)
	if !ok {
		rcvdError = syscall.EINVAL
	}

	resp := &sysResponse{
		Id:    id,
		Error: int32(rcvdError),
		Val:   0,
		Flags: 0,
	}

	return resp
}
