//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package implementations

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/kernel/cap_last_cap handler
//
// Documentation: The value in this file exposes the numerical value of the
// highest capability supported by the running kernel ('37' as of today's
// latest / 5.X kernels ).
//
type KernelLastCapHandler struct {
	Name      string
	Path      string
	Type      domain.HandlerType
	Enabled   bool
	Cacheable bool
	Service   domain.HandlerService
}

func (h *KernelLastCapHandler) Lookup(n domain.IOnode, pid uint32) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() method on %v handler", h.Name)

	// Identify the pidNsInode corresponding to this pid.
	pidInode := h.Service.FindPidNsInode(pid)
	if pidInode == 0 {
		return nil, errors.New("Could not identify pidNsInode")
	}

	return n.Stat()
}

func (h *KernelLastCapHandler) Getattr(n domain.IOnode, pid uint32) (*syscall.Stat_t, error) {

	logrus.Debugf("Executing Getattr() method on %v handler", h.Name)

	commonHandler, ok := h.Service.FindHandler("commonHandler")
	if !ok {
		return nil, fmt.Errorf("No commonHandler found")
	}

	return commonHandler.Getattr(n, pid)
}

func (h *KernelLastCapHandler) Open(n domain.IOnode, pid uint32) error {

	logrus.Debugf("Executing %v Open() method\n", h.Name)

	flags := n.OpenFlags()
	if flags != syscall.O_RDONLY {
		return fuse.IOerror{Code: syscall.EACCES}
	}

	if err := n.Open(); err != nil {
		logrus.Debug("Error opening file ", h.Path)
		return fuse.IOerror{Code: syscall.EIO}
	}

	return nil
}

func (h *KernelLastCapHandler) Close(n domain.IOnode) error {

	logrus.Debugf("Executing Close() method on %v handler", h.Name)

	return nil
}

func (h *KernelLastCapHandler) Read(n domain.IOnode, pid uint32,
	buf []byte, off int64) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	// We are dealing with a single integer element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if off > 0 {
		return 0, io.EOF
	}

	name := n.Name()
	path := n.Path()

	// Identify the container holding the process represented by this pid. This
	// action can only succeed if the associated container has been previously
	// registered in sysbox-fs.
	css := h.Service.StateService()
	cntr := css.ContainerLookupByPid(pid)
	if cntr == nil {
		logrus.Errorf("Could not find the container originating this request (pid %v)", pid)
		return 0, errors.New("Container not found")
	}

	// Check if this resource has been initialized for this container. Otherwise,
	// fetch the information from the host FS and store it accordingly within
	// the container struct.
	data, ok := cntr.Data(path, name)
	if !ok {
		// Read from host FS to extract the existing 'panic' interval value.
		curHostVal, err := n.ReadLine()
		if err != nil && err != io.EOF {
			logrus.Error("Could not read from file ", h.Path)
			return 0, fuse.IOerror{Code: syscall.EIO}
		}

		// High-level verification to ensure that format is the expected one.
		_, err = strconv.Atoi(curHostVal)
		if err != nil {
			logrus.Errorf("Unsupported content read from file %v, error %v", h.Path, err)
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}

		data = curHostVal
		cntr.SetData(path, name, data)
	}

	data += "\n"

	return copyResultBuffer(buf, []byte(data))
}

func (h *KernelLastCapHandler) Write(n domain.IOnode, pid uint32,
	buf []byte) (int, error) {

	logrus.Debugf("Executing %v Write() method", h.Name)

	return 0, nil
}

func (h *KernelLastCapHandler) ReadDirAll(n domain.IOnode, pid uint32) ([]os.FileInfo, error) {
	return nil, nil
}

func (h *KernelLastCapHandler) GetName() string {
	return h.Name
}

func (h *KernelLastCapHandler) GetPath() string {
	return h.Path
}

func (h *KernelLastCapHandler) GetEnabled() bool {
	return h.Enabled
}

func (h *KernelLastCapHandler) GetType() domain.HandlerType {
	return h.Type
}

func (h *KernelLastCapHandler) GetService() domain.HandlerService {
	return h.Service
}

func (h *KernelLastCapHandler) SetEnabled(val bool) {
	h.Enabled = val
}

func (h *KernelLastCapHandler) SetService(hs domain.HandlerService) {
	h.Service = hs
}