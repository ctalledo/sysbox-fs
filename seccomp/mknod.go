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
	"fmt"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"golang.org/x/sys/unix"
)

// MountSyscall information structure.
type mknodSyscallInfo struct {
	syscallCtx                  // syscall generic info
	*domain.MknodSyscallPayload // mknod-syscall specific details
}

// Mknod syscall processing wrapper instruction.
func (m *mknodSyscallInfo) process() (*sysResponse, error) {

	// Validate incoming mknod attributes.
	if !m.validate() {
		return m.tracer.createContinueResponse(m.reqId), nil
	}

	// Create instruction's payload.
	payload := m.createMknodPayload()
	if payload == nil {
		return nil, fmt.Errorf("Could not construct ReMount payload")
	}

	nss := m.tracer.sms.nss
	event := nss.NewEvent(
		m.syscallCtx.pid,
		&domain.AllNSsButUser,
		&domain.NSenterMessage{
			Type:    domain.MknodSyscallRequest,
			Payload: payload,
		},
		nil,
	)

	// Launch nsenter-event.
	err := nss.SendRequestEvent(event)
	if err != nil {
		return nil, err
	}

	// Obtain nsenter-event response.
	responseMsg := nss.ReceiveResponseEvent(event)
	if responseMsg.Type == domain.ErrorResponse {
		resp := m.tracer.createErrorResponse(
			m.reqId,
			responseMsg.Payload.(fuse.IOerror).Code)
		return resp, nil
	}

	return m.tracer.createSuccessResponse(m.reqId), nil
}

// Build instructions payload required for overlay-mount operations.
func (m *mknodSyscallInfo) createMknodPayload() *domain.MknodSyscallPayload {

	// Create a process struct to represent the process generating the 'mount'
	// instruction, and extract its capabilities to hand them out to 'nsenter'
	// logic.
	//process := m.tracer.sms.prs.ProcessCreate(m.pid, 0, 0)

	// Set payload instruction for mknod request.
	payload := &domain.MknodSyscallPayload{
		Header: domain.NSenterMsgHeader{
			Pid:  m.pid,
			Uid:  m.uid,
			Gid:  m.gid,
			Root: m.root,
			Cwd:  m.cwd,
			// CapSysAdmin:    process.IsSysAdminCapabilitySet(),
			// CapDacRead:     process.IsDacReadCapabilitySet(),
			// CapDacOverride: process.IsDacOverrideCapabilitySet(),
		},
		Path: m.Path,
		Mode: m.Mode,
		Dev:  m.Dev,
	}

	return payload
}

//
func (m *mknodSyscallInfo) validate() bool {

	if m.Mode&unix.S_IFMT == unix.S_IFCHR {
		dev := unix.Mkdev(0, 0)
		if m.Dev == dev {
			return true
		}
	}

	return false
}

// 	switch (mode & S_IFMT) {
// 	case S_IFCHR:
// 		if (dev == makedev(0, 0)) // whiteout
// 			return 0;
// 		else if (dev == makedev(5, 1)) // /dev/console
// 			return 0;
// 		else if (dev == makedev(1, 7)) // /dev/full
// 			return 0;
// 		else if (dev == makedev(1, 3)) // /dev/null
// 			return 0;
// 		else if (dev == makedev(1, 8)) // /dev/random
// 			return 0;
// 		else if (dev == makedev(5, 0)) // /dev/tty
// 			return 0;
// 		else if (dev == makedev(1, 9)) // /dev/urandom
// 			return 0;
// 		else if (dev == makedev(1, 5)) // /dev/zero
// 			return 0;
// 	}
// 	return -EPERM;
// }

func (m *mknodSyscallInfo) String() string {
	return fmt.Sprintf("path: %s, mode = %d, dev = %d, root = %s, cwd = %s",
		m.Path, m.Mode, m.Dev, m.root, m.cwd)
}
