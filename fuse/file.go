//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package fuse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
)

type File struct {
	// File name.
	name string

	// File absolute-path + name.
	path string

	// File attributes.
	attr *fuse.Attr

	// I/O abstraction to represent each file/dir.
	ionode domain.IOnode

	// Pointer to parent fuseService hosting this file/dir.
	server *fuseServer
}

//
// NewFile method serves as File constructor.
//
func NewFile(name string, path string, attr *fuse.Attr, srv *fuseServer) *File {

	newFile := &File{
		name:   name,
		path:   path,
		attr:   attr,
		server: srv,
		ionode: srv.service.ios.NewIOnode(name, path, 0),
	}

	return newFile
}

//
// Attr FS operation.
//
func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {

	logrus.Debugf("Requested Attr() operation for entry %v", f.path)

	// Simply return the attributes that were previously collected during the
	// lookup() execution.
	*a = *f.attr

	return nil
}

//
// Getattr FS operation.
//
func (f *File) Getattr(
	ctx context.Context,
	req *fuse.GetattrRequest,
	resp *fuse.GetattrResponse) error {

	logrus.Debugf("Requested GetAttr() operation for entry %v (Req ID=%#v)", f.path, uint64(req.ID))

	// Use the attributes obtained during Lookup()
	resp.Attr = *f.attr

	// Override the uid & gid attributes with the requester'ss user-ns root uid
	// & gid. In the future we should return the requester's user-ns root uid &
	// gid instead; this will help us to support "unshare -U -m --mount-proc"
	// inside a sys container.
	resp.Attr.Uid = f.server.container.UID()
	resp.Attr.Gid = f.server.container.GID()

	return nil
}

//
// Open FS operation.
//
func (f *File) Open(
	ctx context.Context,
	req *fuse.OpenRequest,
	resp *fuse.OpenResponse) (fs.Handle, error) {

	logrus.Debugf("Requested Open() operation for entry %v (Req ID=%#v)", f.path, uint64(req.ID))

	f.ionode.SetOpenFlags(int(req.Flags))

	// Lookup the associated handler within handler-DB.
	handler, ok := f.server.service.hds.LookupHandler(f.ionode)
	if !ok {
		logrus.Errorf("No supported handler for %v resource", f.path)
		return nil, fmt.Errorf("No supported handler for %v resource", f.path)
	}

	request := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Container: f.server.container,
	}

	// Handler execution.
	err := handler.Open(f.ionode, request)
	if err != nil && err != io.EOF {
		logrus.Debugf("Open() error: %v", err)
		return nil, err
	}

	//
	// Due to the nature of procfs and sysfs, files lack explicit sizes (other
	// than zero) as regular files have. In consequence, read operations (also
	// writes) may not be properly handled by kernel, as these ones extend
	// beyond the file sizes reported by Attr() / GetAttr().
	//
	// A solution to this problem is to rely on O_DIRECT flag for all the
	// interactions with procfs/sysfs files. By making use of this flag,
	// sysbox-fs will ensure that it receives all read/write requests
	// generated by fuse-clients, regardless of the file-size issue mentioned
	// above. For regular files, this approach usually comes with a cost, as
	// page-cache is being bypassed for all files I/O; however, this doesn't
	// pose a problem for Inception as we are dealing with special FSs.
	//
	resp.Flags |= fuse.OpenDirectIO

	return f, nil
}

//
// Release FS operation.
//
func (f *File) Release(ctx context.Context, req *fuse.ReleaseRequest) error {

	logrus.Debugf("Requested Release() operation for entry %v (Req ID=%#v)", f.path, uint64(req.ID))

	// Lookup the associated handler within handler-DB.
	handler, ok := f.server.service.hds.LookupHandler(f.ionode)
	if !ok {
		logrus.Errorf("No supported handler for %v resource", f.path)
		return fmt.Errorf("No supported handler for %v resource", f.path)
	}

	// Handler execution.
	err := handler.Close(f.ionode)

	return err
}

//
// Read FS operation.
//
func (f *File) Read(
	ctx context.Context,
	req *fuse.ReadRequest,
	resp *fuse.ReadResponse) error {

	logrus.Debugf("Requested Read() operation for entry %v (Req ID=%#v)", f.path, uint64(req.ID))

	if f.ionode == nil {
		logrus.Error("Read() error: File should be properly defined by now")
		return fuse.ENOTSUP
	}

	// Adjust receiving buffer to the request's size.
	resp.Data = resp.Data[:req.Size]

	// Identify the associated handler and execute it accordingly.
	handler, ok := f.server.service.hds.LookupHandler(f.ionode)
	if !ok {
		logrus.Errorf("Read() error: No supported handler for %v resource", f.path)
		return fmt.Errorf("No supported handler for %v resource", f.path)
	}

	request := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Offset:    req.Offset,
		Data:      resp.Data,
		Container: f.server.container,
	}

	// Handler execution.
	n, err := handler.Read(f.ionode, request)
	if err != nil && err != io.EOF {
		logrus.Debugf("Read() error: %v", err)
		return err
	}

	resp.Data = resp.Data[:n]

	return nil
}

//
// Write FS operation.
//
func (f *File) Write(
	ctx context.Context,
	req *fuse.WriteRequest,
	resp *fuse.WriteResponse) error {

	logrus.Debugf("Requested Write() operation for entry %v (Req ID=%#v)", f.path, uint64(req.ID))

	if f.ionode == nil {
		logrus.Error("Write() error: File should be properly defined by now")
		return fuse.ENOTSUP
	}

	// Lookup the associated handler within handler-DB.
	handler, ok := f.server.service.hds.LookupHandler(f.ionode)
	if !ok {
		logrus.Errorf("Write() error: No supported handler for %v resource", f.path)
		return fmt.Errorf("No supported handler for %v resource", f.path)
	}

	request := &domain.HandlerRequest{
		ID:        uint64(req.ID),
		Pid:       req.Pid,
		Uid:       req.Uid,
		Gid:       req.Gid,
		Data:      req.Data,
		Container: f.server.container,
	}

	// Handler execution.
	n, err := handler.Write(f.ionode, request)
	if err != nil && err != io.EOF {
		logrus.Debugf("Write() error: %v", err)
		return err
	}

	resp.Size = n

	return nil
}

//
// Setattr FS operation.
//
func (f *File) Setattr(
	ctx context.Context,
	req *fuse.SetattrRequest,
	resp *fuse.SetattrResponse) error {

	logrus.Debugf("Requested Setattr() operation for entry %v (Req ID=%#v)", f.path, uint64(req.ID))

	// No file attr changes are allowed in a procfs, with the exception of
	// 'size' modifications which are needed to allow write()/truncate() ops.
	// All other 'fuse.SetattrValid' operations will be rejected.
	if req.Valid.Size() {
		return nil
	}

	return fuse.EPERM
}

//
// Forget FS operation.
//
func (f *File) Forget() {

	logrus.Debugf("Requested Forget() operation for entry %v", f.path)
}

//
// Size method returns the 'size' of a File element.
//
func (f *File) Size() uint64 {
	return f.attr.Size
}

//
// Mode method returns the 'mode' of a File element.
//
func (f *File) Mode() os.FileMode {
	return f.attr.Mode
}

//
// ModTime method returns the modification-time of a File element.
//
func (f *File) ModTime() time.Time {
	return f.attr.Mtime
}

// getUsernsRootUid returns the uid and gid for the root user in the user-ns associated
// with the given request.
func (f *File) getUsernsRootUid(reqPid, reqUid, reqGid uint32) (uint32, uint32, error) {

	usernsInode := f.server.service.hds.FindUserNsInode(reqPid)
	if usernsInode == 0 {
		return 0, 0, errors.New("Could not identify userNsInode")
	}

	if usernsInode == f.server.service.hds.HostUserNsInode() {
		return 0, 0, nil
	}

	// TODO: for now we return the root uid and gid associated with the the sys container.
	// in the future we should return the requester's user-ns root uid & gid instead; this
	// will help us to support "unshare -U -m --mount-proc" inside a sys container.

	prs := f.server.service.hds.ProcessService()
	css := f.server.service.hds.StateService()

	process := prs.ProcessCreate(reqPid, reqUid, reqGid)
	cntr := css.ContainerLookupByProcess(process)

	if cntr == nil {
		return 0, 0, errors.New("Could not find container")
	}

	return cntr.UID(), cntr.GID(), nil
}

//
// statToAttr helper function to translate FS node-parameters from unix/kernel
// format to FUSE ones.
//
// Kernel FS node attribs:  fuse.attr (fuse_kernel*.go)
// FUSE node attribs:       fuse.Attr (fuse.go)
//
// TODO: Place me in a more appropriate location
//
func statToAttr(s *syscall.Stat_t) fuse.Attr {

	var a fuse.Attr

	a.Inode = uint64(s.Ino)
	a.Size = uint64(s.Size)
	a.Blocks = uint64(s.Blocks)

	a.Atime = time.Unix(s.Atim.Sec, s.Atim.Nsec)
	a.Mtime = time.Unix(s.Mtim.Sec, s.Mtim.Nsec)
	a.Ctime = time.Unix(s.Ctim.Sec, s.Ctim.Nsec)

	a.Mode = os.FileMode(s.Mode)
	a.Nlink = uint32(s.Nlink)
	a.Uid = uint32(s.Uid)
	a.Gid = uint32(s.Gid)
	a.Rdev = uint32(s.Rdev)
	a.BlockSize = uint32(s.Blksize)

	return a
}
