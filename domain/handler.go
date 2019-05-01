package domain

import "os"

type Handler struct {
	Name    string
	Path    string
	Enabled bool
	Service HandlerService
	HandlerIface
}

type HandlerIface interface {
	// FS operations.
	Open(node IOnode) error
	Close(node IOnode) error
	Read(node IOnode, pidInode Inode, buf []byte, off int64) (int, error)
	Write(node IOnode, pidInode Inode, buf []byte) (int, error)
	ReadDirAll(node IOnode, pidInode Inode) ([]os.FileInfo, error)

	// getters/setters.
	GetName() string
	GetPath() string
	GetEnabled() bool
	SetEnabled(val bool)
	SetService(hs HandlerService)
}

type HandlerService interface {
	RegisterHandler(h HandlerIface) error
	UnregisterHandler(h HandlerIface) error
	LookupHandler(i IOnode) (HandlerIface, bool)
	EnableHandler(h HandlerIface) error
	DisableHandler(h HandlerIface) error
	StateService() ContainerStateService
}