package seccomp

import (
	"fmt"
	"os"
)

// Checks if a process with the given pid exists.
func pidExists(pid int) (bool, error) {

	// Our current checking mechanism is very simple but not the best; in the future, we
	// should consider replacing it with the newly added pidfd_* syscalls in Linux.

	path := fmt.Sprintf("/proc/%d", pid)

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}
