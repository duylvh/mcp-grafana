//go:build !windows

package mcpgrafana

import (
	"errors"
	"syscall"
)

const openNoFollow = syscall.O_NOFOLLOW

// isSymlinkOpenError reports the failure O_NOFOLLOW causes on a symlink.
func isSymlinkOpenError(err error) bool { return errors.Is(err, syscall.ELOOP) }
