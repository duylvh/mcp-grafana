//go:build windows

package mcpgrafana

// Windows has no O_NOFOLLOW; symlink creation there needs elevated rights.
const openNoFollow = 0

func isSymlinkOpenError(error) bool { return false }
