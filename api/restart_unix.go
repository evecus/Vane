//go:build !windows

package api

import "syscall"

// restartExec replaces the current process image with a new invocation of the
// same binary on Unix-like systems. This is a zero-downtime in-process restart.
func restartExec(exe string, args, env []string) error {
	return syscall.Exec(exe, args, env)
}
