//go:build windows

package api

import (
	"fmt"
	"os"
	"os/exec"
)

// restartExec spawns a new process on Windows (syscall.Exec is not available)
// then exits the current process. The process supervisor is expected to manage
// the transition (e.g. NSSM, Task Scheduler, or a service wrapper).
func restartExec(exe string, args, env []string) error {
	cmd := exec.Command(exe, args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn child: %w", err)
	}
	os.Exit(0)
	return nil // unreachable
}
