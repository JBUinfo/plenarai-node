//go:build windows

package setup

import (
	"os/exec"
	"syscall"
)

const detachedProcess = 0x00000008
const createNoWindow = 0x08000000

// startDetached starts a process detached from the parent, with no visible window.
func startDetached(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNoWindow,
	}
	return cmd.Start()
}
