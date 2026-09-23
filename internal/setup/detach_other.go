//go:build !windows

package setup

import "os/exec"

func startDetached(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Start()
}
