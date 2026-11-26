// Package elevate re-runs yking with root privileges for the apply step.
// The TUI itself always runs as the user.
package elevate

import (
	"errors"
	"os"
	"os/exec"
)

// IsRoot reports whether the process already has root.
func IsRoot() bool { return os.Geteuid() == 0 }

// Self returns a command that runs this yking binary with args as root:
// directly when already root, else through sudo, falling back to pkexec.
func Self(args ...string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if IsRoot() {
		return exec.Command(self, args...), nil
	}
	for _, tool := range []string{"sudo", "pkexec"} {
		if p, err := exec.LookPath(tool); err == nil {
			return exec.Command(p, append([]string{self}, args...)...), nil
		}
	}
	return nil, errors.New("need root to apply changes, but neither sudo nor pkexec is installed")
}

// Reexec runs this binary as root with args, attached to the terminal, and
// returns its exit error.
func Reexec(args ...string) error {
	cmd, err := Self(args...)
	if err != nil {
		return err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
