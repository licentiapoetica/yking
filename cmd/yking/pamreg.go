package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/pam"
)

// cmdPAMRegister runs pamu2fcfg for the TUI. pamu2fcfg reads a PIN only
// from a terminal, so it gets a pseudo-terminal: its PIN question is passed
// to the TUI (asked once; a second question stops it) and the credential
// line goes to stdout. yking pam register
func cmdPAMRegister(args []string) error {
	if len(args) != 1 || args[0] != "register" {
		return errors.New("usage: yking pam register (run by the TUI)")
	}
	sock := os.Getenv(askpass.EnvSock)
	if sock == "" {
		return errors.New("yking pam register runs from the TUI (c)")
	}
	origin, err := pam.Origin()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Touch the key when it blinks.")
	cred, err := runOnPTY(pam.RegisterCommand(origin), func() (string, error) {
		pin, ok, err := askpass.Ask(sock, askpass.KindAsk, "FIDO2 PIN for the new PAM credential")
		if err == nil && !ok {
			err = errors.New("cancelled")
		}
		return pin, err
	})
	if err != nil {
		return err
	}
	fmt.Println(cred)
	return nil
}

// openPTY returns a new pseudo-terminal pair (no echo of what is typed:
// the PIN never appears in the output read back).
func openPTY() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	if t, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS); err == nil {
		t.Lflag &^= unix.ECHO
		unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, t)
	}
	return master, slave, nil
}

// runOnPTY runs cmd on a pseudo-terminal. A PIN question ("…PIN…:") is
// answered with ask(), once; a second one kills cmd. Returns the
// credential line (":…"); other output goes to stderr.
func runOnPTY(cmd *exec.Cmd, ask func() (string, error)) (string, error) {
	master, slave, err := openPTY()
	if err != nil {
		return "", err
	}
	defer master.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		slave.Close()
		return "", err
	}
	slave.Close()

	var out bytes.Buffer
	asked := false
	stop := func(why error) (string, error) {
		cmd.Process.Kill()
		cmd.Wait()
		return "", why
	}
	buf := make([]byte, 4096)
	for {
		n, rerr := master.Read(buf) // EIO once cmd exits
		if n > 0 {
			out.Write(buf[:n])
			tail := strings.ToLower(out.String()[max(0, out.Len()-200):])
			if strings.Contains(tail, "pin") && strings.HasSuffix(strings.TrimSpace(tail), ":") {
				if asked {
					return stop(errors.New("the PIN was asked again (not accepted); stopped so no further attempt is used"))
				}
				asked = true
				pin, err := ask()
				if err != nil {
					return stop(err)
				}
				master.Write([]byte(pin + "\n"))
				out.WriteString("\n") // answered: not matched again
			}
		}
		if rerr != nil {
			break
		}
	}
	werr := cmd.Wait()
	cred := ""
	for _, l := range strings.Split(out.String(), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, ":") {
			cred = l
		} else if l != "" && !strings.Contains(strings.ToLower(l), "pin") {
			fmt.Fprintln(os.Stderr, l) // the tool's messages, never the PIN line
		}
	}
	if werr != nil {
		return "", fmt.Errorf("%s: %w", cmd.Path, werr)
	}
	if cred == "" {
		return "", errors.New("no credential in the output")
	}
	return cred, nil
}
