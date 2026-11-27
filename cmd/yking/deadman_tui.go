package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/plan"
)

// deadmanTUI is the dead-man switch when the apply was started from the
// TUI (`apply --tui SOCK`): the same rules as deadman, but the questions
// are asked in the TUI over its askpass socket, and the sudo test asks
// for the PIN there too (`sudo -A`). Nothing reads a terminal.
//
// Fail-safe: any answer other than an explicit keep (r, no answer within
// the time, the TUI gone, a signal) restores the previous PAM files.
func deadmanTUI(a *plan.Applier, m *plan.Manifest, sock string) error {
	var once sync.Once
	var rbErr error
	rollback := func(why string) error {
		once.Do(func() {
			fmt.Printf("yking: %s — restoring the previous PAM files…\n", why)
			if _, err := a.Rollback(m.ID, false); err != nil {
				if _, err2 := a.Rollback(m.ID, true); err2 != nil {
					rbErr = fmt.Errorf("ROLLBACK FAILED (%v); originals are in %s", err2, filepath.Join(a.BackupRoot, m.ID))
					return
				}
			}
			fmt.Println("yking: done, everything is as before.")
			rbErr = fmt.Errorf("PAM change rolled back: %s", why)
		})
		return rbErr
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(sig)
	stopSig := make(chan struct{})
	defer close(stopSig)
	go func() {
		select {
		case s := <-sig:
			fmt.Println("yking:", rollback("received "+s.String()))
			exit(1)
		case <-stopSig:
		}
	}()

	var services []string
	for _, e := range m.Entries {
		services = append(services, filepath.Base(e.Path))
	}
	fmt.Printf("yking: PAM change applied for %s — not kept yet.\n", strings.Join(services, ", "))

	if slices.Contains(services, "sudo") {
		key, err := askpass.Choose(sock,
			"PAM change applied for "+strings.Join(services, ", ")+" — not kept yet.\n\n"+
				"Test sudo with the NEW config now? yking runs `sudo -v` as you;\n"+
				"authenticate the way the new config expects.",
			[]askpass.Option{{Key: "enter", Label: "test sudo"}, {Key: "n", Label: "skip the test"}, {Key: "r", Label: "roll back"}},
			time.Time{})
		switch {
		case err != nil:
			return rollback("no answer from yking (" + err.Error() + ")")
		case key == "r":
			return rollback("you chose to roll back")
		case key == "n":
			fmt.Println("yking: sudo test skipped.")
		case key == "enter":
			askpass.Phase(sock, "sudo test with the NEW config")
			if err := testSudoTUI(sock); err != nil {
				fmt.Printf("yking: sudo test FAILED: %v\n", err)
				return rollback("sudo test failed")
			}
			fmt.Println("yking: sudo test OK.")
		default:
			return rollback("unexpected answer")
		}
	}

	askpass.Phase(sock, "keep the PAM change?")
	deadline := time.Now().Add(deadmanTUITimeout)
	key, err := askpass.Choose(sock,
		"1. Lock the screen (Meta+L) and unlock it, if the lock screen changed.\n"+
			"2. Optional, in another terminal:  sudo -k && sudo true\n"+
			"3. Then press k here to keep the change.\n\n"+
			"r, closing yking, or no answer in time restores your previous PAM files.",
		[]askpass.Option{{Key: "k", Label: "keep"}, {Key: "r", Label: "roll back now"}},
		deadline)
	switch {
	case err == nil && key == "k":
		fmt.Println("yking: keeping the change.")
		return nil
	case err == nil && key == "r":
		return rollback("you chose to roll back")
	case errors.Is(err, os.ErrDeadlineExceeded) || (err != nil && time.Now().After(deadline)):
		return rollback("no confirmation within " + deadmanTUITimeout.String())
	case err != nil:
		return rollback("no answer from yking (" + err.Error() + ")")
	}
	return rollback("unexpected answer")
}

// Swappable for tests.
var (
	deadmanTUITimeout = deadmanTimeout
	testSudoTUI       = testSudoAsUserTUI
)

// testSudoAsUserTUI is testSudoAsUser with `sudo -A`: no terminal; the
// PIN (or password) prompt goes to the TUI through yking's askpass.
func testSudoAsUserTUI(sock string) error {
	uidStr := os.Getenv("SUDO_UID")
	if uidStr == "" {
		uidStr = os.Getenv("PKEXEC_UID")
	}
	if uidStr == "" || uidStr == "0" {
		return fmt.Errorf("cannot tell which user to test as")
	}
	u, err := user.LookupId(uidStr)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	var groups []uint32
	if gs, err := u.GroupIds(); err == nil {
		for _, g := range gs {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				groups = append(groups, uint32(n))
			}
		}
	}
	run := func(args ...string) error {
		cmd := exec.Command("sudo", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}}
		cmd.Env = []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username,
			"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=" + os.Getenv("LANG"),
			"SUDO_ASKPASS=" + self, askpass.EnvSock + "=" + sock}
		cmd.Dir = u.HomeDir
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	if err := run("-k"); err != nil {
		return fmt.Errorf("sudo -k: %w", err)
	}
	fmt.Printf("yking: running `sudo -A -v` as %s — authenticate the way the new config expects.\n", u.Username)
	return run("-A", "-v")
}
