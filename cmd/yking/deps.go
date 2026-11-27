package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/deps"
	"github.com/licentiapoetica/yking/internal/elevate"
	"github.com/licentiapoetica/yking/internal/pam"
)

// enableUnits are the only units yking enables.
var enableUnits = []string{"pcscd.socket"}

// cmdDeps: yking deps [install [--tui SOCK]]
func cmdDeps(args []string) error {
	check := func() []deps.Problem {
		return deps.Check(deps.Local(func() bool { return pam.ModuleExists("pam_u2f.so") }, nil))
	}
	if len(args) == 0 {
		ps := check()
		for _, p := range ps {
			fmt.Printf("%s — %s\n", p.What, p.For)
		}
		for _, f := range deps.Fixes(ps) {
			fmt.Println("  " + f)
		}
		if len(ps) == 0 {
			fmt.Println("tools and services present")
		}
		return nil
	}
	if args[0] != "install" {
		return errors.New("usage: yking deps [install]")
	}
	sock := ""
	if len(args) == 3 && args[1] == "--tui" {
		sock = args[2]
	} else if len(args) != 1 {
		return errors.New("usage: yking deps install")
	}
	if !elevate.IsRoot() {
		return elevate.Reexec(append([]string{"deps"}, args...)...)
	}

	// Computed here, as root, from yking's own table: nothing from outside.
	osr, _ := os.ReadFile("/etc/os-release")
	d := deps.DistroOf(string(osr))
	pkgs, units := deps.Actions(check())
	if len(pkgs) == 0 && len(units) == 0 {
		fmt.Println("Nothing to install.")
		return nil
	}
	if len(pkgs) > 0 && deps.InstallArgs(d, pkgs) == nil {
		return errors.New("unknown distribution: install " + strings.Join(pkgs, " ") + " yourself")
	}
	ui, closeUI, err := newUI(sock)
	if err != nil {
		return err
	}
	defer closeUI()
	var plan []string
	if len(pkgs) > 0 {
		plan = append(plan, strings.Join(deps.InstallArgs(d, pkgs), " "))
	}
	for _, u := range units {
		plan = append(plan, "systemctl enable --now "+u)
	}
	if ui.choose("yking will run:\n\n  "+strings.Join(plan, "\n  "),
		[]askpass.Option{{Key: "enter", Label: "install"}, {Key: "n", Label: "cancel"}}) != "enter" {
		return errors.New("cancelled; nothing installed")
	}

	run := func(timeout time.Duration, argv ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		cmd.Stdout, cmd.Stderr = ui.out(), ui.out()
		return cmd.Run()
	}
	if len(pkgs) > 0 {
		ui.phase("installing " + strings.Join(pkgs, " "))
		if err := run(15*time.Minute, deps.InstallArgs(d, pkgs)...); err != nil {
			hint := ""
			if d == deps.Debian {
				hint = " (try: sudo apt update)"
			}
			return fmt.Errorf("install failed: %w%s", err, hint)
		}
	}
	for _, u := range units {
		if !slices.Contains(enableUnits, u) {
			return fmt.Errorf("refusing to enable %s", u)
		}
		ui.phase("enabling " + u)
		if err := run(time.Minute, "systemctl", "enable", "--now", u); err != nil {
			return fmt.Errorf("enabling %s failed: %w", u, err)
		}
	}
	if left := check(); len(left) > 0 {
		for _, p := range left {
			ui.say("still: %s — %s", p.What, p.For)
		}
		return errors.New("not everything could be fixed")
	}
	ui.say("All tools and services present.")
	return nil
}
