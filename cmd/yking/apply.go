package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/licentiapoetica/yking/internal/elevate"
	"github.com/licentiapoetica/yking/internal/luks"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/targets"
)

// cmdApply: yking apply [--yes] [--pause-on-error] [--tui SOCK] PLAN.json
func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation (the diff was already reviewed)")
	pause := fs.Bool("pause-on-error", false, "wait for Enter after an error (terminal use)")
	tui := fs.String("tui", "", "started by the TUI: ask questions over this askpass socket, never read a terminal")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: yking apply [--yes] PLAN.json")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}

	if !elevate.IsRoot() {
		fwd := []string{"apply"}
		if *yes {
			fwd = append(fwd, "--yes")
		}
		if *pause {
			fwd = append(fwd, "--pause-on-error")
		}
		if *tui != "" {
			fwd = append(fwd, "--tui", *tui)
		}
		return elevate.Reexec(append(fwd, path)...)
	}

	if *tui != "" {
		// The TUI reads our output through a pipe. If yking is closed
		// meanwhile, a write must not kill a half-done apply (SIGPIPE).
		signal.Ignore(syscall.SIGPIPE)
		return applyAsRoot(path, true, *tui)
	}
	err = applyAsRoot(path, *yes, "")
	if err != nil && *pause {
		fmt.Fprintln(os.Stderr, "yking: apply failed:", err)
		fmt.Fprint(os.Stderr, "Press Enter to return to yking… ")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	return err
}

// applyAsRoot applies the plan. tuiSock != "": started by the TUI (the
// dead-man switch asks there).
func applyAsRoot(path string, yes bool, tuiSock string) error {
	p, err := plan.Load(path)
	if err != nil {
		return err
	}
	a := targets.Applier()
	if err := a.Check(p); err != nil {
		return err
	}
	fmt.Printf("Plan %s: %s\n%s", p.ID, p.Description, p.Summary())
	if !yes {
		d, err := p.Diff()
		if err != nil {
			return err
		}
		fmt.Println()
		fmt.Print(d)
		if !confirm("Apply these changes?") {
			return fmt.Errorf("aborted")
		}
	}
	changed := targets.PlanPaths(p)
	boot := targets.BootCritical(changed)
	if boot {
		// From here until rebuild + verification are done, a dying terminal
		// or Ctrl+C must not leave half-built boot images behind.
		signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		defer signal.Reset(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		fmt.Println("yking: boot files are being changed — this takes a minute and cannot be interrupted. Do not power off.")
		if err := luks.SetPending(p.ID); err != nil {
			return err
		}
	}
	m, err := a.Apply(p)
	if err != nil {
		if boot {
			luks.ClearPending() // Apply restores on failure; nothing half-done
		}
		return err
	}
	if targets.TouchesPAM(p) {
		// Lockout-critical: keep only if the user confirms it works.
		dm := func() error { return deadman(a, m, os.Stdin, os.Stdout) }
		if tuiSock != "" {
			dm = func() error { return deadmanTUI(a, m, tuiSock) }
		}
		if err := dm(); err != nil {
			return err
		}
	}
	if err := runReloads(changed); err == nil {
		err = targets.Verify(changed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "yking: verification failed: %v\n", err)
		}
		if err != nil && targets.BootCritical(changed) {
			return bootRollback(a, m, err)
		}
	} else if targets.BootCritical(changed) {
		return bootRollback(a, m, err)
	}
	if boot {
		luks.ClearPending()
	}
	fmt.Printf("Applied %s. Undo with: yking rollback %s\n", m.ID, m.ID)
	return nil
}

// bootRollback restores boot files after a failed rebuild/verification and
// rebuilds again from the restored files.
func bootRollback(a *plan.Applier, m *plan.Manifest, cause error) error {
	fmt.Fprintln(os.Stderr, "yking: restoring the previous boot files and rebuilding…")
	if _, err := a.Rollback(m.ID, true); err != nil {
		return fmt.Errorf("%v; ROLLBACK FAILED: %v — backups in %s/%s", cause, err, a.BackupRoot, m.ID)
	}
	var changed []string
	for _, e := range m.Entries {
		changed = append(changed, e.Path)
	}
	if err := runReloads(changed); err != nil {
		return fmt.Errorf("%v; files restored but rebuilding failed too: %v — do not reboot before fixing (yking luks repair)", cause, err)
	}
	luks.ClearPending()
	return fmt.Errorf("%v — rolled back, boot is as before", cause)
}

// runReloads runs the fixed reload/rebuild commands for changed paths
// (udev, systemd, mkinitcpio, GRUB). The commands come from yking, never
// from a plan. Returns the first failure.
func runReloads(changed []string) error {
	// mkinitcpio and grub-mkconfig do not fsync their output: without this,
	// a hard reset right after "done" can lose grub.cfg or an image (seen in
	// the VM: new initramfs, old grub.cfg).
	defer syscall.Sync()
	var first error
	for _, c := range targets.Reloads(changed) {
		fmt.Printf("yking: running %s\n", strings.Join(c, " "))
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "yking: %s failed: %v\n", strings.Join(c, " "), err)
			if first == nil {
				first = fmt.Errorf("%s: %w", c[0], err)
			}
		}
	}
	return first
}

// cmdRollback: yking rollback [--force] [--yes] [ID]
func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	force := fs.Bool("force", false, "restore even if files changed after yking wrote them")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	userFiles := fs.Bool("user", false, "roll back a change to your own files (e.g. ~/.config/Yubico/u2f_keys, ~/.ssh/config); no root")
	fs.Parse(args)
	if fs.NArg() > 1 {
		return fmt.Errorf("usage: yking rollback [--user] [--force] [ID]")
	}
	if *userFiles {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		return rollbackWith(targets.UserApplier(home), fs.Arg(0), *force, *yes)
	}
	if !elevate.IsRoot() {
		fwd := []string{"rollback"}
		if *force {
			fwd = append(fwd, "--force")
		}
		if *yes {
			fwd = append(fwd, "--yes")
		}
		return elevate.Reexec(append(fwd, fs.Args()...)...)
	}

	return rollbackWith(targets.Applier(), fs.Arg(0), *force, *yes)
}

func rollbackWith(a *plan.Applier, id string, force, yes bool) error {
	if id == "" {
		m, err := a.Latest()
		if err != nil {
			return err
		}
		id = m.ID
	}
	h, err := a.History()
	if err != nil {
		return err
	}
	for _, m := range h {
		if m.ID == id {
			fmt.Println(m.Describe())
		}
	}
	if !yes && !confirm("Roll back this plan?") {
		return fmt.Errorf("aborted")
	}
	m, err := a.Rollback(id, force)
	if err != nil {
		return err
	}
	var changed []string
	for _, e := range m.Entries {
		changed = append(changed, e.Path)
	}
	if err := runReloads(changed); err != nil {
		return fmt.Errorf("rolled back %s, but rebuilding failed: %w", id, err)
	}
	fmt.Printf("Rolled back %s.\n", id)
	return nil
}

func cmdHistory() error {
	h, err := plan.NewApplier().History()
	if err != nil {
		return err
	}
	fmt.Println("System files (undo: yking rollback ID):")
	if len(h) == 0 {
		fmt.Println("  none")
	}
	for _, m := range h {
		fmt.Println("  " + m.Describe())
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	uh, err := targets.UserApplier(home).History()
	if err != nil {
		return err
	}
	if len(uh) > 0 {
		fmt.Println("Your files (undo: yking rollback --user ID):")
		for _, m := range uh {
			fmt.Println("  " + m.Describe())
		}
	}
	return nil
}

func confirm(q string) bool {
	fmt.Printf("%s [y/N] ", q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}
