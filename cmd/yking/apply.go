package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/licentiapoetica/yking/internal/elevate"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/targets"
)

// cmdApply: yking apply [--yes] [--pause-on-error] PLAN.json
func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation (the diff was already reviewed)")
	pause := fs.Bool("pause-on-error", false, "wait for Enter after an error (used by the TUI)")
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
		return elevate.Reexec(append(fwd, path)...)
	}

	err = applyAsRoot(path, *yes)
	if err != nil && *pause {
		fmt.Fprintln(os.Stderr, "yking: apply failed:", err)
		fmt.Fprint(os.Stderr, "Press Enter to return to yking… ")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	return err
}

func applyAsRoot(path string, yes bool) error {
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
	m, err := a.Apply(p)
	if err != nil {
		return err
	}
	if targets.TouchesPAM(p) {
		// Lockout-critical: keep only if the user confirms it works.
		if err := deadman(a, m, os.Stdin, os.Stdout); err != nil {
			return err
		}
	}
	runReloads(targets.PlanPaths(p))
	fmt.Printf("Applied %s. Undo with: yking rollback %s\n", m.ID, m.ID)
	return nil
}

// runReloads runs the fixed reload commands for changed paths (udev rules,
// systemd units). The commands come from yking, never from a plan.
func runReloads(changed []string) {
	for _, c := range targets.Reloads(changed) {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "yking: %s failed: %v\n", strings.Join(c, " "), err)
		} else {
			fmt.Printf("yking: ran %s\n", strings.Join(c, " "))
		}
	}
}

// cmdRollback: yking rollback [--force] [--yes] [ID]
func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	force := fs.Bool("force", false, "restore even if files changed after yking wrote them")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	userFiles := fs.Bool("user", false, "roll back a change to your own files (e.g. ~/.config/Yubico/u2f_keys); no root")
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
	runReloads(changed)
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
