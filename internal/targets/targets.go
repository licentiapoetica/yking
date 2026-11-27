// Package targets lists every directory the elevated apply may write to,
// each with its content validator. Adding a directory here is a security
// decision: keep it small and the validators strict.
package targets

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/luks"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
)

// Default returns the production targets.
func Default() []plan.Target {
	return []plan.Target{
		{Dir: "/etc/yking", Validate: validateYkingFile},
		{Dir: pam.EtcDir, Validate: pam.Validate},
		{Dir: filepath.Dir(events.RulePath), Validate: events.ValidateRule},
		{Dir: filepath.Dir(events.UnitPath), Validate: events.ValidateUnit},
		{Dir: filepath.Dir(events.BinaryPath), Validate: events.ValidateBinary},
		{Dir: "/etc", Validate: validateEtcFile},
		{Dir: filepath.Dir(luks.GrubDefault), Validate: luks.ValidateGrubDefault},
		{Dir: filepath.Dir(luks.GrubFallback), Validate: luks.ValidateFallbackScript},
		{Dir: filepath.Dir(luks.ConsoleDropIn), Validate: luks.ValidateConsoleDropIn},
		{Dir: filepath.Dir(luks.MkinitcpioDropIn), Validate: luks.ValidateMkinitcpioDropIn},
	}
}

// validateEtcFile allows exactly two files directly in /etc.
func validateEtcFile(path string, content []byte) error {
	switch path {
	case luks.MkinitcpioConf:
		return luks.ValidateMkinitcpio(path, content)
	case luks.Crypttab:
		return luks.ValidateCrypttab(path, content)
	}
	return fmt.Errorf("yking does not write %s", path)
}

func validateYkingFile(path string, content []byte) error {
	switch filepath.Base(path) {
	case "keyring.toml":
		_, err := keyring.Parse(content)
		return err
	case "events.toml":
		_, err := events.Parse(content)
		return err
	case "mkinitcpio-fallback.conf":
		return luks.ValidateMkinitcpio(path, content)
	default:
		return fmt.Errorf("unknown yking config file %s", filepath.Base(path))
	}
}

// Applier returns the production applier with all targets.
func Applier() *plan.Applier {
	a := plan.NewApplier()
	a.Targets = Default()
	return a
}

// UserApplier writes the user's own files (no root): only the pam_u2f
// mapping directory, with backups under ~/.local/state/yking/backups.
func UserApplier(home string) *plan.Applier {
	a := plan.NewApplier()
	a.BackupRoot = filepath.Join(home, ".local", "state", "yking", "backups")
	a.Targets = []plan.Target{{Dir: filepath.Dir(pam.DefaultMappingPath(home)), Validate: pam.ValidateMapping}}
	return a
}

// TouchesPAM reports whether a plan writes PAM files (lockout-critical).
func TouchesPAM(p *plan.Plan) bool { return touches(paths(p), pam.EtcDir+"/") }

// Reloads returns the FIXED commands to run after files under these paths
// changed (never taken from a plan).
func Reloads(changed []string) [][]string {
	var out [][]string
	if touches(changed, events.RulePath) {
		out = append(out, []string{"udevadm", "control", "--reload"})
	}
	if touches(changed, events.UnitPath) {
		out = append(out, []string{"systemctl", "daemon-reload"})
	}
	return append(out, luks.Rebuilds(changed)...)
}

// BootCritical reports whether a failed rebuild must roll the plan back.
func BootCritical(changed []string) bool { return len(luks.Rebuilds(changed)) > 0 }

// Verify runs the post-apply checks for what changed.
func Verify(changed []string) error { return luks.VerifyBoot(changed) }

func paths(p *plan.Plan) []string {
	var out []string
	for _, s := range p.Steps {
		out = append(out, s.Path)
	}
	return out
}

// PlanPaths lists the paths a plan writes.
func PlanPaths(p *plan.Plan) []string { return paths(p) }

func touches(changed []string, prefix string) bool {
	for _, c := range changed {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}
