package pam

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/plan"
)

// Default locations.
const (
	EtcDir    = "/etc/pam.d"
	VendorDir = "/usr/lib/pam.d"
)

// IncludeDirs are searched for included services.
var IncludeDirs = []string{EtcDir, VendorDir}

// ModuleDirs are searched for PAM modules.
var ModuleDirs = []string{"/usr/lib/security", "/lib/security", "/usr/lib64/security", "/lib/x86_64-linux-gnu/security"}

// Service describes a PAM service yking can manage.
type Service struct {
	Name string
	Desc string
	// LoginPath services count for "a password still gets you in".
	LoginPath bool
	// LockScreen services start authenticating the moment the screen locks
	// — often right after the key was pulled. Without pam_u2f's
	// "interactive" option they fail at once and (KDE) never prompt again:
	// a hard lockout. yking always sets "interactive" for them.
	LockScreen bool
}

// Known services, in display order. Only those present are shown.
var Known = []Service{
	{"sudo", "sudo (admin commands in a terminal)", true, false},
	{"sddm", "SDDM login screen", true, false},
	{"plasmalogin", "Plasma login screen", true, false},
	{"kde", "KDE lock screen", false, true},
	{"polkit-1", "admin prompts in the desktop (polkit)", false, false},
	{"login", "text console login (Ctrl+Alt+F2…)", true, false},
	{"systemd-run0", "run0 (systemd's sudo)", false, false},
	{"gdm-password", "GDM login screen", true, false},
	{"lightdm", "LightDM login screen", true, false},
	{"cinnamon-screensaver", "Cinnamon lock screen", false, true},
}

// State is one service as found on disk.
type State struct {
	Service Service
	Path    string // file yking writes (/etc/pam.d/<name>)
	// Source is where the current behaviour comes from: Path, or the
	// vendor file when /etc has none.
	Source  string
	Current Config
	Managed bool // current pam_u2f line carries yking's marker
	// Custom is set when the pam_u2f setup is not understood; yking then
	// refuses to change the service.
	Custom string
	base   []Line
	raw    []byte // exact bytes of Path ("" if absent) for the precondition
	exists bool
}

// Discover reads every known service present under etcDir / vendorDir.
func Discover(etcDir, vendorDir string) ([]State, error) {
	var out []State
	for _, svc := range Known {
		st, ok, err := discover(svc, etcDir, vendorDir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", svc.Name, err)
		}
		if ok {
			out = append(out, st)
		}
	}
	return out, nil
}

func discover(svc Service, etcDir, vendorDir string) (State, bool, error) {
	st := State{Service: svc, Path: filepath.Join(etcDir, svc.Name)}
	etc, err := os.ReadFile(st.Path)
	switch {
	case err == nil:
		st.exists, st.raw, st.Source = true, etc, st.Path
	case !errors.Is(err, fs.ErrNotExist):
		return st, false, err
	}
	vendorPath := filepath.Join(vendorDir, svc.Name)
	vendor, verr := os.ReadFile(vendorPath)
	if !st.exists && verr != nil {
		return st, false, nil // service not installed
	}

	cur := etc
	if !st.exists {
		cur, st.Source = vendor, vendorPath
	}
	lines, err := Parse(string(cur))
	if err != nil {
		return st, false, err
	}
	cfg, ok, why := Classify(lines)
	if !ok {
		st.Custom = why
	}
	st.Current = cfg
	for _, l := range lines {
		if l.Comment && strings.HasPrefix(strings.TrimSpace(l.Raw), markerPrefix) {
			st.Managed = true
		}
	}

	// The base is the file without pam_u2f. If /etc only held a pam_u2f
	// line (it overrides the vendor file completely), rebuild from the
	// vendor file so the other modes have a password rule to work with.
	st.base = Base(lines)
	if st.exists && !HasRules(st.base) && verr == nil {
		vl, err := Parse(string(vendor))
		if err != nil {
			return st, false, fmt.Errorf("%s: %w", vendorPath, err)
		}
		st.base = Base(vl)
	}
	return st, true, nil
}

// Effective is cfg with the settings yking always enforces for the
// service (lock screens: interactive).
func (s State) Effective(cfg Config) Config {
	if s.Service.LockScreen && cfg.Mode != ModeOff {
		cfg.Interactive = true
	}
	return cfg
}

// LockoutRisk reports a lock screen that needs the key but fails at once
// when the key is absent (no "interactive"): it can never be unlocked
// after the key was pulled.
func (s State) LockoutRisk() bool {
	return s.Service.LockScreen && s.Custom == "" && s.Current.Mode != ModeOff && !s.Current.Interactive
}

// Render returns the new file content for cfg.
func (s State) Render(cfg Config) (string, error) {
	cfg = s.Effective(cfg)
	lines, err := Apply(s.base, cfg)
	if err != nil {
		return "", err
	}
	return Render(lines), nil
}

// Change is one requested service change.
type Change struct {
	Service string
	To      Config
}

// BuildPlan renders every change into a plan. States must come from a
// fresh Discover; their exact bytes become the preconditions.
func BuildPlan(states []State, changes []Change, now time.Time) (*plan.Plan, error) {
	byName := map[string]State{}
	for _, s := range states {
		byName[s.Service.Name] = s
	}
	var names []string
	p := plan.New("", now)
	for _, c := range changes {
		s, ok := byName[c.Service]
		if !ok {
			return nil, fmt.Errorf("unknown service %s", c.Service)
		}
		if s.Custom != "" {
			return nil, fmt.Errorf("%s has a custom pam_u2f setup (%s); yking will not change it", c.Service, s.Custom)
		}
		content, err := s.Render(c.To)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Service, err)
		}
		before := len(p.Steps)
		p.Replace(plan.Base{Path: s.Path, Data: s.raw, Exists: s.exists}, []byte(content), 0o644)
		if len(p.Steps) > before {
			names = append(names, fmt.Sprintf("%s → %s", c.Service, c.To))
		}
	}
	if p.Empty() {
		return nil, plan.ErrNoChanges
	}
	p.Description = "PAM: " + strings.Join(names, ", ")
	return p, nil
}

// ModuleExists reports whether a PAM module can be found.
func ModuleExists(module string) bool {
	if filepath.IsAbs(module) {
		_, err := os.Stat(module)
		return err == nil
	}
	for _, d := range ModuleDirs {
		if _, err := os.Stat(filepath.Join(d, module)); err == nil {
			return true
		}
	}
	return false
}

// Validate checks a PAM file before the elevated apply writes it: it must
// parse, contain rules, and every non-optional module and include must
// exist. A missing module in a "required" rule would lock the service.
func Validate(path string, content []byte) error {
	lines, err := Parse(string(content))
	if err != nil {
		return err
	}
	if !HasRules(lines) {
		return errors.New("file has no rules")
	}
	if _, ok, why := Classify(lines); !ok {
		return fmt.Errorf("pam_u2f setup not understood: %s", why)
	}
	for _, l := range lines {
		if l.Comment || l.Optional {
			continue
		}
		if l.IsInclude() {
			if !serviceExists(l.Module) {
				return fmt.Errorf("included service %q not found", l.Module)
			}
			continue
		}
		if !ModuleExists(l.Module) {
			return fmt.Errorf("module %s not installed", l.Module)
		}
	}
	return nil
}

func serviceExists(name string) bool {
	if strings.Contains(name, "/") {
		_, err := os.Stat(name)
		return err == nil
	}
	for _, d := range IncludeDirs {
		if _, err := os.Stat(filepath.Join(d, name)); err == nil {
			return true
		}
	}
	return false
}

// displayManagers maps a display manager's unit to its PAM login service.
var displayManagers = map[string]string{
	"sddm.service":        "sddm",
	"plasmalogin.service": "plasmalogin",
	"gdm.service":         "gdm-password",
	"lightdm.service":     "lightdm",
}

// DisplayManagerLink is the systemd alias naming the active login screen.
var DisplayManagerLink = "/etc/systemd/system/display-manager.service"

// DisplayManager returns the active display manager's unit and the PAM
// service yking manages for it ("" when yking does not know it).
func DisplayManager() (unit, service string) {
	target, err := os.Readlink(DisplayManagerLink)
	if err != nil {
		return "", ""
	}
	unit = filepath.Base(target)
	return unit, displayManagers[unit]
}
