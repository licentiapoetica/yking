package tui

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/fsutil"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
)

// eventsScreen configures what happens when a YubiKey is plugged in or
// pulled out, and installs the pieces (binary, config, udev rule, unit).

// discoverPAM reads the PAM services (tests override it).
var discoverPAM = func() ([]pam.State, error) { return pam.Discover(pam.EtcDir, pam.VendorDir) }

// eventsConfigPath is read for the current settings (tests override it).
var eventsConfigPath = events.ConfigPath

type eventsScreen struct {
	keys     []keyring.Key
	cfg      events.Config
	triggers map[string]bool
	cursor   int // 0..len(keys)-1 = trigger keys, then lock, sudo, wake
	status   []string
	err      string
}

func newEventsScreen(krPath string) eventsScreen {
	s := eventsScreen{triggers: map[string]bool{}}
	kr, err := keyring.Load(krPath)
	if err != nil {
		s.err = err.Error()
		return s
	}
	s.keys = kr.Keys
	if b, err := os.ReadFile(eventsConfigPath); err == nil {
		if c, err := events.Parse(b); err == nil {
			s.cfg = *c
		}
	}
	if s.cfg.Version == 0 { // defaults: daily keys trigger; all actions on
		s.cfg = events.Config{Version: 1, Users: []string{currentUser()},
			OnRemove: events.Remove{Lock: true, SudoReset: true}, OnInsert: events.Insert{Wake: true}}
		for _, k := range kr.Keys {
			if k.Role == keyring.RoleDaily {
				s.cfg.Triggers = append(s.cfg.Triggers, k.Serial)
			}
		}
	}
	for _, t := range s.cfg.Triggers {
		s.triggers[t] = true
	}
	if !slices.Contains(s.cfg.Users, currentUser()) {
		s.cfg.Users = append(s.cfg.Users, currentUser())
	}
	s.status = installStatus()
	return s
}

func installStatus() []string {
	var out []string
	self, _ := os.Executable()
	mine, _ := os.ReadFile(self)
	inst, err := os.ReadFile(events.BinaryPath)
	switch {
	case err != nil:
		out = append(out, "binary "+events.BinaryPath+": not installed")
	case fsutil.SHA256(inst) == fsutil.SHA256(mine):
		out = append(out, "binary "+events.BinaryPath+": installed, current")
	default:
		out = append(out, "binary "+events.BinaryPath+": installed, OLDER than this yking (will be updated)")
	}
	for _, f := range []struct{ path, want string }{{events.RulePath, events.Rule}, {events.UnitPath, events.Unit}} {
		b, err := os.ReadFile(f.path)
		switch {
		case err != nil:
			out = append(out, f.path+": not installed")
		case string(b) == f.want:
			out = append(out, f.path+": installed")
		default:
			out = append(out, f.path+": differs (will be replaced)")
		}
	}
	if _, err := os.Stat(events.ConfigPath); err != nil {
		out = append(out, events.ConfigPath+": not set up")
	} else {
		out = append(out, events.ConfigPath+": set up")
	}
	return out
}

func (s eventsScreen) rows() int { return len(s.keys) + 3 }

func (m model) updateEvents(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	s := &m.events
	switch key.String() {
	case "esc", "q":
		m.mode = modeKeys
	case "up", "k":
		s.cursor = max(s.cursor-1, 0)
	case "down", "j":
		s.cursor = min(s.cursor+1, s.rows()-1)
	case " ":
		switch i := s.cursor; {
		case i < len(s.keys):
			s.triggers[s.keys[i].Serial] = !s.triggers[s.keys[i].Serial]
		case i == len(s.keys):
			s.cfg.OnRemove.Lock = !s.cfg.OnRemove.Lock
		case i == len(s.keys)+1:
			s.cfg.OnRemove.SudoReset = !s.cfg.OnRemove.SudoReset
		default:
			s.cfg.OnInsert.Wake = !s.cfg.OnInsert.Wake
		}
	case "enter":
		return m.buildEventsPlan()
	}
	return m, nil
}

func (m model) buildEventsPlan() (tea.Model, tea.Cmd) {
	s := &m.events
	s.err = ""
	c := s.cfg
	c.Triggers = nil
	for _, k := range s.keys {
		if s.triggers[k.Serial] {
			c.Triggers = append(c.Triggers, k.Serial)
		}
	}
	if len(c.Triggers) == 0 && c.OnRemove.Lock {
		s.err = "Tick at least one trigger key (otherwise pulling ANY registered key would lock)."
		return m, nil
	}
	if c.OnRemove.Lock {
		if sts, err := discoverPAM(); err == nil {
			for _, st := range sts {
				if st.LockoutRisk() {
					s.err = fmt.Sprintf("Not enabling \"lock\": the %s needs the key but fails at once when it is absent —\n"+
						"after pulling the key you could never unlock. Fix it first on the PAM screen (p): yking adds \"interactive\".", st.Service.Desc)
					return m, nil
				}
			}
		}
	}
	conf, err := c.Encode()
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	self, err := os.Executable()
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	p := plan.New("plug/unplug actions: install yking, config, udev rule, systemd unit", time.Now())
	for _, step := range []func() error{
		func() error { return p.Install(events.BinaryPath, self, 0o755) },
		func() error { return p.WriteFile(events.ConfigPath, conf, 0o644) },
		func() error { return p.WriteFile(events.RulePath, []byte(events.Rule), 0o644) },
		func() error { return p.WriteFile(events.UnitPath, []byte(events.Unit), 0o644) },
	} {
		if err := step(); err != nil {
			s.err = err.Error()
			return m, nil
		}
	}
	m.review, err = newReview(p)
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	m.review.note = "Test after applying: pull out a trigger key → the screen locks. Log: journalctl -u 'yking-event@*' -n 20"
	m.reviewBack = modeEvents
	m.mode = modeReview
	return m, nil
}

func (s eventsScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Plug in / pull out actions") + "\n")
	b.WriteString("\n")
	box := func(on bool) string {
		if on {
			return okStyle.Render("[x]")
		}
		return dimStyle.Render("[ ]")
	}
	cur := func(i int) string {
		if s.cursor == i {
			return selStyle.Render("▸ ")
		}
		return "  "
	}
	b.WriteString("Pulling out one of these keys triggers the actions below:\n")
	for i, k := range s.keys {
		b.WriteString(cur(i) + box(s.triggers[k.Serial]) + fmt.Sprintf(" %-12s %-12s %s", k.Label, k.Role, k.Serial) + "\n")
	}
	b.WriteString("\n")
	n := len(s.keys)
	b.WriteString("When a trigger key is pulled out:\n")
	b.WriteString(cur(n) + box(s.cfg.OnRemove.Lock) + " lock the screen\n")
	b.WriteString(cur(n+1) + box(s.cfg.OnRemove.SudoReset) + " forget cached sudo (next sudo asks again)\n")
	b.WriteString("When a registered key is plugged in:\n")
	b.WriteString(cur(n+2) + box(s.cfg.OnInsert.Wake) + " wake a locked screen so the unlock prompt appears (no auto-unlock)\n\n")
	for _, l := range s.status {
		b.WriteString(dimStyle.Render("  "+l) + "\n")
	}
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}
