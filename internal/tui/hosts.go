package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// hostsScreen lists the servers SSH keys were deployed to and whether
// ~/.ssh/config has yking's Host block for each. Enter reviews the change
// for ONE host; nothing is written without the review.
type hostsScreen struct {
	home    string
	kr      *keyring.Keyring
	entries []sshkey.HostEntry
	state   map[string]sshkey.BlockState
	orphans []string // yking blocks whose host has no recorded keys any more
	cursor  int
	err     string
}

func newHostsScreen(krPath string) hostsScreen {
	s := hostsScreen{}
	home, err := os.UserHomeDir()
	if err != nil {
		s.err = err.Error()
		return s
	}
	s.home = home
	kr, err := keyring.Load(krPath)
	if err != nil {
		s.err = err.Error()
		return s
	}
	s.kr = kr
	s.entries = sshkey.Hosts(kr, nil)
	cfg, err := os.ReadFile(sshkey.ConfigPath(home))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.err = err.Error()
		return s
	}
	s.state, s.orphans, err = sshkey.ConfigState(string(cfg), home, s.entries)
	if err != nil {
		s.err = "~/.ssh/config: " + err.Error() + " — fix the yking markers by hand; yking will not edit it until then"
	}
	return s
}

func (s hostsScreen) rows() int { return len(s.entries) + len(s.orphans) }

// selected returns the entry for the cursor row; orphans get an empty
// entry, which makes the plan remove their block.
func (s hostsScreen) selected() (sshkey.HostEntry, bool) {
	switch {
	case s.cursor < len(s.entries):
		return s.entries[s.cursor], true
	case s.cursor < s.rows():
		return sshkey.HostEntry{Host: s.orphans[s.cursor-len(s.entries)]}, true
	}
	return sshkey.HostEntry{}, false
}

func (m model) updateHosts(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	s := &m.hosts
	switch key.String() {
	case "esc", "q":
		m.mode = modeKeys
	case "up", "k":
		if s.cursor > 0 {
			s.cursor--
		}
	case "down", "j":
		if s.cursor < s.rows()-1 {
			s.cursor++
		}
	case "r":
		cur := s.cursor
		m.hosts = newHostsScreen(m.cfg.KeyringPath)
		m.hosts.cursor = min(cur, max(m.hosts.rows()-1, 0))
	case "enter":
		e, ok := s.selected()
		if !ok || s.state == nil {
			return m, nil
		}
		p, notes, err := sshkey.ConfigPlan(sshkey.ConfigPath(s.home), s.home, e, time.Now())
		if errors.Is(err, plan.ErrNoChanges) {
			s.err = ""
			m.status = okStyle.Render("~/.ssh/config already has the current Host " + e.Host + " block.")
			return m, nil
		}
		if err == nil {
			m.review, err = newReviewPair(p, nil)
		}
		if err != nil {
			s.err = err.Error()
			return m, nil
		}
		m.review.note = strings.Join(notes, "\n")
		m.reviewBack = modeHosts
		m.mode = modeReview
		m.status = ""
	}
	return m, nil
}

func (s hostsScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("SSH hosts → ~/.ssh/config") + "\n")
	b.WriteString("\n")
	if s.rows() == 0 && s.err == "" {
		b.WriteString(dimStyle.Render("No deployed SSH keys yet.") + "\n")
		return b.String()
	}
	for i, e := range s.entries {
		var keys []string
		for _, k := range e.Keys {
			keys = append(keys, fmt.Sprintf("%s (%s)", filepath.Base(k.Path), k.Label))
		}
		if len(keys) == 0 {
			keys = []string{"no key file on this machine"}
		}
		users := strings.Join(slices.DeleteFunc(slices.Clone(e.Users), func(u string) bool { return u == "" }), ",")
		st := s.state[e.Host]
		stStyle := warnStyle
		if st == sshkey.BlockCurrent {
			stStyle = okStyle
		}
		line := fmt.Sprintf("%-28s %-10s %-44s ", e.Host, or(users, "—"), strings.Join(keys, ", "))
		b.WriteString(rowCursor(i == s.cursor) + line + stStyle.Render(st.String()) + "\n")
	}
	for j, h := range s.orphans {
		line := fmt.Sprintf("%-28s %-10s %-44s ", h, "—", "no keys recorded any more")
		b.WriteString(rowCursor(len(s.entries)+j == s.cursor) + line + warnStyle.Render("yking block left over (enter removes)") + "\n")
	}

	if e, ok := s.selected(); ok && s.kr != nil && len(e.Keys)+len(e.Missing) > 0 {
		b.WriteString("\n")
		if n := deployedYubiKeys(e); n == 1 {
			b.WriteString(warnStyle.Render("! only one YubiKey can log in here — deploy a backup key") + "\n")
		}
		if other := notDeployed(s.kr, e); len(other) > 0 {
			b.WriteString(dimStyle.Render("not here: "+strings.Join(other, ", ")) + "\n")
		}
		for _, k := range e.Missing {
			b.WriteString(dimStyle.Render(fmt.Sprintf("no key file on this machine: %s (%s)", or(k.Comment, k.Fingerprint), k.Label)) + "\n")
		}
	}
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}

func rowCursor(on bool) string {
	if on {
		return selStyle.Render("▸ ")
	}
	return "  "
}

func deployedYubiKeys(e sshkey.HostEntry) int {
	seen := map[string]bool{}
	for _, k := range slices.Concat(e.Keys, e.Missing) {
		seen[k.Serial] = true
	}
	return len(seen)
}

// notDeployed lists SSH keys of registered YubiKeys that are not on e.Host.
func notDeployed(kr *keyring.Keyring, e sshkey.HostEntry) []string {
	on := map[string]bool{}
	for _, k := range slices.Concat(e.Keys, e.Missing) {
		on[k.Fingerprint] = true
	}
	var out []string
	for _, k := range kr.Keys {
		for _, s := range k.SSH {
			if !on[s.Fingerprint] {
				out = append(out, fmt.Sprintf("%s (%s)", or(filepath.Base(s.Path), s.Comment), k.Label))
			}
		}
	}
	return out
}
