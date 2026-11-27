package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/transfer"
)

// importScreen walks through a staged import (yking import FILE). Every step
// reuses the normal screens and their safety checks.
type importScreen struct {
	exp   *transfer.Export
	steps []importStep
	err   string
	note  string
}

type importStep struct {
	title string
	done  bool
	lines []string
	key   string // what to press
}

func newImportScreen(krPath string) importScreen {
	home, _ := os.UserHomeDir()
	e, err := transfer.LoadPending(home)
	s := importScreen{exp: e}
	if err != nil {
		s.err = err.Error()
	}
	if e == nil {
		return s
	}
	kr, _ := keyring.Load(krPath)
	if kr == nil {
		kr = keyring.New()
	}
	mp, _, _ := readMapping()
	user := currentUser()
	cov := pam.Coverage(kr, mp, user)

	// 1 keyring + SSH files
	st := importStep{title: "Register the keys and copy the SSH key files", key: "1"}
	st.done = true
	for _, k := range e.Keys {
		if kr.Find(k.Serial) == nil {
			st.done = false
			st.lines = append(st.lines, "· "+k.Label+" not registered yet")
		}
	}
	for _, f := range e.SSHFiles {
		if _, err := os.Stat(filepath.Join(sshDir(), f.Name)); err != nil {
			st.done = false
			st.lines = append(st.lines, "· ~/.ssh/"+f.Name+" missing")
		}
	}
	s.steps = append(s.steps, st)

	// 2 PAM credentials
	st = importStep{title: "PAM credential per key (plug in alone → main screen c → a, one touch)", done: true}
	for _, k := range e.Keys {
		if cov[k.Serial] {
			st.lines = append(st.lines, "✓ "+k.Label)
		} else {
			st.done = false
			st.lines = append(st.lines, "· "+k.Label+" — no credential on this machine yet")
		}
	}
	s.steps = append(s.steps, st)

	// 3 PAM modes
	st = importStep{title: "PAM modes as on the old machine", key: "p", done: true}
	sts, _ := pam.Discover(pam.EtcDir, pam.VendorDir)
	cur := map[string]pam.Config{}
	for _, x := range sts {
		cur[x.Service.Name] = x.Current
	}
	for name, want := range e.DesiredPAM() {
		have := cur[name]
		if have.Mode == want.Mode && have.Unlock == want.Unlock {
			st.lines = append(st.lines, fmt.Sprintf("✓ %s: %s", name, want))
		} else {
			st.done = false
			st.lines = append(st.lines, fmt.Sprintf("· %s: %s (now %s)", name, want, have))
		}
	}
	if !s.steps[1].done {
		st.lines = append(st.lines, "  do step 2 first: key-only modes need confirmed keys")
	}
	s.steps = append(s.steps, st)

	// 4 events
	if want := e.DesiredEvents(user); want != nil {
		st = importStep{title: "Plug in / pull out actions", key: "u"}
		if b, err := os.ReadFile(eventsConfigPath); err == nil {
			if have, err := events.Parse(b); err == nil && have.OnRemove == want.OnRemove && have.OnInsert == want.OnInsert && strings.Join(have.Triggers, ",") == strings.Join(want.Triggers, ",") {
				st.done = true
			}
		}
		if !st.done {
			st.lines = append(st.lines, fmt.Sprintf("· lock=%v sudo-reset=%v wake=%v, triggers %d key(s)", want.OnRemove.Lock, want.OnRemove.SudoReset, want.OnInsert.Wake, len(want.Triggers)))
		}
		s.steps = append(s.steps, st)
	}

	// 5 LUKS (optional, other disk)
	if l := e.LUKSKeys(); len(l) > 0 {
		st = importStep{title: "Disk encryption (optional): enroll " + strings.Join(l, ", "), key: "b", done: true}
		for _, k := range e.Keys {
			if len(k.LUKS) == 0 {
				continue
			}
			lk := kr.Find(k.Serial)
			if lk == nil || len(lk.LUKS) == 0 {
				st.done = false
				st.lines = append(st.lines, "· "+k.Label+" not enrolled on this disk")
			}
		}
		s.steps = append(s.steps, st)
	}
	return s
}

func (m model) updateImport(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.imp
	key, ok := msg.(tea.KeyMsg)
	if !ok || s.exp == nil {
		if ok && (key.String() == "esc" || key.String() == "q") {
			m.mode = modeKeys
		}
		return m, nil
	}
	switch key.String() {
	case "esc", "q":
		m.mode = modeKeys
	case "1":
		written, err := transfer.WriteSSHFiles(s.exp, sshDir())
		if err != nil {
			s.err = err.Error()
			return m, nil
		}
		p, err := transfer.KeyringPlan(m.cfg.KeyringPath, s.exp, currentUser(), sshDir(), time.Now())
		if err == plan.ErrNoChanges {
			s.note = fmt.Sprintf("Keyring already complete; %d SSH file(s) written.", len(written))
			m.imp = newImportScreen(m.cfg.KeyringPath)
			m.imp.note = s.note
			return m, nil
		}
		if err == nil {
			m.review, err = newReview(p)
		}
		if err != nil {
			s.err = err.Error()
			return m, nil
		}
		m.review.note = fmt.Sprintf("%d SSH key file(s) already written to ~/.ssh.", len(written))
		m.reviewBack = modeImport
		m.mode = modeReview
	case "p":
		m.pam = newPAMScreen(m.cfg.KeyringPath)
		for i, st := range m.pam.states {
			if want, ok := s.exp.DesiredPAM()[st.Service.Name]; ok && st.Custom == "" {
				m.pam.desired[i] = want
			}
		}
		m.pam.recheck()
		m.mode = modePAM
	case "u":
		m.events = newEventsScreen(m.cfg.KeyringPath)
		if want := s.exp.DesiredEvents(currentUser()); want != nil {
			m.events.cfg = *want
			m.events.triggers = map[string]bool{}
			for _, t := range want.Triggers {
				m.events.triggers[t] = true
			}
		}
		m.mode = modeEvents
	case "b":
		m.luks = newLUKSScreen(m.cfg.KeyringPath)
		m.mode = modeLUKS
	case "D":
		home, _ := os.UserHomeDir()
		os.Remove(transfer.PendingPath(home))
		m.status = okStyle.Render("Import finished and removed.")
		m.mode = modeKeys
	}
	return m, nil
}

func (s importScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Import from another machine") + "\n\n")
	if s.exp == nil {
		b.WriteString("No import staged. On the old machine: yking export; here: yking import FILE.\n")
		if s.err != "" {
			b.WriteString(errStyle.Render(s.err) + "\n")
		}
		return b.String()
	}
	all := true
	for i, st := range s.steps {
		box := dimStyle.Render("[ ]")
		if st.done {
			box = okStyle.Render("[x]")
		} else {
			all = false
		}
		k := ""
		if st.key != "" && !st.done {
			k = selStyle.Render("  press " + st.key)
		}
		fmt.Fprintf(&b, "%s %d. %s%s\n", box, i+1, st.title, k)
		for _, l := range st.lines {
			b.WriteString(dimStyle.Render("      "+l) + "\n")
		}
	}
	if all {
		b.WriteString("\n" + okStyle.Render("Everything is done.") + " Press D to remove the staged import.\n")
	}
	if s.note != "" {
		b.WriteString("\n" + s.note + "\n")
	}
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}
