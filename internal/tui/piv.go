package tui

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// pivScreen shows the PIV applet of each plugged-in YubiKey and replaces
// its factory PIN, PUK and management key.

type pivCard struct {
	serial string
	key    *keyring.Key // nil: not registered
	info   ykman.PIVInfo
	keys   map[string]ykman.PIVKey // used slots only
	err    string
}

func (c pivCard) name() string {
	if c.key != nil {
		return fmt.Sprintf("%s (%s)", c.key.Label, c.serial)
	}
	return c.serial
}

type pivScreen struct {
	loading bool
	cards   []pivCard
	cursor  int
	err     string
	note    string
}

type pivLoadMsg struct {
	cards []pivCard
	err   error
}

type pivDoneMsg struct{ res runResult }

func (m model) openPIV() (tea.Model, tea.Cmd) {
	m.piv = pivScreen{loading: true}
	m.mode = modePIV
	m.status = ""
	return m, m.loadPIV()
}

func (m model) loadPIV() tea.Cmd {
	krPath, client := m.cfg.KeyringPath, m.cfg.Client
	return func() tea.Msg {
		if client == nil {
			return pivLoadMsg{}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		kr, err := keyring.Load(krPath)
		if err != nil {
			return pivLoadMsg{err: err}
		}
		serials, err := client.ListSerials(ctx)
		if err != nil {
			return pivLoadMsg{err: err}
		}
		var msg pivLoadMsg
		for _, s := range serials {
			c := pivCard{serial: s, key: kr.Find(s), keys: map[string]ykman.PIVKey{}}
			if c.info, err = client.PIVInfo(ctx, s); err != nil {
				c.err = err.Error()
			}
			for _, slot := range ykman.PIVSlots {
				if _, used := c.info.Slots[slot]; !used || c.err != "" {
					continue
				}
				k, err := client.PIVKey(ctx, s, slot)
				if err != nil {
					c.err = err.Error()
					break
				}
				c.keys[slot] = k
			}
			msg.cards = append(msg.cards, c)
		}
		return msg
	}
}

func (m model) updatePIV(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.piv
	switch msg := msg.(type) {
	case pivLoadMsg:
		s.loading = false
		if msg.err != nil {
			s.err = msg.err.Error()
			return m, nil
		}
		s.cards = msg.cards
		s.cursor = min(s.cursor, max(len(s.cards)-1, 0))
		return m, nil
	case pivDoneMsg:
		s.loading = true
		if msg.res.skipped {
			s.loading = false
			return m, nil
		}
		if msg.res.err != nil {
			s.err = msg.res.err.Error()
			if msg.res.pinAsked {
				s.err += " (r for tries left)"
			}
		}
		var done []string
		sc := bufio.NewScanner(bytes.NewReader(msg.res.stdout))
		for sc.Scan() {
			if f := strings.Fields(sc.Text()); len(f) == 2 && f[0] == "YKING-PIV" {
				done = append(done, map[string]string{"pin": "PIN", "puk": "PUK", "mgmt": "management key"}[f[1]])
			}
		}
		if len(done) > 0 {
			s.note = strings.Join(done, ", ") + " set."
		}
		return m, m.loadPIV()
	case tea.KeyMsg:
		if s.loading {
			if msg.String() == "esc" {
				m.mode = modeKeys
			}
			return m, nil
		}
		s.err, s.note = "", ""
		switch msg.String() {
		case "esc", "q":
			m.mode = modeKeys
		case "up", "k":
			s.cursor = max(s.cursor-1, 0)
		case "down", "j":
			s.cursor = min(s.cursor+1, max(len(s.cards)-1, 0))
		case "r":
			s.loading = true
			return m, m.loadPIV()
		case "c":
			return m.pivDefaults()
		}
	}
	return m, nil
}

func (m model) pivDefaults() (tea.Model, tea.Cmd) {
	s := &m.piv
	if s.cursor >= len(s.cards) {
		return m, nil
	}
	c := s.cards[s.cursor]
	switch {
	case c.key == nil:
		s.err = "Register this key first (e)."
		return m, nil
	case c.err != "":
		s.err = "PIV unreadable: " + c.err
		return m, nil
	case !c.info.AnyDefault():
		s.err = "No factory default left."
		return m, nil
	case c.info.PINTries == 0:
		s.err = "PIV PIN is blocked."
		return m, nil
	case !c.info.DefaultPIN:
		if ok, why := c.info.PINPromptAllowed(); !ok {
			s.err = why
			return m, nil
		}
	}
	self, err := os.Executable()
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	k := *c.key
	j := runJob{
		title:    "PIV PIN on " + k.Label,
		lines:    []string{"! the PUK unblocks a locked PIN — keep it"},
		cmd:      exec.Command(self, "piv", "defaults", "--serial", k.Serial, "--label", k.Label),
		back:     modePIV,
		outLines: 4,
		need:     &k,
		key:      &k,
		needWhy:  "to set its PIV PIN",
		done:     func(r runResult) tea.Msg { return pivDoneMsg{res: r} },
	}
	return m.startRun(j)
}

func (s pivScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("PIV") + "\n\n")
	if s.loading {
		return b.String() + dimStyle.Render("reading…") + "\n"
	}
	if len(s.cards) == 0 && s.err == "" {
		b.WriteString(dimStyle.Render("no YubiKey plugged in") + "\n")
	}
	for i, c := range s.cards {
		head := c.name()
		if c.info.Version != "" {
			head += dimStyle.Render("  PIV " + c.info.Version)
		}
		if i == s.cursor {
			b.WriteString(selStyle.Render("▸ ") + head + "\n")
		} else {
			b.WriteString("  " + head + "\n")
		}
		if c.err != "" {
			b.WriteString("    " + errStyle.Render(c.err) + "\n\n")
			continue
		}
		tries := func(name string, n int) string {
			t := fmt.Sprintf("%s %d", name, n)
			if n >= 0 && n < 2 {
				return errStyle.Render(t)
			}
			return t
		}
		mgmt := "mgmt " + c.info.MgmtAlgo
		if c.info.MgmtStored {
			mgmt += " (PIN)"
		}
		b.WriteString("    " + tries("PIN", c.info.PINTries) + " · " + tries("PUK", c.info.PUKTries) + " · " + dimStyle.Render(mgmt) + "\n")
		var def []string
		if c.info.DefaultPIN {
			def = append(def, "PIN")
		}
		if c.info.DefaultPUK {
			def = append(def, "PUK")
		}
		if c.info.DefaultMgmt {
			def = append(def, "management key")
		}
		if len(def) > 0 {
			b.WriteString("    " + warnStyle.Render("! default "+strings.Join(def, ", ")+" — c") + "\n")
		}
		retired := 0
		for _, slot := range ykman.PIVSlots {
			sl, used := c.info.Slots[slot]
			if !used {
				continue
			}
			if ykman.PIVSlotName(slot) == "retired" {
				retired++
			}
			k := c.keys[slot]
			algo := k.Algorithm
			if k.Empty || algo == "" {
				algo = "no key"
			}
			row := fmt.Sprintf("    %s %-9s %-8s", slot, ykman.PIVSlotName(slot), algo)
			if k.Touch == "ALWAYS" || k.Touch == "CACHED" {
				row += " ☝"
			}
			if sl.Subject != "" {
				row += "  " + sl.Subject
			}
			if sl.NotAfter != "" {
				row += "  until " + strings.SplitN(sl.NotAfter, "T", 2)[0]
			}
			b.WriteString(dimStyle.Render(row) + "\n")
		}
		if len(c.info.Slots) == 0 {
			b.WriteString(dimStyle.Render("    slots empty") + "\n")
		} else {
			b.WriteString(dimStyle.Render(fmt.Sprintf("    retired %d/20 used", retired)) + "\n")
		}
		b.WriteString("\n")
	}
	if s.note != "" {
		b.WriteString(okStyle.Render(s.note) + "\n")
	}
	if s.err != "" {
		b.WriteString(errStyle.Render(s.err) + "\n")
	}
	return b.String()
}
