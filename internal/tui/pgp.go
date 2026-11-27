package tui

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pgp"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// pgpScreen lists the user's GnuPG identities and copies their subkeys to
// the plugged-in YubiKey (see package pgp for how).

// cardSlots are the slots yking fills: signing and encryption.
var cardSlots = []string{"sig", "dec"}

type pgpCard struct {
	key   keyring.Key
	info  ykman.OpenPGPInfo
	slots map[string]ykman.PGPSlot
	err   string
}

type pgpInput int

const (
	pgpInputNone pgpInput = iota
	pgpInputName
	pgpInputEmail
	pgpInputBackup
	pgpInputFrom    // backup file to copy from (subkeys no longer on disk)
	pgpInputConfirm // protected key: type its label
)

type pgpScreen struct {
	loading bool
	ids     []pgp.Identity
	cards   []pgpCard
	others  int // plugged-in keys that are not registered
	kr      *keyring.Keyring
	scdOK   bool
	gitKey  string
	cursor  int
	err     string
	note    string

	input    textinput.Model
	inputFor pgpInput
	newName  string
	from     string
	askOnly  bool // card-only: waiting for y/n
}

type pgpLoadMsg struct {
	ids    []pgp.Identity
	cards  []pgpCard
	others int
	kr     *keyring.Keyring
	scdOK  bool
	gitKey string
	err    error
}

type pgpDoneMsg struct {
	op   string
	res  runResult
	card *pgpCard
	id   pgp.Identity
}

func (m model) openPGP() (tea.Model, tea.Cmd) {
	m.pgp = pgpScreen{loading: true}
	m.mode = modePGP
	m.status = ""
	return m, m.loadPGP()
}

func (m model) loadPGP() tea.Cmd {
	krPath, client := m.cfg.KeyringPath, m.cfg.Client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var msg pgpLoadMsg
		kr, err := keyring.Load(krPath)
		if err != nil {
			return pgpLoadMsg{err: err}
		}
		msg.kr = kr
		if msg.ids, err = (pgp.GPG{}).Secret(ctx); err != nil {
			return pgpLoadMsg{err: err}
		}
		home, _ := os.UserHomeDir()
		b, _ := os.ReadFile(pgp.ScdaemonPath(home))
		msg.scdOK = pgp.ScdaemonOK(string(b))
		msg.gitKey = strings.TrimSuffix(pgp.GitSigningKey(), "!")
		if client == nil {
			return msg
		}
		serials, err := client.ListSerials(ctx)
		if err != nil {
			return pgpLoadMsg{err: err}
		}
		for _, s := range serials {
			k := kr.Find(s)
			if k == nil {
				msg.others++
				continue
			}
			c := pgpCard{key: *k, slots: map[string]ykman.PGPSlot{}}
			if c.info, err = client.OpenPGPInfo(ctx, s); err != nil {
				c.err = err.Error()
			}
			for _, slot := range pgp.Slots {
				if c.err != "" {
					break
				}
				sl, err := client.PGPSlot(ctx, s, slot)
				if err != nil {
					c.err = err.Error()
				}
				c.slots[slot] = sl
			}
			msg.cards = append(msg.cards, c)
		}
		return msg
	}
}

func (s pgpScreen) selected() (pgp.Identity, bool) {
	if s.cursor < len(s.ids) {
		return s.ids[s.cursor], true
	}
	return pgp.Identity{}, false
}

// carriers lists the registered keys recorded to hold subkey fpr.
func (s pgpScreen) carriers(fpr string) []string {
	var out []string
	if s.kr == nil {
		return nil
	}
	for _, k := range s.kr.Keys {
		for _, p := range k.PGP {
			if p.Fingerprint == fpr {
				out = append(out, k.Label)
			}
		}
	}
	return out
}

func (s *pgpScreen) ask(kind pgpInput, value string) tea.Cmd {
	s.input = textinput.New()
	s.input.CharLimit = 200
	s.input.Width = 50
	s.input.SetValue(value)
	s.input.Focus()
	s.inputFor = kind
	return textinput.Blink
}

func (m model) updatePGP(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.pgp
	switch msg := msg.(type) {
	case pgpLoadMsg:
		s.loading = false
		if msg.err != nil {
			s.err = msg.err.Error()
			return m, nil
		}
		s.ids, s.cards, s.others, s.kr, s.scdOK, s.gitKey = msg.ids, msg.cards, msg.others, msg.kr, msg.scdOK, msg.gitKey
		s.cursor = min(s.cursor, max(len(s.ids)-1, 0))
		return m, nil
	case pgpDoneMsg:
		return m.afterPGP(msg)
	case tea.KeyMsg:
		if s.loading {
			if msg.String() == "esc" {
				m.mode = modeKeys
			}
			return m, nil
		}
		if s.inputFor != pgpInputNone {
			return m.pgpInputKey(msg)
		}
		if s.askOnly {
			s.askOnly = false
			if msg.String() == "y" {
				return m.pgpCardOnly()
			}
			return m, nil
		}
		s.err, s.note = "", ""
		id, ok := s.selected()
		switch msg.String() {
		case "esc", "q":
			m.mode = modeKeys
			return m, nil
		case "up", "k":
			s.cursor = max(s.cursor-1, 0)
		case "down", "j":
			s.cursor = min(s.cursor+1, max(len(s.ids)-1, 0))
		case "r":
			s.loading = true
			return m, m.loadPGP()
		case "n":
			return m, s.ask(pgpInputName, "")
		case "a":
			switch {
			case !ok:
			case id.ForSlot("sig") != nil:
				s.err = "Already has a signing subkey."
			case id.Where != pgp.WhereDisk:
				s.err = "Primary key not on this computer."
			default:
				return m.pgpRun("add-sign", "Add signing subkey", id, nil, []string{"pgp", "add-sign", "--primary", id.Fingerprint})
			}
		case "w":
			if !ok {
				return m, nil
			}
			c, err := s.target(id)
			if err != "" {
				s.err = err
				return m, nil
			}
			if c.key.Protected {
				return m, s.ask(pgpInputConfirm, "")
			}
			return m.pgpToCard(id, c)
		case "b":
			if !ok {
				return m, nil
			}
			if len(diskSubs(id)) == 0 {
				s.err = "No subkeys on disk."
				return m, nil
			}
			home, _ := os.UserHomeDir()
			return m, s.ask(pgpInputBackup, filepath.Join(home, "pgp-"+id.Fingerprint[len(id.Fingerprint)-8:]+"-subkeys.asc"))
		case "g":
			if !ok {
				return m, nil
			}
			sig := id.ForSlot("sig")
			if sig == nil {
				s.err = "No signing subkey (a)."
				return m, nil
			}
			home, _ := os.UserHomeDir()
			p, err := pgp.GitSigningPlan(home, sig.Fingerprint, time.Now())
			if err == nil {
				m.review, err = newReviewPair(p, nil)
			}
			if err != nil {
				s.err = err.Error()
				return m, nil
			}
			m.reviewBack, m.mode = modePGP, modeReview
			return m, nil
		case "f":
			home, _ := os.UserHomeDir()
			p, err := pgp.ScdaemonPlan(home, time.Now())
			if err == nil {
				m.review, err = newReviewPair(p, nil)
			}
			if err != nil {
				s.err = err.Error()
				return m, nil
			}
			m.reviewBack, m.mode = modePGP, modeReview
			return m, nil
		case "x":
			if !ok {
				return m, nil
			}
			if why := s.cardOnlyBlocked(id); why != "" {
				s.err = why
				return m, nil
			}
			s.askOnly = true
		}
	}
	return m, nil
}

// target is the one plugged-in registered key to write to.
func (s pgpScreen) target(id pgp.Identity) (pgpCard, string) {
	switch {
	case len(s.cards) == 0:
		return pgpCard{}, "Plug in a registered YubiKey."
	case len(s.cards)+s.others > 1:
		return pgpCard{}, "Plug in only one YubiKey."
	}
	c := s.cards[0]
	if c.err != "" {
		return c, "OpenPGP unreadable: " + c.err
	}
	for _, slot := range cardSlots {
		sub := id.ForSlot(slot)
		if sub == nil {
			return c, fmt.Sprintf("No %s subkey (a adds one).", slot)
		}
		if sl := c.slots[slot]; !sl.Empty && sl.Fingerprint != sub.Fingerprint {
			return c, fmt.Sprintf("%s slot holds another key.", slot)
		}
	}
	if ok, why := c.info.AdminPromptAllowed(); !ok {
		return c, why
	}
	return c, ""
}

func diskSubs(id pgp.Identity) []string {
	var out []string
	for _, slot := range cardSlots {
		if sub := id.ForSlot(slot); sub != nil && sub.Where == pgp.WhereDisk {
			out = append(out, sub.Fingerprint)
		}
	}
	return out
}

func (s pgpScreen) cardOnlyBlocked(id pgp.Identity) string {
	subs := diskSubs(id)
	switch {
	case !s.scdOK:
		return "Fix gpg card access first (f)."
	case len(subs) == 0:
		return "No subkeys on disk."
	}
	for _, f := range subs {
		if len(s.carriers(f)) == 0 {
			return "Copy to a YubiKey first (w)."
		}
	}
	for _, c := range s.cards {
		all := true
		for _, f := range subs {
			if !slices.Contains(s.carriers(f), c.key.Label) {
				all = false
			}
		}
		if all {
			return ""
		}
	}
	return "Plug in a YubiKey that holds the subkeys."
}

func (m model) pgpInputKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := &m.pgp
	switch key.String() {
	case "esc":
		s.inputFor = pgpInputNone
		return m, nil
	case "enter":
		v := strings.TrimSpace(s.input.Value())
		kind := s.inputFor
		s.inputFor = pgpInputNone
		id, _ := s.selected()
		switch kind {
		case pgpInputName:
			if v == "" {
				return m, nil
			}
			s.newName = v
			return m, s.ask(pgpInputEmail, "")
		case pgpInputEmail:
			if !strings.Contains(v, "@") || strings.ContainsAny(v, "<> ") {
				s.err = "Invalid email."
				return m, nil
			}
			uid := s.newName + " <" + v + ">"
			return m.pgpRun("new", "New PGP identity", pgp.Identity{UIDs: []string{uid}}, nil, []string{"pgp", "new", "--uid", uid, "--expire", "3y"})
		case pgpInputBackup:
			if v == "" {
				return m, nil
			}
			args := []string{"pgp", "backup", "--primary", id.Fingerprint, "--out", v}
			for _, f := range diskSubs(id) {
				args = append(args, "--sub", f)
			}
			return m.pgpRun("backup", "Back up subkeys", id, nil, args)
		case pgpInputFrom:
			s.from = v
			c, _ := s.target(id)
			return m.pgpToCard(id, c)
		case pgpInputConfirm:
			c, err := s.target(id)
			if err != "" {
				s.err = err
				return m, nil
			}
			if v != c.key.Label {
				s.err = fmt.Sprintf("Type %q to confirm.", c.key.Label)
				return m, nil
			}
			return m.pgpToCard(id, c)
		}
		return m, nil
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(key)
	return m, cmd
}

func (m model) pgpToCard(id pgp.Identity, c pgpCard) (tea.Model, tea.Cmd) {
	s := &m.pgp
	args := []string{"pgp", "tocard", "--serial", c.key.Serial, "--label", c.key.Label, "--primary", id.Fingerprint, "--touch"}
	onDisk := true
	for _, slot := range cardSlots {
		sub := id.ForSlot(slot)
		args = append(args, "--write", slot+"="+sub.Fingerprint)
		if sub.Where != pgp.WhereDisk && c.slots[slot].Fingerprint != sub.Fingerprint {
			onDisk = false
		}
	}
	if !onDisk {
		if s.from == "" {
			home, _ := os.UserHomeDir()
			return m, s.ask(pgpInputFrom, filepath.Join(home, "pgp-"+id.Fingerprint[len(id.Fingerprint)-8:]+"-subkeys.asc"))
		}
		args = append(args, "--from", s.from)
	}
	s.from = ""
	return m.pgpRun("tocard", "Copy subkeys to "+c.key.Label, id, &c, args)
}

func (m model) pgpCardOnly() (tea.Model, tea.Cmd) {
	id, _ := m.pgp.selected()
	args := []string{"pgp", "card-only", "--primary", id.Fingerprint}
	for _, f := range diskSubs(id) {
		args = append(args, "--sub", f)
	}
	return m.pgpRun("card-only", "Remove subkeys from disk", id, nil, args)
}

func (m model) pgpRun(op, title string, id pgp.Identity, c *pgpCard, args []string) (tea.Model, tea.Cmd) {
	self, err := os.Executable()
	if err != nil {
		m.pgp.err = err.Error()
		return m, nil
	}
	j := runJob{
		title:    title,
		lines:    []string{id.Name()},
		cmd:      exec.Command(self, args...),
		back:     modePGP,
		outLines: 4,
		done: func(r runResult) tea.Msg {
			return pgpDoneMsg{op: op, res: r, card: c, id: id}
		},
	}
	if c != nil {
		k := c.key
		j.need, j.key, j.needWhy = &k, &k, "to copy the subkeys"
	}
	return m.startRun(j)
}

func (m model) afterPGP(msg pgpDoneMsg) (tea.Model, tea.Cmd) {
	s := &m.pgp
	s.loading = true
	reload := m.loadPGP()
	if msg.res.skipped {
		s.loading = false
		return m, nil
	}
	if msg.op != "tocard" {
		if msg.res.err != nil {
			s.err = msg.res.err.Error()
		} else {
			s.note = map[string]string{"new": "Identity created.", "add-sign": "Signing subkey added.",
				"backup": "Backup written.", "card-only": "Subkeys removed from disk."}[msg.op]
		}
		return m, reload
	}

	// tocard: record whatever is on the card now, even after a failure.
	var entries []keyring.PGPKey
	touch := map[string]bool{}
	now := time.Now().UTC().Truncate(time.Second)
	sc := bufio.NewScanner(bytes.NewReader(msg.res.stdout))
	var lines [][]string
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 3 && f[0] == "YKING-PGP" && f[1] == "touch" {
			touch[f[2]] = true
		}
		lines = append(lines, f)
	}
	for _, f := range lines {
		if len(f) == 4 && f[0] == "YKING-PGP" && (f[1] == "written" || f[1] == "present") {
			entries = append(entries, keyring.PGPKey{Primary: msg.id.Fingerprint, Fingerprint: f[3], Slot: f[2],
				UserID: msg.id.Name(), Touch: touch[f[2]], CopiedAt: now})
		}
	}
	if msg.res.err != nil {
		s.err = "Copy failed: " + msg.res.err.Error()
		if msg.res.pinAsked {
			s.err += " (rescan for tries left)"
		}
	}
	if len(entries) == 0 || msg.card == nil {
		return m, reload
	}
	p, err := pgp.RecordPlan(m.cfg.KeyringPath, msg.card.key.Serial, entries, time.Now())
	if err == nil {
		m.review, err = newReview(p)
	}
	if err != nil {
		if s.err == "" {
			s.note = "On the card."
		}
		return m, reload
	}
	m.status = okStyle.Render("Subkeys on " + msg.card.key.Label + ". Apply to record them.")
	m.reviewBack, m.mode = modePGP, modeReview
	return m, reload
}

func (s pgpScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("PGP") + "\n\n")
	if s.loading {
		return b.String() + dimStyle.Render("reading…") + "\n"
	}
	if len(s.ids) == 0 {
		b.WriteString(dimStyle.Render("no secret keys — n to create") + "\n")
	}
	for i, id := range s.ids {
		exp := "no expiry"
		if !id.Expires.IsZero() {
			exp = "until " + id.Expires.Format(time.DateOnly)
		}
		line := fmt.Sprintf("%s  %s", id.Name(), dimStyle.Render(pgp.Short(id.Fingerprint)+"  "+exp))
		if id.Invalid {
			line += errStyle.Render("  expired/revoked")
		}
		if i == s.cursor {
			b.WriteString(selStyle.Render("▸ ") + line + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
		if i != s.cursor {
			continue
		}
		for _, slot := range cardSlots {
			sub := id.ForSlot(slot)
			if sub == nil {
				b.WriteString(dimStyle.Render(fmt.Sprintf("      %s  —", slot)) + "\n")
				continue
			}
			where := map[pgp.Where]string{pgp.WhereDisk: "disk", pgp.WhereCard: "card", pgp.WhereNone: "card (stub)"}[sub.Where]
			row := fmt.Sprintf("      %s  %-8s %s  %-11s", slot, sub.Algo, pgp.Short(sub.Fingerprint), where)
			if on := s.carriers(sub.Fingerprint); len(on) > 0 {
				row += "  on: " + strings.Join(on, ", ")
			}
			if slot == "sig" && s.gitKey == sub.Fingerprint {
				row += "  git ✓"
			}
			b.WriteString(dimStyle.Render(row) + "\n")
		}
	}

	if len(s.cards) > 0 {
		b.WriteString("\n")
	}
	for _, c := range s.cards {
		row := fmt.Sprintf("%s (%s)", c.key.Label, c.key.Serial)
		if c.err != "" {
			b.WriteString(row + "  " + errStyle.Render(c.err) + "\n")
			continue
		}
		var parts []string
		for _, slot := range pgp.Slots {
			v := "—"
			if sl := c.slots[slot]; !sl.Empty {
				v = pgp.Short(sl.Fingerprint)
				if strings.EqualFold(sl.Touch, "on") {
					v += " ☝"
				}
			}
			parts = append(parts, slot+" "+v)
		}
		pin := fmt.Sprintf("Admin\u00a0PIN\u00a0%d", c.info.AdminPINTries) // stays on one line
		if ok, _ := c.info.AdminPromptAllowed(); !ok {
			pin = errStyle.Render(pin)
		}
		b.WriteString(row + "  " + dimStyle.Render(strings.Join(parts, " · ")) + "  " + pin + "\n")
	}
	if !s.scdOK {
		b.WriteString("\n" + warnStyle.Render("! gpg cannot use the YubiKey next to ykman — f") + "\n")
	}

	switch s.inputFor {
	case pgpInputName:
		b.WriteString("\nName   " + s.input.View() + "\n")
	case pgpInputEmail:
		b.WriteString("\nName   " + s.newName + "\nEmail  " + s.input.View() + "\n")
	case pgpInputBackup:
		b.WriteString("\nBackup file  " + s.input.View() + "\n")
	case pgpInputFrom:
		b.WriteString("\nSubkeys not on disk. Backup file  " + s.input.View() + "\n")
	case pgpInputConfirm:
		b.WriteString("\nProtected key: type its label  " + s.input.View() + "\n")
	}
	if s.askOnly {
		id, _ := s.selected()
		n := 0
		if subs := diskSubs(id); len(subs) > 0 {
			n = len(s.carriers(subs[0]))
		}
		if n < 2 {
			b.WriteString("\n" + warnStyle.Render("! only on one YubiKey — losing it loses these subkeys unless backed up") + "\n")
		}
		b.WriteString("\nRemove subkeys from disk?  " + selStyle.Render("y") + " yes  " + selStyle.Render("n") + " no\n")
	}
	if s.note != "" {
		b.WriteString("\n" + okStyle.Render(s.note) + "\n")
	}
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}
