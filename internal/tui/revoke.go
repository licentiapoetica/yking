package tui

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/revoke"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// The revoke wizard: pick a registered key (connected or not), review
// everything tied to it, untick what to keep, type the label, run.
// Servers are only contacted for the hosts left ticked, one at a time.

type revokeItemKind int

const (
	itemPAM revokeItemKind = iota
	itemUnassigned
	itemHost
	itemArchive
	itemKeyring
)

type revokeItem struct {
	kind revokeItemKind
	host int // index into analysis.Hosts
	on   bool
}

type revokeScreen struct {
	keys      []keyring.Key
	connected map[string]bool
	pick      int
	a         *revoke.Analysis // nil while picking
	items     []revokeItem
	cursor    int
	logins    []string
	login     int
	confirm   textinput.Model
	results   map[int]sshkey.RemoveResult // host index → result
	queue     []int                       // host indexes still to run
	busy      string
	err       string
}

type revokeHostDoneMsg struct {
	host int
	out  []byte
	err  error
}

func newRevokeScreen(krPath string, connected map[string]bool, preselect string) revokeScreen {
	s := revokeScreen{connected: connected, results: map[int]sshkey.RemoveResult{}}
	kr, err := keyring.Load(krPath)
	if err != nil {
		s.err = err.Error()
		return s
	}
	s.keys = kr.Keys
	for i, k := range s.keys {
		if k.Serial == preselect {
			s.pick = i
		}
	}
	return s
}

func (m model) revokeAnalyze() (revokeScreen, error) {
	s := m.revoke
	k := s.keys[s.pick]
	kr, err := keyring.Load(m.cfg.KeyringPath)
	if err != nil {
		return s, err
	}
	mp, _, err := readMapping()
	if err != nil {
		return s, fmt.Errorf("%s: %w", tildePath(mappingPath()), err)
	}
	sts, _ := pam.Discover(pam.EtcDir, pam.VendorDir)
	a, err := revoke.Analyze(kr, mp, currentUser(), k.Serial, sts)
	if err != nil {
		return s, err
	}
	s.a = a
	s.items = nil
	if len(a.Recorded) > 0 {
		s.items = append(s.items, revokeItem{kind: itemPAM, on: true})
	}
	if len(a.Unassigned) > 0 && a.UnassignedAreThisKeys {
		s.items = append(s.items, revokeItem{kind: itemUnassigned, on: false})
	}
	for i := range a.Hosts {
		s.items = append(s.items, revokeItem{kind: itemHost, host: i, on: true})
	}
	if len(a.Files) > 0 {
		s.items = append(s.items, revokeItem{kind: itemArchive, on: true})
	}
	s.items = append(s.items, revokeItem{kind: itemKeyring, on: true})
	s.logins = append([]string{""}, sshkey.IdentityFiles(sshDir())...)
	// Never offer the revoked key's own files for logging in.
	var keep []string
	for _, l := range s.logins {
		mine := false
		for _, sk := range k.SSH {
			if l != "" && l == sk.Path {
				mine = true
			}
		}
		if !mine {
			keep = append(keep, l)
		}
	}
	s.logins = keep
	ti := textinput.New()
	ti.CharLimit = 40
	ti.Width = 20
	s.confirm = ti
	s.cursor = 0
	return s, nil
}

func (m model) updateRevoke(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.revoke
	switch msg := msg.(type) {
	case revokeHostDoneMsg:
		r := sshkey.ParseRemoveOutput(msg.out)
		if msg.err != nil && r.Kind == "" {
			r = sshkey.RemoveResult{Kind: "error: " + msg.err.Error()}
		}
		s.results[msg.host] = r
		return m.revokeNextHost()
	case tea.KeyMsg:
		if s.busy != "" {
			return m, nil
		}
		if s.a == nil {
			return m.updateRevokePick(msg)
		}
		return m.updateRevokeItems(msg)
	}
	if s.a != nil {
		var cmd tea.Cmd
		s.confirm, cmd = s.confirm.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) updateRevokePick(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := &m.revoke
	switch key.String() {
	case "esc", "q":
		m.mode = modeKeys
	case "up", "k":
		s.pick = max(s.pick-1, 0)
	case "down", "j":
		s.pick = min(s.pick+1, len(s.keys)-1)
	case "enter":
		if len(s.keys) == 0 {
			return m, nil
		}
		ns, err := m.revokeAnalyze()
		if err != nil {
			s.err = err.Error()
			return m, nil
		}
		m.revoke = ns
		m.revoke.confirm.Focus()
		return m, textinput.Blink
	}
	return m, nil
}

func (m model) updateRevokeItems(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := &m.revoke
	switch key.String() {
	case "esc":
		s.a = nil
		s.err = ""
		return m, nil
	case "up":
		s.cursor = max(s.cursor-1, 0)
		return m, nil
	case "down", "tab":
		s.cursor = min(s.cursor+1, len(s.items)-1)
		return m, nil
	case " ":
		if it := &s.items[s.cursor]; it.kind != itemKeyring {
			it.on = !it.on
		}
		return m, nil
	case "left", "right":
		if len(s.logins) > 1 {
			d := 1
			if key.String() == "left" {
				d = len(s.logins) - 1
			}
			s.login = (s.login + d) % len(s.logins)
		}
		return m, nil
	case "enter":
		return m.revokeStart()
	}
	var cmd tea.Cmd
	s.confirm, cmd = s.confirm.Update(key)
	return m, cmd
}

func (m model) revokeStart() (tea.Model, tea.Cmd) {
	s := &m.revoke
	s.err = ""
	if strings.TrimSpace(s.confirm.Value()) != s.a.Key.Label {
		s.err = fmt.Sprintf("Type the key's label %q to confirm.", s.a.Key.Label)
		return m, nil
	}
	s.queue = nil
	for _, it := range s.items {
		if it.kind == itemHost && it.on {
			if _, done := s.results[it.host]; !done {
				s.queue = append(s.queue, it.host)
			}
		}
	}
	return m.revokeNextHost()
}

// revokeNextHost runs the next server cleanup, or builds the local plans
// once all hosts are done.
func (m model) revokeNextHost() (tea.Model, tea.Cmd) {
	s := &m.revoke
	if len(s.queue) == 0 {
		s.busy = ""
		return m.revokePlans()
	}
	h := s.queue[0]
	s.queue = s.queue[1:]
	host := s.a.Hosts[h]
	line := host.Key.PublicKey
	if line == "" {
		line = strings.TrimSpace(string(mustRead(host.Key.Path + ".pub")))
	}
	blob, err := sshkey.BlobOf(line)
	if err == nil && line != "" {
		if pk, perr := sshkey.ParsePub(line); perr != nil || pk.Fingerprint != host.Key.Fingerprint {
			err = errors.New("public key does not match the recorded fingerprint")
		}
	}
	if err != nil {
		s.results[h] = sshkey.RemoveResult{Kind: "error: cannot find the public key (" + err.Error() + ")"}
		return m.revokeNextHost()
	}
	cmd, err := sshkey.RemoveCommand(host.Host, blob, s.logins[s.login])
	if err != nil {
		s.results[h] = sshkey.RemoveResult{Kind: "error: " + err.Error()}
		return m.revokeNextHost()
	}
	login := s.logins[s.login]
	owner := describeLogin(s.keys, login).owner
	how := "login: ssh default"
	if owner != nil {
		how = fmt.Sprintf("login: %s (%s)", filepath.Base(login), owner.Label)
	}
	s.busy = "Cleaning " + host.Host + "…"
	return m.startRun(runJob{
		title:   fmt.Sprintf("Remove %s from %s", host.Key.Comment, host.Host),
		lines:   []string{how},
		cmd:     cmd,
		need:    owner,
		needWhy: "for the login with " + filepath.Base(login),
		key:     owner,
		back:    modeRevoke,
		done: func(r runResult) tea.Msg {
			return revokeHostDoneMsg{host: h, out: r.stdout, err: r.err}
		},
	})
}

func (m model) revokePlans() (tea.Model, tea.Cmd) {
	s := &m.revoke
	ch := revoke.Choices{HostsCleaned: map[string]bool{}}
	for _, it := range s.items {
		switch it.kind {
		case itemPAM:
			ch.RemoveRecorded = it.on
		case itemUnassigned:
			ch.RemoveUnassigned = it.on
		case itemArchive:
			ch.ArchiveFiles = it.on
		}
	}
	for h, r := range s.results {
		if r.Done() {
			ch.HostsCleaned[revoke.HostKey(s.a.Hosts[h])] = true
		}
	}
	now := time.Now()
	base, err := plan.ReadBase(mappingPath())
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	up, err := revoke.UserPlan(s.a, ch, currentUser(), base, now)
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	rp, err := revoke.RootPlan(m.cfg.KeyringPath, s.a, ch, now)
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	m.review, err = newReviewPair(up, rp)
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	var notes []string
	for h, r := range s.results {
		notes = append(notes, fmt.Sprintf("%s: %s", s.a.Hosts[h].Host, r))
	}
	if ch.ArchiveFiles {
		notes = append(notes, fmt.Sprintf("After applying, %d key file(s) move to %s.", len(s.a.Files), tildePath(revoke.ArchiveDir(sshDir()))))
		m.pendingArchive = s.a.Files
	} else {
		m.pendingArchive = nil
	}
	m.review.note = strings.Join(notes, "\n")
	m.reviewBack = modeRevoke
	m.mode = modeReview
	return m, nil
}

func (s revokeScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Revoke a key") + "\n\n")
	if s.a == nil {
		if len(s.keys) == 0 {
			b.WriteString("No registered keys.\n")
		}
		for i, k := range s.keys {
			where := dimStyle.Render("not connected")
			if s.connected[k.Serial] {
				where = okStyle.Render("connected")
			}
			line := fmt.Sprintf("%-12s %-12s %s  %s", k.Label, k.Role, k.Serial, where)
			if i == s.pick {
				b.WriteString(selStyle.Render("▸ ") + line + "\n")
			} else {
				b.WriteString("  " + line + "\n")
			}
		}
		if s.err != "" {
			b.WriteString("\n" + errStyle.Render(s.err) + "\n")
		}
		return b.String()
	}

	a := s.a
	b.WriteString(fmt.Sprintf("Key %q (%s, %s)\n\n", a.Key.Label, a.Key.Role, a.Key.Serial))
	box := func(on bool) string {
		if on {
			return okStyle.Render("[x]")
		}
		return dimStyle.Render("[ ]")
	}
	for i, it := range s.items {
		var text string
		switch it.kind {
		case itemPAM:
			text = fmt.Sprintf("PAM: remove credential(s) %s from %s", credList(a.Recorded), tildePath(mappingPath()))
		case itemUnassigned:
			text = fmt.Sprintf("PAM: also remove %s — on none of your other keys (all checked), so a lost or unknown key's", credList(a.Unassigned))
		case itemHost:
			h := a.Hosts[it.host]
			text = fmt.Sprintf("SSH: remove %s from %s", h.Key.Comment, h.Host)
			if r, ok := s.results[it.host]; ok {
				st := okStyle
				if !r.Done() {
					st = errStyle
				}
				text += "  " + st.Render("→ "+r.String())
			}
		case itemArchive:
			var names []string
			for _, f := range a.Files {
				names = append(names, filepath.Base(f))
			}
			text = fmt.Sprintf("Files: move %s to %s", strings.Join(names, ", "), tildePath(revoke.ArchiveDir(sshDir())))
		case itemKeyring:
			text = "Keyring: remove the key, remember it as revoked (servers not cleaned are kept as to-do)"
		}
		cur := "  "
		if i == s.cursor {
			cur = selStyle.Render("▸ ")
		}
		b.WriteString(cur + box(it.on) + " " + text + "\n")
	}
	if len(a.Recorded) == 0 && !(len(a.Unassigned) > 0 && a.UnassignedAreThisKeys) {
		b.WriteString(dimStyle.Render("  (no PAM credential known for this key)") + "\n")
	}
	if len(a.Hosts) > 0 {
		login := describeLogin(s.keys, s.logins[s.login]).hint(s.connected, "")
		b.WriteString("\n" + dimStyle.Render("Log in to servers with: ") + "◂ " + login + " ▸" + dimStyle.Render("  (←/→)") + "\n")
	}

	conf := "none"
	if len(a.RemainingConfirmed) > 0 {
		conf = strings.Join(a.RemainingConfirmed, ", ")
	}
	b.WriteString("\n" + dimStyle.Render("Keys that still work with PAM afterwards: "+conf) + "\n")
	for _, w := range a.Warnings {
		b.WriteString(warnStyle.Render("! "+w) + "\n")
	}
	b.WriteString(dimStyle.Render("Remove it from websites (passkeys/2FA) yourself.") + "\n\n")
	b.WriteString(fmt.Sprintf("Type %q to confirm: ", a.Key.Label) + s.confirm.View() + "\n")
	if s.busy != "" {
		b.WriteString("\n" + s.busy + "\n")
	}
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}

func credList(cs []revoke.Cred) string {
	var p []int
	for _, c := range cs {
		p = append(p, c.Pos)
	}
	return joinInts(p)
}

// archivePending moves the revoked key's files after the plan applied.
func archivePending(files []string) string {
	moved, err := revoke.Archive(files, revoke.ArchiveDir(sshDir()))
	if err != nil {
		return fmt.Sprintf(" Moving key files stopped: %v (moved %d).", err, len(moved))
	}
	if len(moved) == 0 {
		return ""
	}
	return fmt.Sprintf(" Key files moved to %s.", tildePath(revoke.ArchiveDir(sshDir())))
}
