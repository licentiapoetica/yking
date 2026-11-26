package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// linkScreen proves which YubiKey holds an SSH key made outside yking
// (test signature: touch + PIN once) and records it in the keyring.

type linkScreen struct {
	key    detect.KeyReport
	cands  []sshkey.PubKey
	idx    int
	hosts  textinput.Model
	focus  int // 0 = key list, 1 = hosts
	busy   string
	err    string
	failed map[string]string // pub path → why not this key
}

type linkReadyMsg struct {
	pub    sshkey.PubKey
	handle sshkey.SKHandle
	err    error
}

type linkSignedMsg struct {
	pub          sshkey.PubKey
	handle       sshkey.SKHandle
	err          error
	pinRequested bool
}

func newLinkScreen(k detect.KeyReport, cands []sshkey.PubKey) linkScreen {
	ti := textinput.New()
	ti.CharLimit = 300
	ti.Width = 50
	ti.Placeholder = "optional: user@host, other-host"
	return linkScreen{key: k, cands: cands, hosts: ti, failed: map[string]string{}}
}

func privOf(pub string) string { return strings.TrimSuffix(pub, ".pub") }

func parseHosts(s string) ([]string, error) {
	var out []string
	for _, h := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if err := sshkey.ValidTarget(h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

func (m model) updateLink(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.link
	switch msg := msg.(type) {
	case linkReadyMsg:
		if msg.err != nil {
			s.busy, s.err = "", msg.err.Error()
			return m, nil
		}
		return m.linkSign(msg.pub, msg.handle)
	case linkSignedMsg:
		s.busy = ""
		if msg.err != nil {
			why := "not on this key"
			if msg.pinRequested && !strings.Contains(msg.err.Error(), "device not found") {
				why = "failed: " + msg.err.Error() + " (if the PIN was wrong, one attempt was used)"
			}
			s.failed[msg.pub.Path] = why
			return m, nil
		}
		return m.linkRecord(msg.pub, msg.handle)
	case tea.KeyMsg:
		if s.busy != "" {
			return m, nil
		}
		switch msg.String() {
		case "esc":
			m.mode = modeKeys
			return m, nil
		case "tab":
			s.focus = 1 - s.focus
			if s.focus == 1 {
				s.hosts.Focus()
			} else {
				s.hosts.Blur()
			}
			return m, nil
		case "enter":
			if len(s.cands) == 0 {
				return m, nil
			}
			s.err = ""
			if _, err := parseHosts(s.hosts.Value()); err != nil {
				s.err = err.Error()
				return m, nil
			}
			s.busy = "Checking that only this key is connected…"
			return m, m.linkPrepare(s.cands[s.idx])
		}
		if s.focus == 0 {
			switch msg.String() {
			case "up", "k":
				s.idx = max(s.idx-1, 0)
			case "down", "j":
				s.idx = min(s.idx+1, len(s.cands)-1)
			}
			return m, nil
		}
	}
	var cmd tea.Cmd
	if s.focus == 1 {
		s.hosts, cmd = s.hosts.Update(msg)
	}
	return m, cmd
}

func (m model) linkPrepare(pub sshkey.PubKey) tea.Cmd {
	serial := m.link.key.Serial
	return func() tea.Msg {
		if _, err := m.singleKeyDevice(context.Background(), serial); err != nil {
			return linkReadyMsg{err: err}
		}
		h, err := sshkey.ReadSKHandle(privOf(pub.Path))
		if errors.Is(err, sshkey.ErrEncrypted) {
			return linkReadyMsg{err: errors.New("the key file has a passphrase; yking cannot test it (ssh-keygen would ask for the passphrase)")}
		}
		if err != nil {
			return linkReadyMsg{err: err}
		}
		return linkReadyMsg{pub: pub, handle: h}
	}
}

func (m model) linkSign(pub sshkey.PubKey, h sshkey.SKHandle) (tea.Model, tea.Cmd) {
	s := &m.link
	info := askpass.Info{Label: s.key.Known.Label, Serial: s.key.Serial, Retries: -1}
	if f := s.key.FIDO; f != nil {
		info.Retries, info.MinPINLength = f.PINRetries, f.MinPINLength
		if h.PINRequired() {
			if ok, why := f.PINPromptAllowed(); !ok {
				s.err = "not testing: " + why
				return m, nil
			}
		}
	}
	self, err := os.Executable()
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	dir, err := os.MkdirTemp(os.Getenv("XDG_RUNTIME_DIR"), "yking-link-")
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	data := filepath.Join(dir, "test")
	os.WriteFile(data, []byte("yking ownership test "+time.Now().String()+"\n"), 0o600)
	sess, err := askpass.Prepare(self, info)
	if err != nil {
		os.RemoveAll(dir)
		s.err = err.Error()
		return m, nil
	}
	how := "touch the key when it blinks"
	if h.PINRequired() {
		how = "enter the PIN (asked once), then touch the key"
	}
	run := &introExec{
		cmd:   sshkey.SignTestCommand(privOf(pub.Path), data, sess.Env),
		intro: fmt.Sprintf("\nyking: testing whether %s is on key %q (%s): %s.\nyking: this only signs a throwaway file; nothing is stored.\n\n", filepath.Base(privOf(pub.Path)), s.key.Known.Label, s.key.Serial, how),
	}
	s.busy = "Testing…"
	return m, tea.Exec(run, func(err error) tea.Msg {
		asked := sess.PINWasRequested()
		sess.Close()
		os.RemoveAll(dir)
		return linkSignedMsg{pub: pub, handle: h, err: withTail(err, run), pinRequested: asked}
	})
}

func (m model) linkRecord(pub sshkey.PubKey, h sshkey.SKHandle) (tea.Model, tea.Cmd) {
	s := &m.link
	hosts, _ := parseHosts(s.hosts.Value())
	entry := sshkey.LinkEntry(pub, privOf(pub.Path), h, currentUser(), hosts, time.Now())
	p, err := sshkey.RecordPlan(m.cfg.KeyringPath, s.key.Serial, entry, time.Now())
	if err == nil {
		m.review, err = newReview(p)
	}
	if err != nil {
		s.err = "the key signed, but recording failed: " + err.Error()
		return m, nil
	}
	m.status = okStyle.Render(fmt.Sprintf("%s is on %q. Apply below to link it.", filepath.Base(privOf(pub.Path)), s.key.Known.Label))
	m.reviewBack = modeKeys
	m.mode = modeReview
	return m, nil
}

func (s linkScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf("Link an SSH key to %q (%s)", s.key.Known.Label, s.key.Serial)) + "\n")
	b.WriteString(dimStyle.Render("PIN-protected SSH keys are invisible without the PIN, so the test is a real\nsignature of a throwaway file: PIN once + touch. Plug in only this key.") + "\n\n")
	if len(s.cands) == 0 {
		b.WriteString("No unlinked security-key SSH keys in ~/.ssh.\n")
	}
	for i, p := range s.cands {
		line := fmt.Sprintf("%-14s %s", filepath.Base(privOf(p.Path)), dimStyle.Render(p.Comment))
		if why, ok := s.failed[p.Path]; ok {
			line += "  " + warnStyle.Render("✗ "+why)
		}
		if i == s.idx {
			cur := selStyle.Render("▸ ")
			if s.focus != 0 {
				cur = "› "
			}
			b.WriteString(cur + line + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	cur := "  "
	if s.focus == 1 {
		cur = selStyle.Render("▸ ")
	}
	b.WriteString("\n" + cur + "Already deployed to: " + s.hosts.View() + "\n")
	b.WriteString(dimStyle.Render("  (so a later revoke can remove it from those servers)") + "\n")
	if s.busy != "" {
		b.WriteString("\n" + s.busy + "\n")
	}
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}
