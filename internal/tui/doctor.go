package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/doctor"
	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
)

type doctorScreen struct {
	findings []doctor.Finding
	rows     []doctor.Row
	offset   int
	err      string
}

type doctorDoneMsg struct {
	findings []doctor.Finding
	rows     []doctor.Row
	err      error
}

type keyTestMsg struct {
	serial string
	lines  []string
	ok     bool
	err    error
}

func (m model) doctorOptions() doctor.Options {
	home, _ := os.UserHomeDir()
	self, _ := os.Executable()
	return doctor.Options{KeyringPath: m.cfg.KeyringPath, Home: home, User: currentUser(), Client: m.cfg.Client, Self: self}
}

func (m model) runDoctor() tea.Cmd {
	o := m.doctorOptions()
	return func() tea.Msg {
		in, err := doctor.Gather(o)
		if err != nil {
			return doctorDoneMsg{err: err}
		}
		return doctorDoneMsg{findings: doctor.Run(in), rows: doctor.Coverage(in)}
	}
}

func (m model) updateDoctor(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.doctor
	switch msg := msg.(type) {
	case doctorDoneMsg:
		s.findings, s.rows, s.err = msg.findings, msg.rows, ""
		if msg.err != nil {
			s.err = msg.err.Error()
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q":
			m.mode = modeKeys
		case "r":
			s.findings = nil
			return m, m.runDoctor()
		case "up", "k":
			s.offset = max(s.offset-1, 0)
		case "down", "j":
			s.offset = min(s.offset+1, max(len(s.findings)-1, 0))
		}
	}
	return m, nil
}

// keyTest silently checks one connected key: PIN tries and its recorded
// PAM credentials. No touch, no PIN. Records the test date when it passes.
func (m model) keyTest(k keyring.Key) tea.Cmd {
	o := m.doctorOptions()
	return func() tea.Msg {
		ctx := context.Background()
		r := keyTestMsg{serial: k.Serial, ok: true}
		dev, err := m.singleKeyDevice(ctx, k.Serial)
		if err != nil {
			return keyTestMsg{serial: k.Serial, err: err}
		}
		f, err := m.cfg.Client.FIDOInfo(ctx, k.Serial)
		switch {
		case err != nil:
			r.ok = false
			r.lines = append(r.lines, "✗ FIDO2 state unreadable: "+err.Error())
		case f.PINBlocked:
			r.ok = false
			r.lines = append(r.lines, "✗ FIDO2 PIN is BLOCKED")
		case f.PINSet && f.PINRetries < 8:
			r.lines = append(r.lines, fmt.Sprintf("! %d of 8 PIN tries left (one correct PIN entry resets it)", f.PINRetries))
		case f.PINSet:
			r.lines = append(r.lines, "✓ FIDO2 PIN set, 8 of 8 tries left")
		default:
			r.lines = append(r.lines, "! no FIDO2 PIN set")
		}

		origin, _ := pam.Origin()
		mp, _, _ := readMapping()
		inMap := map[string]bool{}
		if mp != nil {
			for _, c := range mp.Creds(o.User) {
				inMap[c.KeyHandle] = true
			}
		}
		n := 0
		for _, c := range k.U2F {
			if c.User != o.User {
				continue
			}
			n++
			switch err := fido.Probe(ctx, dev, origin, c.KeyHandle); {
			case !inMap[c.KeyHandle]:
				r.ok = false
				r.lines = append(r.lines, "✗ a recorded PAM credential is missing from your mapping")
			case err == nil:
				r.lines = append(r.lines, "✓ PAM credential answers (works for sudo, login, lock screen …)")
			case errors.Is(err, fido.ErrNotThisKey):
				r.ok = false
				r.lines = append(r.lines, "✗ the key does NOT own its recorded PAM credential")
			default:
				r.ok = false
				r.lines = append(r.lines, "✗ PAM check failed: "+err.Error())
			}
		}
		if n == 0 {
			r.lines = append(r.lines, "! no PAM credential recorded — press c to check / add one")
		}
		if len(k.SSH) > 0 {
			r.lines = append(r.lines, fmt.Sprintf("· %d SSH key(s): PIN-protected, not testable silently (log in once with ssh -i …)", len(k.SSH)))
		}
		if r.ok {
			if err := doctor.RecordTest(o.Home, k.Serial, time.Now()); err != nil {
				r.lines = append(r.lines, "! could not save the test date: "+err.Error())
			} else {
				r.lines = append(r.lines, "✓ test date saved")
			}
		}
		return r
	}
}

func severityStyle(s doctor.Severity) (string, func(...string) string) {
	switch s {
	case doctor.Error:
		return "✗", errStyle.Render
	case doctor.Warn:
		return "!", warnStyle.Render
	case doctor.OK:
		return "✓", okStyle.Render
	default:
		return "·", dimStyle.Render
	}
}

func (s doctorScreen) view(height int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Doctor") + dimStyle.Render(" — read-only health check of the whole setup") + "\n\n")
	if s.err != "" {
		b.WriteString(errStyle.Render(s.err) + "\n")
		return b.String()
	}
	if s.findings == nil {
		b.WriteString("Checking…\n")
		return b.String()
	}

	fmt.Fprintf(&b, "  %s\n", dimStyle.Render(fmt.Sprintf("%-13s %-12s %-5s %-8s %-10s %-11s %s", "Key", "Role", "PAM", "SSH keys", "Connected", "Last test", "Servers")))
	for _, r := range s.rows {
		pamS := errStyle.Render("✗  ")
		if r.PAM {
			pamS = okStyle.Render("✓  ")
		}
		conn := dimStyle.Render("no        ")
		if r.Connected {
			conn = okStyle.Render("yes       ")
		}
		last := "never"
		if !r.LastTest.IsZero() {
			last = r.LastTest.Local().Format("2006-01-02")
		}
		hosts := strings.Join(r.Hosts, ", ")
		if hosts == "" {
			hosts = dimStyle.Render("—")
		}
		fmt.Fprintf(&b, "  %-13s %-12s %s   %-8d %s %-11s %s\n", pad(r.Label, 13), pad(r.Role, 12), pamS, r.SSHKeys, conn, last, hosts)
	}
	b.WriteString("\n")

	page := max(height-len(s.rows)-8, 3)
	end := min(s.offset+page, len(s.findings))
	for _, f := range s.findings[s.offset:end] {
		icon, style := severityStyle(f.Severity)
		b.WriteString(style(fmt.Sprintf("%s %-6s %s", icon, f.Area, f.Message)) + "\n")
		if f.Fix != "" {
			b.WriteString(dimStyle.Render("         → "+f.Fix) + "\n")
		}
	}
	if len(s.findings) > page {
		b.WriteString(dimStyle.Render(fmt.Sprintf("findings %d–%d of %d", s.offset+1, end, len(s.findings))) + "\n")
	}
	return b.String()
}
