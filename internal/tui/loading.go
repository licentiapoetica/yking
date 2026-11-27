package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// The loading screen: a YubiKey whose touch disc pulses while a shine
// sweeps across it, and the scan's real steps as they happen.

const frameEvery = 70 * time.Millisecond

type animTickMsg struct{}

type scanProgressMsg struct {
	p  detect.Progress
	ch <-chan tea.Msg
}

func animTick() tea.Cmd {
	return tea.Tick(frameEvery, func(time.Time) tea.Msg { return animTickMsg{} })
}

// scan runs the inventory in the background and streams its steps. Like
// any tea.Cmd it does nothing until the program runs it.
func (m model) scan() tea.Cmd {
	cfg := m.cfg
	return func() tea.Msg {
		ch := make(chan tea.Msg, 32)
		go runScan(cfg, ch)
		return waitScan(ch)()
	}
}

func runScan(cfg Config, ch chan tea.Msg) {
	defer close(ch)
	step := func(p detect.Progress) { ch <- scanProgressMsg{p: p, ch: ch} }
	step(detect.Progress{Step: "keyring", Text: "reading the keyring"})
	kr, err := keyring.Load(cfg.KeyringPath)
	if err != nil {
		ch <- scanDoneMsg{err: err}
		return
	}
	step(detect.Progress{Step: "keyring", Text: registered(len(kr.Keys)), Done: true})
	rep, err := detect.ScanProgress(context.Background(), cfg.Client, kr, step)
	step(detect.Progress{Step: "local", Text: "checking SSH keys and PAM credentials"})
	sk, _ := sshkey.ScanSK(sshDir())
	mp, _, _ := readMapping()
	cov := pam.Coverage(kr, mp, currentUser())
	ch <- scanDoneMsg{rep: rep, kr: kr, sshKeys: sk, coverage: cov, stale: installedStale(), err: err}
}

func registered(n int) string {
	switch n {
	case 0:
		return "keyring empty — no keys registered yet"
	case 1:
		return "keyring: 1 key registered"
	}
	return fmt.Sprintf("keyring: %d keys registered", n)
}

func waitScan(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

// onProgress records a step; a message from a new scan starts a new log.
func (m model) onProgress(msg scanProgressMsg) (tea.Model, tea.Cmd) {
	if msg.ch != m.scanCh {
		m.scanCh, m.scanLog = msg.ch, nil
	}
	for i := range m.scanLog {
		if m.scanLog[i].Step == msg.p.Step {
			m.scanLog[i] = msg.p
			return m, waitScan(msg.ch)
		}
	}
	m.scanLog = append(m.scanLog, msg.p)
	return m, waitScan(msg.ch)
}

// keepAnimating starts the frame clock when a scan is running and no clock
// is; a running clock stops itself once the scan is over.
func (m model) keepAnimating(cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if m.animating() && !m.ticking {
		m.ticking = true
		return m, tea.Batch(cmd, animTick())
	}
	return m, cmd
}

// animating: the loading screen or a run screen is up.
func (m model) animating() bool { return m.scanning || m.mode == modeRun }

func (m model) onTick() (tea.Model, tea.Cmd) {
	if !m.animating() {
		m.ticking = false
		return m, nil
	}
	m.frame++
	return m, animTick()
}

// --- drawing

var (
	pulse    = []string{"22", "28", "34", "40", "46", "83", "120", "83", "46", "40", "34", "28"}
	shine    = []string{"255", "253", "250", "247"}
	bodyGrey = lipgloss.Color("240")
	spinner  = []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}
)

// keyArt draws the key with label on its body; 'o' marks the touch disc.
// It returns the lines and the label's rune columns on the middle line.
func keyArt(label string) ([]string, int, int) {
	const field = 26
	text := label
	if n := len([]rune(label)); n > 0 && n*3-2 <= field-4 {
		text = strings.Join(strings.Split(label, ""), "  ")
	}
	if r := []rune(text); len(r) > field-4 {
		text = string(r[:field-5]) + "…"
	}
	pad := field - 4 - len([]rune(text))
	mid := "  │ ▪ ▪ ├─┤    " + text + strings.Repeat(" ", pad) + "│  o  │ │"
	start := len([]rune("  │ ▪ ▪ ├─┤    "))
	return []string{
		"          ╭" + strings.Repeat("─", 34) + "╮",
		"  ┌─────┐ │" + strings.Repeat(" ", field) + "╭─────╮ │",
		mid,
		"  └─────┘ │" + strings.Repeat(" ", field) + "╰─────╯ │",
		"          ╰" + strings.Repeat("─", 34) + "╯",
	}, start, start + len([]rune(text))
}

func (m model) viewLoading() string {
	var b strings.Builder
	if art := m.art("yking", false); art != "" {
		b.WriteString(art + "\n")
	}
	spin := selStyle.Render(spinner[m.frame%len(spinner)])
	b.WriteString("  " + spin + " " + titleStyle.Render("Scanning your YubiKeys") + "\n\n")
	for _, p := range m.scanLog {
		if p.Done {
			b.WriteString("    " + okStyle.Render("✓") + " " + p.Text + "\n")
		} else {
			b.WriteString("    " + selStyle.Render(spinner[(m.frame+3)%len(spinner)]) + " " + p.Text + dimStyle.Render(dots(m.frame)) + "\n")
		}
	}
	return b.String()
}

func dots(frame int) string { return strings.Repeat(".", (frame/5)%4) }

// art is the animated key, or "" when the window has no room for it.
func (m model) art(label string, fast bool) string {
	if m.width != 0 && (m.width < 50 || (m.height > 0 && m.height < 24)) {
		return ""
	}
	return drawKey(m.frame, label, fast)
}

// drawKey renders one frame: a diagonal shine moving left to right over the
// outline and lettering, and the disc breathing green like a YubiKey's LED
// (faster when fast is set: "touch me now").
func drawKey(frame int, label string, fast bool) string {
	art, from, to := keyArt(label)
	width := len([]rune(art[0]))
	span := width + 16
	pos := frame%span - 8
	p := frame
	if fast {
		p = frame * 2
	}
	disc := lipgloss.NewStyle().Foreground(lipgloss.Color(pulse[p%len(pulse)])).Bold(true)
	var b strings.Builder
	for y, line := range art {
		for x, r := range []rune(line) {
			switch {
			case r == ' ':
				b.WriteRune(r)
			case r == 'o' && y == 2 && x > to:
				b.WriteString(disc.Render("●"))
			default:
				d := x + y - pos // slanted band
				if d < 0 {
					d = -d
				}
				c := bodyGrey
				if d < len(shine) {
					c = lipgloss.Color(shine[d])
				} else if y == 2 && x >= from && x < to {
					c = lipgloss.Color("12")
				}
				b.WriteString(lipgloss.NewStyle().Foreground(c).Render(string(r)))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
