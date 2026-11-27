package tui

import (
	"regexp"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// The layout fits every screen into the terminal: lines wrap at its width
// (continuations keep their indent), and when the content is taller than
// the window the middle scrolls — following the ▸ cursor, PgUp/PgDn
// otherwise — while title, status and help stay on screen.

const minWidth, minHeight = 30, 10

type layoutParts struct {
	head, body, status, help []string
	avail                    int // lines the body may use
}

func (m model) layout() layoutParts {
	w := m.width
	var f layoutParts
	f.head = []string{titleStyle.Render("yking") + dimStyle.Render(" — YubiKey setup")}
	roomy := m.height >= 24
	if roomy {
		f.head = append(f.head, "")
	}
	_, help := m.screen(m.height)
	limit := 0
	if !m.typing() {
		limit = max(2, m.height/5)
	}
	if m.helpOpen {
		help, limit = "? close · esc close", 0
	}
	f.help = strings.Split(renderHelpMax(help, w, limit), "\n")
	if roomy {
		f.help = append([]string{""}, f.help...)
	}
	if m.status != "" {
		st := fitLines(strings.TrimRight(m.status, "\n"), w)
		if limit := max(m.height/3, 2); len(st) > limit {
			st = append(st[:limit-1], dimStyle.Render("…"))
		}
		f.status = append([]string{""}, st...)
	}
	f.avail = max(m.height-len(f.head)-len(f.help)-len(f.status), 1)
	body, full := m.screen(f.avail)
	if m.helpOpen {
		body = helpList(full)
	}
	f.body = fitLines(strings.TrimRight(body, "\n"), w)
	return f
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 { // size not known yet
		body, help := m.screen(40)
		return body + "\n" + renderHelp(help, 0)
	}
	if m.width < minWidth || m.height < minHeight {
		return warnStyle.Render(ansi.Wrap("Window too small for yking — make it larger.", m.width, ""))
	}
	f := m.layout()
	body := f.body
	if len(body) > f.avail {
		off := scrollOffset(body, f.avail, m.scroll, !m.free)
		body = append([]string{}, body[off:off+f.avail]...)
		if off > 0 {
			body[0] = dimStyle.Render("  ↑ more · PgUp")
		}
		if off+f.avail < len(f.body) {
			body[len(body)-1] = dimStyle.Render("  ↓ more · PgDn")
		}
	}
	lines := append(append(append(append([]string{}, f.head...), body...), f.status...), f.help...)
	return strings.Join(lines, "\n")
}

// scrollOffset is the first body line shown: scroll, moved so that the
// line with the ▸ cursor stays visible (not under a "more" marker) when
// follow is set.
func scrollOffset(body []string, avail, scroll int, follow bool) int {
	n := len(body)
	if n <= avail {
		return 0
	}
	off := min(max(scroll, 0), n-avail)
	cursor := -1
	for i, l := range body {
		if strings.Contains(l, "▸") {
			cursor = i
			break
		}
	}
	if follow && cursor >= 0 && avail >= 3 {
		if cursor <= off {
			off = cursor - 1
		}
		if cursor >= off+avail-1 {
			off = cursor - avail + 2
		}
	}
	return min(max(off, 0), n-avail)
}

// scrollBy moves the body by delta lines (PgUp/PgDn).
func (m model) scrollBy(delta int) model {
	if m.width == 0 || m.height == 0 {
		return m
	}
	f := m.layout()
	if len(f.body) <= f.avail {
		m.scroll = 0
		return m
	}
	off := scrollOffset(f.body, f.avail, m.scroll, !m.free)
	m.scroll = min(max(off+delta, 0), len(f.body)-f.avail)
	m.free = true
	return m
}

// wheelStep is how many lines one wheel notch scrolls.
const wheelStep = 3

// wheel scrolls with the mouse wheel; other mouse events are ignored.
func (m model) wheel(ms tea.MouseMsg) (tea.Model, tea.Cmd) {
	if ms.Action != tea.MouseActionPress {
		return m, nil
	}
	dir := 0
	switch ms.Button {
	case tea.MouseButtonWheelUp:
		dir = -1
	case tea.MouseButtonWheelDown:
		dir = 1
	default:
		return m, nil
	}
	if m.pagesOwnScroll() && !m.helpOpen { // review, doctor: their own line scroll
		key := tea.KeyMsg{Type: tea.KeyDown}
		if dir < 0 {
			key = tea.KeyMsg{Type: tea.KeyUp}
		}
		var next tea.Model = m
		for range wheelStep {
			next, _ = next.(model).update(key)
		}
		return next, nil
	}
	return m.scrollBy(dir * wheelStep), nil
}

// typing: a text field has the keys, so "?" is a character, not help.
func (m model) typing() bool {
	switch m.mode {
	case modeEnroll, modeSSH, modeDeploy, modeLink, modeRevoke, modeRun:
		return true
	case modePGP:
		return m.pgp.inputFor != pgpInputNone
	case modeKeePass:
		return m.kp.inputFor != kpInputNone
	}
	return false
}

// pagesOwnScroll: screens that page with PgUp/PgDn themselves.
func (m model) pagesOwnScroll() bool { return m.mode == modeReview || m.mode == modeDoctor }

// fitLines splits s into lines no wider than w, wrapping long ones; a
// continuation keeps the original line's indent.
func fitLines(s string, w int) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if w <= 0 || ansi.StringWidth(line) <= w {
			out = append(out, line)
			continue
		}
		plain := ansi.Strip(line)
		indent := len(plain) - len(strings.TrimLeft(plain, " "))
		if indent > w/3 {
			indent = 0
		}
		// ansi.Wrap always breaks after "-": shield hyphens so dates and
		// names like home-backup stay whole.
		shielded := strings.ReplaceAll(line, "-", "\u2011")
		wrapped := strings.ReplaceAll(ansi.Wrap(shielded, w-indent, ""), "\u2011", "-")
		parts := selfContained(strings.Split(wrapped, "\n"))
		for i, p := range parts {
			if i > 0 {
				p = strings.Repeat(" ", indent) + strings.TrimLeft(p, " ")
			}
			out = append(out, p)
		}
	}
	return out
}

// fitPane renders content in a pane at most w columns wide.
func fitPane(content string, w int) string {
	p := paneStyle.Render(content)
	if w <= 0 || lipgloss.Width(p) <= w {
		return p
	}
	for inner := w - 2; inner > 4; inner-- {
		if p = paneStyle.Width(inner).Render(content); lipgloss.Width(p) <= w {
			return p
		}
	}
	return p
}

var sgrRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// selfContained makes every wrapped line carry its own colours: the styles
// still open from earlier lines are reopened at its start and reset at its
// end, so a line shown alone (scrolled) neither loses nor leaks colour.
func selfContained(lines []string) []string {
	open := ""
	for i, l := range lines {
		start := open
		for _, seq := range sgrRe.FindAllString(l, -1) {
			if seq == "\x1b[0m" || seq == "\x1b[m" {
				open = ""
			} else {
				open += seq
			}
		}
		l = start + l
		if open != "" {
			l += "\x1b[0m"
		}
		lines[i] = l
	}
	return lines
}
