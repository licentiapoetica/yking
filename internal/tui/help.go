package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	keyCap   = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(lipgloss.Color("238")).Padding(0, 1)
	keyLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	ruleSt   = lipgloss.NewStyle().Foreground(lipgloss.Color("237"))
)

// renderHelp draws "key label · key label" as key caps with labels,
// wrapped to width. A part without a label is shown as plain dim text.
func renderHelp(help string, width int) string { return renderHelpMax(help, width, 0) }

// moreKeys ends a help bar that was cut short.
const moreKeys = "? all keys"

// renderHelpMax is renderHelp in at most maxLines lines (0: no limit);
// what does not fit is replaced by "? all keys".
func renderHelpMax(help string, width, maxLines int) string {
	all := helpItems(help)
	max := width
	if max <= 0 {
		max = 100
	}
	lines := flowHelp(all, max)
	for n := len(all) - 1; maxLines > 0 && len(lines) > maxLines && n >= 0; n-- {
		lines = flowHelp(append(append([]string{}, all[:n]...), helpItems(moreKeys)...), max)
	}
	rule := ruleSt.Render(strings.Repeat("─", min(max, 100)))
	return rule + "\n" + strings.Join(lines, "\n")
}

// helpList is the full help, one key per line.
func helpList(help string) string {
	var b strings.Builder
	for _, it := range helpItems(help) {
		b.WriteString("  " + it + "\n")
	}
	return b.String()
}

func helpItems(help string) []string {
	var items []string
	for _, part := range strings.Split(help, " · ") {
		k, label, ok := strings.Cut(part, " ")
		if !ok || strings.HasSuffix(part, "…") {
			items = append(items, keyLabel.Render(part))
			continue
		}
		items = append(items, keyCap.Render(k)+" "+keyLabel.Render(label))
	}
	return items
}

func flowHelp(items []string, max int) []string {
	var lines []string
	cur := ""
	for _, it := range items {
		if cur != "" && lipgloss.Width(cur)+3+lipgloss.Width(it) > max {
			lines = append(lines, cur)
			cur = ""
		}
		if cur != "" {
			cur += "   "
		}
		cur += it
	}
	return append(lines, cur)
}
