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
func renderHelp(help string, width int) string {
	var items []string
	for _, part := range strings.Split(help, " · ") {
		k, label, ok := strings.Cut(part, " ")
		if !ok || strings.HasSuffix(part, "…") {
			items = append(items, keyLabel.Render(part))
			continue
		}
		items = append(items, keyCap.Render(k)+" "+keyLabel.Render(label))
	}
	max := width
	if max <= 0 {
		max = 100
	}
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
	lines = append(lines, cur)
	rule := ruleSt.Render(strings.Repeat("─", min(max, 100)))
	return rule + "\n" + strings.Join(lines, "\n")
}
