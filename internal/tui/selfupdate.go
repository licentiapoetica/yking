package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/fsutil"
	"github.com/licentiapoetica/yking/internal/plan"
)

// installedStale reports whether /usr/local/bin/yking (what a plain
// `yking` runs, and what udev starts) exists and differs from the running
// binary, with both files' times for the banner ("" when not stale).
// Running the installed copy itself is never "stale": it cannot know about
// newer builds.
func installedStale() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(self); err == nil {
		self = r
	}
	if self == events.BinaryPath {
		return ""
	}
	inst, err := os.ReadFile(events.BinaryPath)
	if err != nil {
		return ""
	}
	mine, err := os.ReadFile(self)
	if err != nil || fsutil.SHA256(inst) == fsutil.SHA256(mine) {
		return ""
	}
	when := func(p string) string {
		if fi, err := os.Stat(p); err == nil {
			return fi.ModTime().Format("Jan 2 15:04")
		}
		return "?"
	}
	return fmt.Sprintf("%s, this build %s", when(events.BinaryPath), when(self))
}

// updateInstalled reviews replacing ONLY /usr/local/bin/yking with this
// binary (hash-pinned; applied with sudo like every system change).
func (m model) updateInstalled() (tea.Model, tea.Cmd) {
	self, err := os.Executable()
	if err == nil {
		p := plan.New("update "+events.BinaryPath+" to this yking", time.Now())
		if err = p.Install(events.BinaryPath, self, 0o755); err == nil {
			m.review, err = newReview(p)
		}
	}
	if err != nil {
		m.status = errStyle.Render("Cannot update " + events.BinaryPath + ": " + err.Error())
		return m, nil
	}
	m.reviewBack = modeKeys
	m.mode = modeReview
	m.status = ""
	return m, nil
}
