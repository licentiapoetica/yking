package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/elevate"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/targets"
)

// review shows a plan's diff before anything is written. It can carry
// two plans: userPlan (the user's own files, applied in-process without
// root) and plan (system files, applied via `sudo yking apply`). Either
// may be nil, not both.
type review struct {
	note     string // extra warning shown above the diff
	plan     *plan.Plan
	userPlan *plan.Plan
	lines    []string
	offset   int
	err      string
	userDone string // id of the applied user plan, once applied
}

type applyDoneMsg struct {
	id     string
	userID string
	err    error
}

func newReview(p *plan.Plan) (review, error) { return newReviewPair(nil, p) }

func newReviewPair(user, root *plan.Plan) (review, error) {
	var d strings.Builder
	for _, p := range []*plan.Plan{user, root} {
		if p == nil || p.Empty() {
			continue
		}
		s, err := p.Diff()
		if err != nil {
			return review{}, err
		}
		d.WriteString(s)
	}
	if d.Len() == 0 {
		return review{}, plan.ErrNoChanges
	}
	if user != nil && user.Empty() {
		user = nil
	}
	if root != nil && root.Empty() {
		root = nil
	}
	return review{plan: root, userPlan: user, lines: strings.Split(strings.TrimRight(d.String(), "\n"), "\n")}, nil
}

// planDir is where plans wait for the elevated apply.
func planDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "yking", "plans"), nil
}

func (m model) updateReview(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	r := &m.review
	page := max(m.height-12, 5)
	switch key.String() {
	case "esc", "q":
		if r.userDone != "" {
			m.status = warnStyle.Render("Your file was changed (" + r.userDone + "), the system part was not applied.")
			m.mode = modeKeys
			return m, m.scan()
		}
		m.mode = m.reviewBack
		return m, nil
	case "up", "k":
		r.offset--
	case "down", "j":
		r.offset++
	case "pgup":
		r.offset -= page
	case "pgdown", " ":
		r.offset += page
	case "a":
		// 1) The user's own files, in-process, no root.
		if r.userPlan != nil && r.userDone == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				r.err = err.Error()
				return m, nil
			}
			um, err := targets.UserApplier(home).Apply(r.userPlan)
			if err != nil {
				r.err = "changing your file failed: " + err.Error()
				return m, nil
			}
			r.userDone = um.ID
		}
		if r.plan == nil {
			id := r.userDone
			return m, func() tea.Msg { return applyDoneMsg{userID: id} }
		}
		// 2) System files via sudo.
		dir, err := planDir()
		if err != nil {
			r.err = err.Error()
			return m, nil
		}
		path := filepath.Join(dir, r.plan.ID+".json")
		if err := r.plan.Save(path); err != nil {
			r.err = err.Error()
			return m, nil
		}
		// Applied on the run screen: sudo's PIN/password prompt and, for PAM
		// changes, the keep-or-roll-back question are asked there.
		cmd, err := elevate.SelfTUI("apply", "--tui", sockArg, path)
		if err != nil {
			r.err = err.Error()
			return m, nil
		}
		id, uid := r.plan.ID, r.userDone
		return m.startRun(runJob{
			title:    "Apply: " + r.plan.Description,
			lines:    nil,
			cmd:      cmd,
			key:      m.onlyKey(),
			noCancel: true,
			hold:     true,
			outLines: 12,
			back:     modeReview,
			done: func(res runResult) tea.Msg {
				os.Remove(path)
				return applyDoneMsg{id: id, userID: uid, err: res.err}
			},
		})
	}
	r.offset = min(max(r.offset, 0), max(len(r.lines)-page, 0))
	return m, nil
}

func (r review) view(height int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Review plan") + "\n")
	for _, p := range []*plan.Plan{r.userPlan, r.plan} {
		if p == nil {
			continue
		}
		who := "system file(s), applied with sudo"
		if p == r.userPlan {
			who = "your file(s), no sudo needed"
		}
		b.WriteString(p.Description + dimStyle.Render("  ("+who+")") + "\n")
		b.WriteString(dimStyle.Render(p.Summary()))
	}
	b.WriteString("\n")
	if r.note != "" {
		b.WriteString(warnStyle.Render(r.note) + "\n\n")
	}

	page := max(height-12, 5)
	end := min(r.offset+page, len(r.lines))
	for _, l := range r.lines[r.offset:end] {
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
			b.WriteString(dimStyle.Render(l))
		case strings.HasPrefix(l, "@@"):
			b.WriteString(hunkStyle.Render(l))
		case strings.HasPrefix(l, "+"):
			b.WriteString(okStyle.Render(l))
		case strings.HasPrefix(l, "-"):
			b.WriteString(errStyle.Render(l))
		default:
			b.WriteString(l)
		}
		b.WriteString("\n")
	}
	if len(r.lines) > page {
		b.WriteString(dimStyle.Render(fmt.Sprintf("lines %d–%d of %d", r.offset+1, end, len(r.lines))) + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("backups kept · undo: yking history") + "\n")
	if r.userDone != "" {
		b.WriteString(okStyle.Render("Your file is already updated ("+r.userDone+"); press a again to apply the system part.") + "\n")
	}
	if r.err != "" {
		b.WriteString(errStyle.Render(r.err) + "\n")
	}
	return b.String()
}
