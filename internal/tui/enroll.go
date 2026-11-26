package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/enroll"
	"github.com/licentiapoetica/yking/internal/keyring"
)

const (
	fieldLabel = iota
	fieldRole
	fieldProtected
	numFields
)

type enrollForm struct {
	key       detect.KeyReport
	label     textinput.Model
	roleIdx   int
	protected bool
	focus     int
	err       string
	// labelEdited stops role changes from overwriting a label the user typed.
	labelEdited bool
	kr          *keyring.Keyring
}

func newEnrollForm(k detect.KeyReport, kr *keyring.Keyring) enrollForm {
	role := enroll.SuggestRole(kr)
	ti := textinput.New()
	ti.CharLimit = 40
	ti.Width = 30
	ti.SetValue(enroll.SuggestLabel(kr, role))
	ti.Focus()
	f := enrollForm{key: k, label: ti, protected: true, kr: kr}
	for i, r := range keyring.Roles {
		if r == role {
			f.roleIdx = i
		}
	}
	return f
}

func (f enrollForm) focusCmd() tea.Cmd { return textinput.Blink }

func (f enrollForm) role() keyring.Role { return keyring.Roles[f.roleIdx] }

func (f *enrollForm) setFocus(i int) {
	f.focus = (i + numFields) % numFields
	if f.focus == fieldLabel {
		f.label.Focus()
	} else {
		f.label.Blur()
	}
}

func (f *enrollForm) cycleRole(d int) {
	f.roleIdx = (f.roleIdx + d + len(keyring.Roles)) % len(keyring.Roles)
	if !f.labelEdited {
		f.label.SetValue(enroll.SuggestLabel(f.kr, f.role()))
	}
}

func (m model) updateEnroll(msg tea.Msg) (tea.Model, tea.Cmd) {
	f := &m.enroll
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		f.label, cmd = f.label.Update(msg)
		return m, cmd
	}
	switch key.String() {
	case "esc":
		m.mode = modeKeys
		return m, nil
	case "tab", "down":
		f.setFocus(f.focus + 1)
		return m, nil
	case "shift+tab", "up":
		f.setFocus(f.focus - 1)
		return m, nil
	case "enter":
		return m.buildEnrollPlan()
	}
	switch f.focus {
	case fieldLabel:
		before := f.label.Value()
		var cmd tea.Cmd
		f.label, cmd = f.label.Update(msg)
		if f.label.Value() != before {
			f.labelEdited = true
			f.err = ""
		}
		return m, cmd
	case fieldRole:
		switch key.String() {
		case "left", "h":
			f.cycleRole(-1)
		case "right", "l", " ":
			f.cycleRole(1)
		}
	case fieldProtected:
		switch key.String() {
		case " ", "left", "right", "h", "l":
			f.protected = !f.protected
		}
	}
	return m, nil
}

func (m model) buildEnrollPlan() (tea.Model, tea.Cmd) {
	f := &m.enroll
	label := strings.TrimSpace(f.label.Value())
	if label == "" {
		f.err = "Label must not be empty."
		f.setFocus(fieldLabel)
		return m, nil
	}
	p, err := enroll.Plan(m.cfg.KeyringPath, f.key, enroll.Request{
		Label: label, Role: f.role(), Protected: f.protected,
	}, time.Now())
	if err != nil {
		f.err = err.Error()
		return m, nil
	}
	r, err := newReview(p)
	if err != nil {
		f.err = err.Error()
		return m, nil
	}
	m.review = r
	m.reviewBack = modeEnroll
	m.mode = modeReview
	return m, nil
}

func (f enrollForm) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf("Register key %s", f.key.Serial)))
	if f.key.Info.DeviceType != "" {
		b.WriteString(dimStyle.Render("  " + f.key.Info.DeviceType + " · fw " + f.key.Info.Firmware))
	}
	b.WriteString("\n" + dimStyle.Render("Host-side only: adds an entry to the keyring. Nothing is written to the key.") + "\n\n")

	cursor := func(i int) string {
		if f.focus == i {
			return selStyle.Render("▸ ")
		}
		return "  "
	}

	b.WriteString(cursor(fieldLabel) + fmt.Sprintf("%-10s ", "Label") + f.label.View() + "\n")

	var roles []string
	for i, r := range keyring.Roles {
		if i == f.roleIdx {
			roles = append(roles, selStyle.Render("["+string(r)+"]"))
		} else {
			roles = append(roles, dimStyle.Render(" "+string(r)+" "))
		}
	}
	b.WriteString(cursor(fieldRole) + fmt.Sprintf("%-10s ", "Role") + strings.Join(roles, " ") + "\n")

	prot := okStyle.Render("[x] yes") + dimStyle.Render(" — type the label to confirm any write to this key")
	if !f.protected {
		prot = warnStyle.Render("[ ] no") + dimStyle.Render(" — writes to this key need only a y/N confirmation")
	}
	b.WriteString(cursor(fieldProtected) + fmt.Sprintf("%-10s ", "Protected") + prot + "\n")

	if f.err != "" {
		b.WriteString("\n" + errStyle.Render(f.err) + "\n")
	}
	return b.String()
}
