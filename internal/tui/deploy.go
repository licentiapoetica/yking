package tui

import (
	"bytes"
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
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// Deploying is only ever started here, by the user, for one host.

const (
	depFieldKey = iota
	depFieldTarget
	depFieldLogin
	depFieldTest
	depNumFields
)

type deployForm struct {
	key    detect.KeyReport
	idx    int // which of key.Known.SSH
	target textinput.Model
	logins []string // candidate identity files for the deploy connection
	login  int      // 0 = ssh default
	test   bool
	focus  int
	err    string
	notes  []string // results so far, shown on failure
}

type deployDoneMsg struct {
	target string
	ssh    keyring.SSHKey
	out    []byte
	err    error
	test   bool
}

type testDoneMsg struct {
	target       string
	ssh          keyring.SSHKey
	result       sshkey.DeployResult
	err          error
	pinRequested bool
}

func newDeployForm(k detect.KeyReport) deployForm {
	ti := textinput.New()
	ti.CharLimit = 120
	ti.Width = 40
	ti.Placeholder = "user@host or ssh alias"
	ti.Focus()
	f := deployForm{key: k, target: ti, test: true, focus: depFieldTarget}
	f.logins = append([]string{""}, sshkey.IdentityFiles(sshDir())...)
	return f
}

func (f deployForm) selected() keyring.SSHKey { return f.key.Known.SSH[f.idx] }

func (f *deployForm) setFocus(i int) {
	f.focus = (i + depNumFields) % depNumFields
	if f.focus == depFieldTarget {
		f.target.Focus()
	} else {
		f.target.Blur()
	}
}

func (m model) updateDeploy(msg tea.Msg) (tea.Model, tea.Cmd) {
	f := &m.deploy
	switch msg := msg.(type) {
	case deployDoneMsg:
		return m.afterDeploy(msg)
	case testDoneMsg:
		return m.afterTest(msg)
	case tea.KeyMsg:
		switch msg.String() {
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
			return m.startDeploy()
		}
		switch f.focus {
		case depFieldKey:
			n := len(f.key.Known.SSH)
			switch msg.String() {
			case "right", "l", " ":
				f.idx = (f.idx + 1) % n
			case "left", "h":
				f.idx = (f.idx + n - 1) % n
			}
			return m, nil
		case depFieldLogin:
			n := len(f.logins)
			switch msg.String() {
			case "right", "l", " ":
				f.login = (f.login + 1) % n
			case "left", "h":
				f.login = (f.login + n - 1) % n
			}
			return m, nil
		case depFieldTest:
			switch msg.String() {
			case " ", "left", "right", "h", "l":
				f.test = !f.test
			}
			return m, nil
		}
	}
	var cmd tea.Cmd
	if f.focus == depFieldTarget {
		f.target, cmd = f.target.Update(msg)
		f.err = ""
	}
	return m, cmd
}

func (m model) startDeploy() (tea.Model, tea.Cmd) {
	f := &m.deploy
	f.err, f.notes = "", nil
	target := strings.TrimSpace(f.target.Value())
	if err := sshkey.ValidTarget(target); err != nil {
		f.err = err.Error()
		f.setFocus(depFieldTarget)
		return m, nil
	}
	s := f.selected()
	pub, err := os.ReadFile(s.Path + ".pub")
	if err != nil {
		f.err = "cannot read public key: " + err.Error()
		return m, nil
	}
	if pk, err := sshkey.ParsePub(string(pub)); err != nil || pk.Fingerprint != s.Fingerprint {
		f.err = fmt.Sprintf("%s.pub does not match the fingerprint in the keyring; refusing to deploy", s.Path)
		return m, nil
	}
	line, err := sshkey.AuthorizedLine(string(pub), s)
	if err != nil {
		f.err = err.Error()
		return m, nil
	}
	cmd, err := sshkey.DeployCommand(target, line, f.logins[f.login])
	if err != nil {
		f.err = err.Error()
		return m, nil
	}
	var out bytes.Buffer
	run := &introExec{
		cmd:     cmd,
		capture: &out,
		intro: fmt.Sprintf("\nyking: adding %s to %s's authorized_keys.\nyking: log in the way you normally do (password or existing key).\n\n",
			filepath.Base(s.Path), target),
	}
	test := f.test
	return m, tea.Exec(run, func(err error) tea.Msg {
		return deployDoneMsg{target: target, ssh: s, out: out.Bytes(), err: withTail(err, run), test: test}
	})
}

func (m model) afterDeploy(msg deployDoneMsg) (tea.Model, tea.Cmd) {
	f := &m.deploy
	res := sshkey.ParseDeployOutput(msg.out)
	if msg.err != nil || res == sshkey.DeployUnknown {
		f.err = fmt.Sprintf("deploy to %s failed", msg.target)
		if msg.err != nil {
			f.err += ": " + msg.err.Error()
		}
		f.err += ". Nothing was recorded."
		return m, nil
	}
	f.notes = append(f.notes, fmt.Sprintf("%s: key %s", msg.target, res))
	if !msg.test {
		return m.recordHost(msg.target, msg.ssh, res, "not tested")
	}

	// Test login with only this key. Needs the YubiKey plugged in.
	info := askpass.Info{Label: f.key.Known.Label, Serial: f.key.Serial, Retries: -1}
	if fi := f.key.FIDO; fi != nil {
		info.Retries, info.MinPINLength = fi.PINRetries, fi.MinPINLength
		if msg.ssh.VerifyRequired {
			if ok, why := fi.PINPromptAllowed(); !ok {
				return m.recordHost(msg.target, msg.ssh, res, "test skipped: "+why)
			}
		}
	}
	self, err := os.Executable()
	if err != nil {
		return m.recordHost(msg.target, msg.ssh, res, "test skipped: "+err.Error())
	}
	sess, err := askpass.Prepare(self, info)
	if err != nil {
		return m.recordHost(msg.target, msg.ssh, res, "test skipped: "+err.Error())
	}
	cmd, err := sshkey.TestLoginCommand(msg.target, msg.ssh.Path, sess.Env)
	if err != nil {
		sess.Close()
		return m.recordHost(msg.target, msg.ssh, res, "test skipped: "+err.Error())
	}
	how := "touch the key when it blinks"
	switch {
	case msg.ssh.NoTouchRequired:
		how = "enter the PIN when asked (no touch)"
	case msg.ssh.VerifyRequired:
		how = "enter the PIN, then touch the key"
	}
	run := &introExec{cmd: cmd, intro: fmt.Sprintf("\nyking: test login to %s using only %s — %s.\n\n", msg.target, filepath.Base(msg.ssh.Path), how)}
	return m, tea.Exec(run, func(err error) tea.Msg {
		asked := sess.PINWasRequested()
		sess.Close()
		return testDoneMsg{target: msg.target, ssh: msg.ssh, result: res, err: withTail(err, run), pinRequested: asked}
	})
}

func (m model) afterTest(msg testDoneMsg) (tea.Model, tea.Cmd) {
	note := "test login OK"
	if msg.err != nil {
		note = "test login FAILED (" + msg.err.Error() + ")"
		if msg.ssh.NoTouchRequired && msg.result == sshkey.DeployDifferent {
			note += "; the server's line lacks no-touch-required"
		}
		if msg.pinRequested {
			note += "; if the PIN was wrong, one attempt was used"
		}
	}
	return m.recordHost(msg.target, msg.ssh, msg.result, note)
}

// recordHost records the deployment in the keyring (review → apply). The
// key is on the server either way, so it is recorded even if the test
// failed: revoke must know about it.
func (m model) recordHost(target string, s keyring.SSHKey, res sshkey.DeployResult, testNote string) (tea.Model, tea.Cmd) {
	summary := fmt.Sprintf("%s → %s: %s, %s. Use: ssh -i %s %s", filepath.Base(s.Path), target, res, testNote, tildePath(s.Path), target)
	style := okStyle
	if strings.Contains(testNote, "FAILED") || res == sshkey.DeployDifferent {
		style = warnStyle
	}
	p, err := sshkey.RecordHostPlan(m.cfg.KeyringPath, s.Fingerprint, target, time.Now())
	if errors.Is(err, plan.ErrNoChanges) {
		m.status = style.Render(summary + " (already recorded)")
		m.mode = modeKeys
		return m, nil
	}
	if err == nil {
		m.review, err = newReview(p)
	}
	if err != nil {
		m.deploy.err = "deployed, but recording failed: " + err.Error()
		return m, nil
	}
	m.status = style.Render(summary + ". Apply below to record the host.")
	m.reviewBack = modeKeys
	m.mode = modeReview
	return m, nil
}

func tildePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rest, ok := strings.CutPrefix(p, home+"/"); ok {
			return "~/" + rest
		}
	}
	return p
}

func (f deployForm) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf("Deploy SSH key from %q (%s)", f.key.Known.Label, f.key.Serial)) + "\n")
	b.WriteString(dimStyle.Render("Adds the public key to ONE server's ~/.ssh/authorized_keys. Existing lines are\nnever changed or removed. ~/.ssh/config is not touched.") + "\n\n")
	cur := func(i int) string {
		if f.focus == i {
			return selStyle.Render("▸ ")
		}
		return "  "
	}
	var keys []string
	for i, s := range f.key.Known.SSH {
		name := filepath.Base(s.Path)
		if i == f.idx {
			keys = append(keys, selStyle.Render("["+name+"]"))
		} else {
			keys = append(keys, dimStyle.Render(" "+name+" "))
		}
	}
	b.WriteString(cur(depFieldKey) + fmt.Sprintf("%-10s ", "SSH key") + strings.Join(keys, " ") + "\n")
	b.WriteString(cur(depFieldTarget) + fmt.Sprintf("%-10s ", "Server") + f.target.View() + "\n")
	login := dimStyle.Render("(ssh default: your config, agent and default keys)")
	if id := f.logins[f.login]; id != "" {
		login = selStyle.Render(filepath.Base(id)) + dimStyle.Render(" — only this key is offered (-i, IdentitiesOnly=yes); password still possible")
	}
	if len(f.logins) > 1 {
		login = "◂ " + login + " ▸"
	}
	b.WriteString(cur(depFieldLogin) + fmt.Sprintf("%-10s ", "Login with") + login + "\n")
	t := dimStyle.Render("[ ] no")
	if f.test {
		t = okStyle.Render("[x] yes") + dimStyle.Render(" — log in once with only this key (needs the YubiKey)")
	}
	b.WriteString(cur(depFieldTest) + fmt.Sprintf("%-10s ", "Test") + t + "\n")
	if s := f.selected(); len(s.Hosts) > 0 {
		b.WriteString("\n" + dimStyle.Render("Already deployed to: "+strings.Join(s.Hosts, ", ")) + "\n")
	}
	if f.selected().NoTouchRequired {
		b.WriteString(dimStyle.Render("PIN-only key: the line is prefixed with no-touch-required.") + "\n")
	}
	for _, n := range f.notes {
		b.WriteString("\n" + n)
	}
	if f.err != "" {
		b.WriteString("\n" + errStyle.Render(f.err) + "\n")
	}
	return b.String()
}
