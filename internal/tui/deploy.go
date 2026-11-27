package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// Deploying is only ever started here, by the user, for one host.

const (
	depFieldKey = iota
	depFieldTarget
	depFieldUser
	depFieldLogin
	depFieldTest
	depFieldConfig
	depNumFields
)

type deployForm struct {
	key       detect.KeyReport
	idx       int             // which of key.Known.SSH
	target    textinput.Model // host or ssh alias (user@host still accepted)
	user      textinput.Model // login name on the server ("" = what ssh would use)
	defUser   string          // what ssh would use for defFor
	defFor    string
	logins    []string // identity files in ~/.ssh ("" = ssh default first)
	loginPath string   // chosen login key file, "" = ssh default
	keys      []keyring.Key
	connected map[string]bool // serials plugged in when the form opened
	test      bool
	config    bool // also review a Host block for ~/.ssh/config (opt-in)
	focus     int
	err       string
	notes     []string // results so far, shown on failure
}

type deployDoneMsg struct {
	target string
	ssh    keyring.SSHKey
	out    []byte
	err    error
	test   bool
	config bool
}

type testDoneMsg struct {
	target       string
	ssh          keyring.SSHKey
	result       sshkey.DeployResult
	err          error
	pinRequested bool
	config       bool
	skipped      bool // the YubiKey for the test was not plugged in
}

func newDeployForm(k detect.KeyReport, keys []keyring.Key, connected map[string]bool) deployForm {
	ti := textinput.New()
	ti.CharLimit = 120
	ti.Width = 40
	ti.Placeholder = "host or ssh alias"
	ti.Focus()
	ui := textinput.New()
	ui.CharLimit = 32
	ui.Width = 20
	f := deployForm{key: k, target: ti, user: ui, test: true, focus: depFieldTarget, keys: keys, connected: connected}
	f.logins = append([]string{""}, sshkey.IdentityFiles(sshDir())...)
	return f
}

func (f deployForm) selected() keyring.SSHKey { return f.key.Known.SSH[f.idx] }

// loginChoices are the files offered for logging in, without the key being
// deployed (it is not on the server yet, so it cannot log in).
func (f deployForm) loginChoices() []string {
	self := f.selected().Path
	return slices.DeleteFunc(slices.Clone(f.logins), func(p string) bool { return p != "" && p == self })
}

func (f *deployForm) cycleLogin(d int) {
	c := f.loginChoices()
	i := max(slices.Index(c, f.loginPath), 0)
	f.loginPath = c[(i+d+len(c))%len(c)]
}

func (f deployForm) login() loginKey { return describeLogin(f.keys, f.loginPath) }

func (f *deployForm) setFocus(i int) {
	f.focus = (i + depNumFields) % depNumFields
	f.target.Blur()
	f.user.Blur()
	switch f.focus {
	case depFieldTarget:
		f.target.Focus()
	case depFieldUser:
		f.user.Focus()
	}
}

func (m model) updateDeploy(msg tea.Msg) (tea.Model, tea.Cmd) {
	f := &m.deploy
	switch msg := msg.(type) {
	case deployUserMsg:
		f.defFor, f.defUser = msg.host, msg.user
		return m, nil
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
			if f.loginPath == f.selected().Path {
				f.loginPath = ""
			}
			return m, nil
		case depFieldLogin:
			switch msg.String() {
			case "right", "l", " ":
				f.cycleLogin(1)
			case "left", "h":
				f.cycleLogin(-1)
			}
			return m, nil
		case depFieldTest:
			switch msg.String() {
			case " ", "left", "right", "h", "l":
				f.test = !f.test
			}
			return m, nil
		case depFieldConfig:
			switch msg.String() {
			case " ", "left", "right", "h", "l":
				f.config = !f.config
			}
			return m, nil
		}
	}
	var cmd tea.Cmd
	switch f.focus {
	case depFieldTarget:
		before := f.target.Value()
		f.target, cmd = f.target.Update(msg)
		f.err = ""
		if f.target.Value() != before {
			return m, tea.Batch(cmd, resolveUser(strings.TrimSpace(f.target.Value())))
		}
	case depFieldUser:
		f.user, cmd = f.user.Update(msg)
		f.err = ""
	}
	return m, cmd
}

// deployUserMsg is what ssh would log in as for host (from the ssh config).
type deployUserMsg struct{ host, user string }

// resolveUser looks the default login up in the background (ssh -G, no
// connection).
func resolveUser(host string) tea.Cmd {
	if host == "" || strings.Contains(host, "@") || sshkey.ValidTarget(host) != nil {
		return nil
	}
	return func() tea.Msg { return deployUserMsg{host: host, user: sshkey.LoginUser(host)} }
}

// loginName is the login name for the deploy: the User field, else what
// ssh would use for the host.
func (f deployForm) loginName() string {
	if u := strings.TrimSpace(f.user.Value()); u != "" {
		return u
	}
	if f.defFor == strings.TrimSpace(f.target.Value()) {
		return f.defUser
	}
	return ""
}

// fullTarget is user@host for ssh and the keyring. The user is always
// explicit when known, so the record says which account has the key.
func (f deployForm) fullTarget() (string, error) {
	host := strings.TrimSpace(f.target.Value())
	user := strings.TrimSpace(f.user.Value())
	if strings.Contains(host, "@") {
		if user != "" {
			return "", fmt.Errorf("user given twice: in the Server field (%s) and the User field (%s)", host, user)
		}
		return host, sshkey.ValidTarget(host)
	}
	t := host
	if u := f.loginName(); u != "" {
		t = u + "@" + host
	}
	return t, sshkey.ValidTarget(t)
}

func (m model) startDeploy() (tea.Model, tea.Cmd) {
	f := &m.deploy
	f.err, f.notes = "", nil
	if strings.TrimSpace(f.target.Value()) == "" {
		f.err = "enter the server (host name or ssh alias)"
		f.setFocus(depFieldTarget)
		return m, nil
	}
	target, err := f.fullTarget()
	if err != nil {
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
	cmd, err := sshkey.DeployCommand(target, line, f.loginPath)
	if err != nil {
		f.err = err.Error()
		return m, nil
	}
	owner := f.login().owner
	how := "login: ssh default"
	switch {
	case owner != nil:
		how = fmt.Sprintf("login: %s (%s)", filepath.Base(f.loginPath), owner.Label)
	case f.loginPath != "":
		how = "login: " + filepath.Base(f.loginPath)
	}
	test, config := f.test, f.config
	return m.startRun(runJob{
		title:   fmt.Sprintf("Deploy %s → %s", filepath.Base(s.Path), target),
		lines:   []string{how},
		cmd:     cmd,
		need:    owner,
		needWhy: "for the login with " + filepath.Base(f.loginPath),
		key:     owner,
		back:    modeDeploy,
		done: func(r runResult) tea.Msg {
			return deployDoneMsg{target: target, ssh: s, out: r.stdout, err: r.err, test: test, config: config}
		},
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
		return m.recordHost(msg.target, msg.ssh, res, msg.config, "not tested")
	}

	// Test login with only this key. Needs its YubiKey plugged in.
	if fi := f.key.FIDO; fi != nil && msg.ssh.VerifyRequired {
		if ok, why := fi.PINPromptAllowed(); !ok {
			return m.recordHost(msg.target, msg.ssh, res, msg.config, "test skipped: "+why)
		}
	}
	cmd, err := sshkey.TestLoginCommand(msg.target, msg.ssh.Path, nil)
	if err != nil {
		return m.recordHost(msg.target, msg.ssh, res, msg.config, "test skipped: "+err.Error())
	}
	return m.startRun(runJob{
		title:   fmt.Sprintf("Test login %s → %s", filepath.Base(msg.ssh.Path), msg.target),
		lines:   nil,
		cmd:     cmd,
		need:    f.key.Known,
		needWhy: "for the test login",
		key:     f.key.Known,
		back:    modeDeploy,
		done: func(r runResult) tea.Msg {
			return testDoneMsg{target: msg.target, ssh: msg.ssh, result: res, err: r.err, pinRequested: r.pinAsked, config: msg.config, skipped: r.skipped}
		},
	})
}

func (m model) afterTest(msg testDoneMsg) (tea.Model, tea.Cmd) {
	if msg.skipped {
		return m.recordHost(msg.target, msg.ssh, msg.result, msg.config, "test skipped ("+m.deploy.key.Known.Label+" was not plugged in)")
	}
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
	return m.recordHost(msg.target, msg.ssh, msg.result, msg.config && msg.err == nil, note)
}

// recordHost records the deployment in the keyring (review → apply). The
// key is on the server either way, so it is recorded even if the test
// failed: revoke must know about it. With config set (the user ticked it,
// and the test did not fail) the same review also carries the Host block
// for ~/.ssh/config.
func (m model) recordHost(target string, s keyring.SSHKey, res sshkey.DeployResult, config bool, testNote string) (tea.Model, tea.Cmd) {
	use := fmt.Sprintf("ssh -i %s %s", tildePath(s.Path), target)
	summary := fmt.Sprintf("%s → %s: %s, %s", filepath.Base(s.Path), target, res, testNote)
	style := okStyle
	if strings.Contains(testNote, "FAILED") || res == sshkey.DeployDifferent {
		style = warnStyle
	}
	if m.deploy.config && !config {
		summary += "; ~/.ssh/config not changed (test login failed)"
	}

	p, err := sshkey.RecordHostPlan(m.cfg.KeyringPath, s.Fingerprint, target, time.Now())
	recorded := errors.Is(err, plan.ErrNoChanges)
	if err != nil && !recorded {
		m.deploy.err = "deployed, but recording failed: " + err.Error()
		return m, nil
	}

	var cp *plan.Plan
	var notes []string
	if config {
		cp, notes, err = m.hostConfigPlan(target, s.Fingerprint)
		switch {
		case errors.Is(err, plan.ErrNoChanges):
			summary += "; ~/.ssh/config already up to date"
			use = "ssh " + target
		case err != nil:
			summary += "; ~/.ssh/config not changed: " + err.Error()
			style = warnStyle
		default:
			use = "ssh " + target + " (after applying)"
		}
	}
	summary += ". Use: " + use

	if recorded && cp == nil {
		m.status = style.Render(summary + " (already recorded)")
		m.mode = modeKeys
		return m, nil
	}
	if recorded {
		p = nil
	}
	m.review, err = newReviewPair(cp, p)
	if err != nil {
		m.deploy.err = "deployed, but building the review failed: " + err.Error()
		return m, nil
	}
	m.review.note = strings.Join(notes, "\n")
	m.status = style.Render(summary + ". Apply below.")
	m.reviewBack = modeKeys
	m.mode = modeReview
	return m, nil
}

// hostConfigPlan builds the ~/.ssh/config change for target's host from
// the keyring as it will be once this deploy is recorded.
func (m model) hostConfigPlan(target, fingerprint string) (*plan.Plan, []string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}
	kr, err := keyring.Load(m.cfg.KeyringPath)
	if err != nil {
		return nil, nil, err
	}
	for i := range kr.Keys {
		for j := range kr.Keys[i].SSH {
			if e := &kr.Keys[i].SSH[j]; e.Fingerprint == fingerprint && !slices.Contains(e.Hosts, target) {
				e.Hosts = append(e.Hosts, target)
			}
		}
	}
	_, host := sshkey.SplitTarget(target)
	e := sshkey.FindHost(sshkey.Hosts(kr, nil), host)
	return sshkey.ConfigPlan(sshkey.ConfigPath(home), home, e, time.Now())
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
	b.WriteString("\n")
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
	b.WriteString(cur(depFieldUser) + fmt.Sprintf("%-10s ", "User") + f.user.View() + f.userHint() + "\n")
	lk := f.login()
	full, _ := f.fullTarget()
	login := lk.hint(f.connected, full)
	if len(f.loginChoices()) > 1 {
		login = "◂ " + login + " ▸"
	}
	b.WriteString(cur(depFieldLogin) + fmt.Sprintf("%-10s ", "Login with") + login + "\n")
	t := dimStyle.Render("[ ] no")
	if f.test {
		t = okStyle.Render("[x] yes")
	}
	b.WriteString(cur(depFieldTest) + fmt.Sprintf("%-10s ", "Test") + t + "\n")
	if f.test && lk.owner != nil && lk.owner.Serial != f.key.Serial {
		b.WriteString(strings.Repeat(" ", 13) + dimStyle.Render(fmt.Sprintf("swap %s → %s for the test", lk.owner.Label, f.key.Known.Label)) + "\n")
	}
	c := dimStyle.Render("[ ] no")
	if f.config {
		c = okStyle.Render("[x] yes")
	}
	b.WriteString(cur(depFieldConfig) + fmt.Sprintf("%-10s ", "SSH config") + c + "\n")
	if s := f.selected(); len(s.Hosts) > 0 {
		b.WriteString("\n" + dimStyle.Render("on: "+strings.Join(s.Hosts, ", ")) + "\n")
	}
	if f.selected().NoTouchRequired {
		b.WriteString(dimStyle.Render("PIN-only: adds no-touch-required") + "\n")
	}
	for _, n := range f.notes {
		b.WriteString("\n" + n)
	}
	if f.err != "" {
		b.WriteString("\n" + errStyle.Render(f.err) + "\n")
	}
	return b.String()
}

// userHint explains the User field: what an empty field means, and the
// full login it adds up to.
func (f deployForm) userHint() string {
	host := strings.TrimSpace(f.target.Value())
	switch {
	case host == "":
		return dimStyle.Render("  empty = ssh default")
	case strings.Contains(host, "@"):
		if strings.TrimSpace(f.user.Value()) != "" {
			return errStyle.Render("  already in Server")
		}
		return ""
	}
	full, err := f.fullTarget()
	switch {
	case err != nil:
		return ""
	case strings.TrimSpace(f.user.Value()) != "":
		return dimStyle.Render("  → ") + selStyle.Render(full)
	case f.defFor == host && f.defUser != "":
		return dimStyle.Render("  → ") + selStyle.Render(full)
	}
	return dimStyle.Render("  empty = ssh default")
}
