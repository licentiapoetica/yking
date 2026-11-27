package tui

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

const (
	sshFieldName = iota
	sshFieldComment
	sshFieldUse
	sshFieldConfirm // only when the key is protected
)

type sshForm struct {
	key      detect.KeyReport
	name     textinput.Model
	comment  textinput.Model
	confirm  textinput.Model
	use      sshkey.Use
	focus    int
	problems []string
	err      string
	busy     string
}

type sshPreflightMsg struct {
	req      sshkey.GenRequest
	state    sshkey.State
	problems []string
	err      error
}

type keygenDoneMsg struct {
	req          sshkey.GenRequest
	err          error
	pinRequested bool
}

func sshDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh")
}

func newSSHForm(k detect.KeyReport) sshForm {
	mk := func(v string, w int) textinput.Model {
		ti := textinput.New()
		ti.CharLimit = 80
		ti.Width = w
		ti.SetValue(v)
		return ti
	}
	name := sshkey.NextName(sshDir())
	f := sshForm{
		key:     k,
		name:    mk(name, 40),
		comment: mk(sshkey.DefaultComment(name), 40),
		confirm: mk("", 20),
	}
	f.name.Focus()
	return f
}

func (f *sshForm) numFields() int {
	if f.key.Known != nil && f.key.Known.Protected {
		return 4
	}
	return 3
}

func (f *sshForm) setFocus(i int) {
	n := f.numFields()
	f.focus = (i + n) % n
	f.name.Blur()
	f.comment.Blur()
	f.confirm.Blur()
	switch f.focus {
	case sshFieldName:
		f.name.Focus()
	case sshFieldComment:
		f.comment.Focus()
	case sshFieldConfirm:
		f.confirm.Focus()
	}
}

func (f sshForm) request() sshkey.GenRequest {
	return sshkey.GenRequest{
		Serial:   f.key.Serial,
		Label:    f.key.Known.Label,
		Firmware: f.key.Info.Firmware,
		Dir:      sshDir(),
		Name:     strings.TrimSpace(f.name.Value()),
		Comment:  strings.TrimSpace(f.comment.Value()),
		Use:      f.use,
	}
}

func (m model) updateSSH(msg tea.Msg) (tea.Model, tea.Cmd) {
	f := &m.ssh
	switch msg := msg.(type) {
	case sshPreflightMsg:
		f.busy = ""
		if msg.err != nil {
			f.err = msg.err.Error()
			return m, nil
		}
		f.problems = msg.problems
		if len(msg.problems) > 0 {
			return m, nil
		}
		return m.runKeygen(msg.req, msg.state)
	case keygenDoneMsg:
		return m.afterKeygen(msg)
	case tea.KeyMsg:
		if f.busy != "" {
			return m, nil
		}
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
			f.err = ""
			if f.numFields() == 4 && f.confirm.Value() != f.key.Known.Label {
				f.err = fmt.Sprintf("This key is protected: type its label %q in the confirm field.", f.key.Known.Label)
				f.setFocus(sshFieldConfirm)
				return m, nil
			}
			f.busy = "Checking connected keys…"
			return m, m.sshPreflight(f.request())
		}
		if f.focus == sshFieldUse {
			n := len(sshkey.Uses)
			switch msg.String() {
			case "right", "l", " ":
				f.use = sshkey.Uses[(int(f.use)+1)%n]
			case "left", "h":
				f.use = sshkey.Uses[(int(f.use)+n-1)%n]
			}
			return m, nil
		}
	}
	var cmd tea.Cmd
	switch f.focus {
	case sshFieldName:
		f.name, cmd = f.name.Update(msg)
	case sshFieldComment:
		f.comment, cmd = f.comment.Update(msg)
	case sshFieldConfirm:
		f.confirm, cmd = f.confirm.Update(msg)
	}
	return m, cmd
}

// sshPreflight re-reads the machine state right before generating.
func (m model) sshPreflight(req sshkey.GenRequest) tea.Cmd {
	return func() tea.Msg {
		kr, err := keyring.Load(m.cfg.KeyringPath)
		if err != nil {
			return sshPreflightMsg{err: err}
		}
		rep, err := detect.Scan(context.Background(), m.cfg.Client, kr)
		if err != nil {
			return sshPreflightMsg{err: err}
		}
		n, err := fido.CountDevices(fido.DefaultSysRoot)
		if err != nil {
			return sshPreflightMsg{err: fmt.Errorf("counting FIDO devices: %w", err)}
		}
		st := sshkey.State{YubiKeys: len(rep.Keys) + len(rep.Unidentified), FIDODevices: n}
		for _, k := range rep.Keys {
			st.Serials = append(st.Serials, k.Serial)
			if k.Serial == req.Serial {
				st.Key = k
			}
		}
		if st.Key.Serial == "" {
			st.Key = detect.KeyReport{Serial: req.Serial}
		}
		return sshPreflightMsg{req: req, state: st, problems: sshkey.Preflight(req, st)}
	}
}

func (m model) runKeygen(req sshkey.GenRequest, st sshkey.State) (tea.Model, tea.Cmd) {
	return m.startRun(runJob{
		title: fmt.Sprintf("Create SSH key ~/.ssh/%s", req.Name),
		lines: []string{fmt.Sprintf("on %s (%s)", req.Label, req.Serial)},
		cmd:   req.Command(nil),
		key:   st.Key.Known,
		back:  modeSSH,
		done: func(r runResult) tea.Msg {
			return keygenDoneMsg{req: req, err: r.err, pinRequested: r.pinAsked}
		},
	})
}

func (m model) afterKeygen(msg keygenDoneMsg) (tea.Model, tea.Cmd) {
	f := &m.ssh
	req := msg.req
	priv, pub := req.Paths()
	if msg.err != nil {
		f.err = "ssh-keygen did not finish: " + msg.err.Error()
		if msg.pinRequested {
			f.err += ". A PIN was entered; if it was wrong, one attempt was used — rescan to see remaining tries."
		}
		m.mode = modeSSH
		return m, nil
	}
	pk, err := sshkey.ReadPub(pub)
	if err != nil || !pk.IsSK() {
		f.err = fmt.Sprintf("ssh-keygen succeeded but %s is unreadable or not a security key: %v", pub, err)
		return m, nil
	}
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	entry := keyring.SSHKey{
		Fingerprint:     pk.Fingerprint,
		Type:            pk.Type,
		VerifyRequired:  req.Use.NeedsPIN(),
		NoTouchRequired: req.Use.NoTouch(),
		User:            uname,
		Path:            priv,
		Comment:         pk.Comment,
		PublicKey:       strings.TrimSpace(string(mustRead(pub))),
		CreatedAt:       time.Now().UTC().Truncate(time.Second),
	}
	p, err := sshkey.RecordPlan(m.cfg.KeyringPath, req.Serial, entry, time.Now())
	if err == nil {
		m.review, err = newReview(p)
	}
	if err != nil {
		f.err = "key created (" + priv + ") but recording it failed: " + err.Error()
		return m, nil
	}
	m.status = okStyle.Render(fmt.Sprintf("Created %s (%s). Apply the plan below to record it in the keyring.", priv, pk.Fingerprint))
	m.reviewBack = modeKeys
	m.mode = modeReview
	return m, nil
}

func (f sshForm) view() string {
	var b strings.Builder
	k := f.key
	b.WriteString(titleStyle.Render(fmt.Sprintf("New SSH key on %q (%s)", k.Known.Label, k.Serial)) + "\n")
	b.WriteString("\n")

	cur := func(i int) string {
		if f.focus == i {
			return selStyle.Render("▸ ")
		}
		return "  "
	}
	req := f.request()
	b.WriteString(cur(sshFieldName) + fmt.Sprintf("%-10s ", "File") + dimStyle.Render("~/.ssh/") + f.name.View() + "\n")
	b.WriteString(cur(sshFieldComment) + fmt.Sprintf("%-10s ", "Comment") + f.comment.View() + "\n")
	var opts []string
	for _, u := range sshkey.Uses {
		if u == f.use {
			opts = append(opts, selStyle.Render("["+u.String()+"]"))
		} else {
			opts = append(opts, dimStyle.Render(" "+u.String()+" "))
		}
	}
	b.WriteString(cur(sshFieldUse) + fmt.Sprintf("%-10s ", "Login") + strings.Join(opts, " ") + "\n")
	for _, l := range strings.Split(f.use.Explain(), "\n") {
		b.WriteString(strings.Repeat(" ", 13) + dimStyle.Render(l) + "\n")
	}
	if f.numFields() == 4 {
		b.WriteString(cur(sshFieldConfirm) + fmt.Sprintf("%-10s ", "Confirm") + f.confirm.View() + dimStyle.Render(fmt.Sprintf("  type %q — this key is protected", f.key.Known.Label)) + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("Will run: ssh-keygen "+strings.Join(quoteArgs(req.Args()), " ")) + "\n")
	b.WriteString(dimStyle.Render("Creating the key always needs one touch.") + "\n")
	if f.use.NeedsPIN() {
	}
	if f.busy != "" {
		b.WriteString("\n" + f.busy + "\n")
	}
	if len(f.problems) > 0 {
		b.WriteString("\n" + errStyle.Render("Cannot create the key yet:") + "\n")
		for _, p := range f.problems {
			b.WriteString(errStyle.Render("  ✗ "+p) + "\n")
		}
	}
	if f.err != "" {
		b.WriteString("\n" + errStyle.Render(f.err) + "\n")
	}
	return b.String()
}

func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return out
}

// introExec prints a line on the released terminal, then runs cmd. If
// capture is set, stdout is also copied there (for result markers). On
// failure it waits for Enter so the user can read the error, and keeps the
// last stderr lines for the TUI.
type introExec struct {
	cmd     *exec.Cmd
	intro   string
	capture *bytes.Buffer
	stderr  bytes.Buffer
	stdout  io.Writer
	tty     io.Reader
	// pauseAlways waits for Enter after success too (output worth reading).
	pauseAlways bool
}

func (e *introExec) SetStdin(r io.Reader) {
	e.tty = r
	if e.cmd.Stdin == nil { // keep a stdin the command brought along
		e.cmd.Stdin = r
	}
}
func (e *introExec) SetStdout(w io.Writer) {
	e.stdout = w
	if e.capture != nil {
		w = io.MultiWriter(w, e.capture)
	}
	e.cmd.Stdout = w
}
func (e *introExec) SetStderr(w io.Writer) { e.cmd.Stderr = io.MultiWriter(w, &e.stderr) }
func (e *introExec) Run() error {
	if e.stdout != nil {
		io.WriteString(e.stdout, e.intro)
	}
	err := e.cmd.Run()
	if err == nil && e.pauseAlways && e.stdout != nil && e.tty != nil {
		fmt.Fprint(e.stdout, "\nPress Enter to return to yking… ")
		bufio.NewReader(e.tty).ReadString('\n')
	}
	if err != nil && e.stdout != nil && e.tty != nil {
		fmt.Fprintf(e.stdout, "\nyking: the command did not succeed (%v) — see the message above.\nPress Enter to return to yking… ", err)
		bufio.NewReader(e.tty).ReadString('\n')
	}
	return err
}

// errTail returns the last n non-empty stderr lines, joined.
func (e *introExec) errTail(n int) string {
	var lines []string
	for _, l := range strings.Split(e.stderr.String(), "\n") {
		if l = strings.TrimSpace(strings.TrimRight(l, "\r")); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " / ")
}

// withTail appends stderr context to an exec error.
func withTail(err error, e *introExec) error {
	if err == nil {
		return nil
	}
	if t := e.errTail(3); t != "" {
		return fmt.Errorf("%w: %s", err, t)
	}
	return err
}

func mustRead(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}
