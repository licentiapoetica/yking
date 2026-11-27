package tui

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// The runner executes ssh / ssh-keygen INSIDE the TUI. The child gets no
// terminal (own session) and yking as its askpass, so every prompt shows
// up here as a panel: which YubiKey to touch, its PIN (asked once, never
// echoed), a server password, a new host key. The terminal is never handed
// over, so nothing reads it behind the TUI's back.

// runJob describes one child process.
type runJob struct {
	title string
	lines []string // what is happening, in plain words
	cmd   *exec.Cmd
	// need must be plugged in before cmd starts (nil: no YubiKey needed).
	need    *keyring.Key
	needWhy string
	// key is the YubiKey for prompts that do not name one (ssh-keygen's
	// "Enter PIN for authenticator").
	key  *keyring.Key
	done func(runResult) tea.Msg // the message the calling screen expects
	back mode
	// noCancel: never kill it (yking's root apply): esc/Ctrl+C only refuse
	// a pending question; the process always finishes on its own.
	noCancel bool
	// hold: after it ends, keep the screen with its output until Enter.
	hold     bool
	outLines int // output lines shown (default 3)
}

// sockArg in a job's command line is replaced by the askpass socket path.
const sockArg = "{yking-askpass-socket}"

type runResult struct {
	err      error
	stdout   []byte
	pinAsked bool
	skipped  bool // need was not plugged in; nothing ran
}

// errNotPlugged means the user gave up waiting for a YubiKey; nothing ran.
var errNotPlugged = errors.New("needed YubiKey was not plugged in")

// errCancelled means the user stopped the run.
var errCancelled = errors.New("cancelled")

type runPhase int

const (
	phaseIdle    runPhase = iota
	phaseWaiting          // for need to be plugged in
	phaseRunning
	phaseDone // hold: result shown, Enter continues
)

type promptKind int

const (
	promptPIN promptKind = iota
	promptSecret
	promptYesNo
	promptChoice // yking's own question with fixed options
)

type runner struct {
	job   runJob
	phase runPhase
	ch    chan tea.Msg
	brk   *askpass.Broker
	proc  *os.Process

	waitNote string // shown while waiting for a YubiKey

	prompt     *askpass.Request
	kind       promptKind
	promptKey  *keyring.Key
	promptFile string
	input      textinput.Model

	touch     *askpass.Request // active "touch your key" notice (nil for ssh-keygen's stderr hint)
	touching  bool
	touchKey  *keyring.Key
	touchFile string

	pinAsked bool
	minPIN   int   // OpenPGP prompt: its minimum length (0: FIDO2 rules)
	stopErr  error // why yking stopped the child (wins over its exit status)
	lines    []string
	stages   []string // headings announced by the child (KindPhase)
	note     string   // e.g. "an apply cannot be interrupted"
	result   runResult
}

type (
	runPlugMsg struct {
		present bool
		err     error
	}
	runReqMsg  struct{ r *askpass.Request }
	runGoneMsg struct{ r *askpass.Request }
	runLineMsg struct{ line string }
	runExitMsg struct {
		err    error
		stdout []byte
	}
)

// startRun switches to the run screen and starts j (after the plug-in
// check, if any).
func (m model) startRun(j runJob) (tea.Model, tea.Cmd) {
	m.run = runner{job: j, ch: make(chan tea.Msg, 64)}
	m.mode = modeRun
	if j.need != nil {
		m.run.phase = phaseWaiting
		return m, m.checkPlugged(0)
	}
	return m.launch()
}

func (m model) checkPlugged(after time.Duration) tea.Cmd {
	serial := m.run.job.need.Serial
	check := func() tea.Msg {
		ok, err := m.serialPresent(serial)
		return runPlugMsg{present: ok, err: err}
	}
	if after == 0 {
		return check
	}
	return tea.Tick(after, func(time.Time) tea.Msg { return check() })
}

// launch starts the child. Like any tea.Cmd, nothing runs until the
// program executes the returned command.
func (m model) launch() (tea.Model, tea.Cmd) {
	m.run.phase = phaseRunning
	cmd, ch := m.run.job.cmd, m.run.ch
	if cmd == nil {
		return m.finish(runResult{err: errors.New("nothing to run")})
	}
	return m, func() tea.Msg { return start(cmd, ch) }
}

type runStartedMsg struct {
	proc *os.Process
	brk  *askpass.Broker
	err  error
}

func start(cmd *exec.Cmd, ch chan tea.Msg) tea.Msg {
	self, err := os.Executable()
	if err != nil {
		return runStartedMsg{err: err}
	}
	brk, err := askpass.NewBroker()
	if err != nil {
		return runStartedMsg{err: err}
	}
	cmd.Env = append(cleanEnv(cmd.Env), brk.Env(self)...)
	for i, a := range cmd.Args {
		if a == sockArg {
			cmd.Args[i] = brk.Sock()
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // no terminal: it cannot prompt behind the TUI
	stdout, err1 := cmd.StdoutPipe()
	stderr, err2 := cmd.StderrPipe()
	if err := errors.Join(err1, err2); err != nil {
		brk.Close()
		return runStartedMsg{err: err}
	}
	if err := cmd.Start(); err != nil {
		brk.Close()
		return runStartedMsg{err: err}
	}
	go func() { // prompts
		for {
			select {
			case q := <-brk.Requests():
				ch <- runReqMsg{q}
				go func() { <-q.Gone; ch <- runGoneMsg{q} }()
			case <-brk.Done():
				return
			}
		}
	}()
	go func() { // output, then exit
		var out bytes.Buffer
		copied := make(chan struct{})
		go func() { io.Copy(&out, stdout); close(copied) }()
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" {
				ch <- runLineMsg{l}
			}
		}
		<-copied
		err := cmd.Wait()
		brk.Close()
		ch <- runExitMsg{err: err, stdout: out.Bytes()}
	}()
	return runStartedMsg{proc: cmd.Process, brk: brk}
}

func waitRun(ch <-chan tea.Msg) tea.Cmd { return func() tea.Msg { return <-ch } }

// cleanEnv starts from env (or the process environment) without anything
// that would redirect prompts elsewhere.
func cleanEnv(env []string) []string {
	if env == nil {
		env = os.Environ()
	}
	return slices.DeleteFunc(slices.Clone(env), func(e string) bool {
		for _, p := range []string{"SSH_ASKPASS=", "SSH_ASKPASS_REQUIRE=", askpass.EnvSock + "="} {
			if strings.HasPrefix(e, p) {
				return true
			}
		}
		return false
	})
}

// stop kills the child (its whole session) and remembers why.
func (r *runner) stop(why error) {
	if r.stopErr == nil {
		r.stopErr = why
	}
	if r.prompt != nil {
		r.prompt.Refuse()
		r.prompt = nil
	}
	if r.proc != nil && !r.job.noCancel {
		syscall.Kill(-r.proc.Pid, syscall.SIGKILL)
	}
}

func (m model) finish(res runResult) (tea.Model, tea.Cmd) {
	res.pinAsked = res.pinAsked || m.run.pinAsked
	done := m.run.job.done(res)
	m.mode = m.run.job.back
	m.run = runner{}
	return m, func() tea.Msg { return done }
}

func (m model) updateRun(msg tea.Msg) (tea.Model, tea.Cmd) {
	r := &m.run
	switch msg := msg.(type) {
	case runStartedMsg:
		if msg.err != nil {
			return m.finish(runResult{err: msg.err})
		}
		r.proc, r.brk = msg.proc, msg.brk
		if r.stopErr != nil { // cancelled while starting
			r.stop(r.stopErr)
		}
		return m, waitRun(r.ch)
	case runPlugMsg:
		if r.phase != phaseWaiting {
			return m, nil
		}
		switch {
		case msg.err != nil:
			r.waitNote = "could not check (" + msg.err.Error() + "); trying anyway"
			return m.launch()
		case msg.present:
			return m.launch()
		}
		return m, m.checkPlugged(700 * time.Millisecond)
	case runReqMsg:
		return m.onRequest(msg.r)
	case runGoneMsg:
		if msg.r == r.touch {
			r.touch, r.touching = nil, false
		}
		if msg.r == r.prompt { // ssh gave up on the question
			r.prompt = nil
		}
		return m, waitRun(r.ch)
	case runLineMsg:
		r.lines = append(r.lines, msg.line)
		if len(r.lines) > 50 {
			r.lines = r.lines[len(r.lines)-50:]
		}
		// ssh-keygen prints its touch request instead of using askpass.
		if low := strings.ToLower(msg.line); strings.Contains(low, "touch your authenticator") || strings.Contains(low, "touch the device") ||
			strings.Contains(low, "confirm presence") || strings.Contains(low, "when it blinks") {
			r.touching, r.touchKey, r.touchFile = true, r.job.key, ""
		} else if r.touch == nil {
			r.touching = false
		}
		return m, waitRun(r.ch)
	case runExitMsg:
		res := runResult{stdout: msg.stdout, err: msg.err}
		t := tail(r.lines, 3)
		switch {
		case r.stopErr != nil && msg.err != nil && r.job.noCancel && t != "":
			res.err = fmt.Errorf("%w (%s)", r.stopErr, t)
		case r.stopErr != nil:
			res.err = r.stopErr
		case msg.err != nil && t != "":
			res.err = fmt.Errorf("%w: %s", msg.err, t)
		}
		if r.job.hold {
			r.phase, r.result, r.prompt, r.touching = phaseDone, res, nil, false
			return m, nil
		}
		return m.finish(res)
	case tea.KeyMsg:
		return m.runKey(msg)
	}
	return m, nil
}

func tail(lines []string, n int) string {
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " / ")
}

var (
	fpRe = regexp.MustCompile(`SHA256:[A-Za-z0-9+/]+`)
)

func (m model) onRequest(q *askpass.Request) (tea.Model, tea.Cmd) {
	r := &m.run
	next := waitRun(r.ch)
	switch q.Kind {
	case askpass.KindNotify:
		r.touch, r.touching = q, true
		r.touchKey, r.touchFile = m.keyForPrompt(q.Prompt)
		return m, next
	case askpass.KindConfirm:
		r.prompt, r.kind = q, promptYesNo
		return m, next
	case askpass.KindPhase:
		// A new stage (e.g. the sudo test after a PAM change): its own PIN.
		r.stages = append(r.stages, q.Prompt)
		r.pinAsked = false
		q.Answer("")
		return m, next
	case askpass.KindChoice:
		if r.prompt != nil || len(q.Options) == 0 {
			q.Refuse()
			return m, next
		}
		r.prompt, r.kind = q, promptChoice
		return m, next
	}
	if r.prompt != nil { // one question at a time
		q.Refuse()
		return m, next
	}
	key, file := m.keyForPrompt(q.Prompt)
	low := strings.ToLower(q.Prompt)
	switch {
	case strings.Contains(low, "pin"):
		if key == nil {
			key = r.job.key
		}
		if r.pinAsked {
			// Asked again = the PIN was wrong. Stop before another attempt.
			q.Refuse()
			r.stop(errors.New("the PIN was not accepted. Stopped so no further attempts are used — check the tries left on the key list"))
			return m, next
		}
		// OpenPGP PINs: yking pgp checks the tries itself.
		r.minPIN = 0
		if strings.Contains(low, "openpgp") {
			r.minPIN = 6
			if strings.Contains(low, "admin") {
				r.minPIN = 8
			}
		} else if key != nil {
			if f := m.fidoOf(key.Serial); f != nil {
				if ok, why := f.PINPromptAllowed(); !ok {
					q.Refuse()
					r.stop(errors.New("not asking for the PIN of " + key.Label + ": " + why))
					return m, next
				}
			}
		}
		r.pinAsked = true
		r.kind = promptPIN
	case strings.Contains(low, "(yes/no"):
		r.kind = promptYesNo
	default:
		r.kind = promptSecret
	}
	r.prompt, r.promptKey, r.promptFile = q, key, file
	r.input = textinput.New()
	r.input.EchoMode = textinput.EchoPassword
	r.input.EchoCharacter = '•'
	r.input.CharLimit = 256
	r.input.Width = 30
	r.input.Focus()
	return m, tea.Batch(next, textinput.Blink)
}

// keyForPrompt finds the YubiKey a prompt is about: by SSH fingerprint
// ("Confirm user presence for key … SHA256:…") or key file path ("Enter
// PIN for ED25519-SK key /home/…/yk-main-01").
func (m model) keyForPrompt(prompt string) (*keyring.Key, string) {
	if m.kr == nil {
		return nil, ""
	}
	fp := fpRe.FindString(prompt)
	for i := range m.kr.Keys {
		k := &m.kr.Keys[i]
		for _, s := range k.SSH {
			if (fp != "" && s.Fingerprint == fp) || (s.Path != "" && strings.Contains(prompt, s.Path)) {
				return k, filepath.Base(s.Path)
			}
		}
	}
	return nil, ""
}

func (m model) fidoOf(serial string) *ykman.FIDOInfo {
	if m.rep != nil {
		for _, k := range m.rep.Keys {
			if k.Serial == serial {
				return k.FIDO
			}
		}
	}
	return nil
}

func (m model) runKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	r := &m.run
	if r.phase == phaseDone {
		if key.String() == "enter" || key.String() == "esc" {
			return m.finish(r.result)
		}
		return m, nil
	}
	if r.phase == phaseWaiting {
		switch key.String() {
		case "s", "esc":
			r.phase = phaseRunning // stale plug checks are ignored from now on
			return m.finish(runResult{err: errNotPlugged, skipped: true})
		}
		return m, nil
	}
	if r.prompt == nil {
		if key.String() == "esc" {
			if r.job.noCancel {
				r.note = "This cannot be interrupted; it finishes by itself."
				return m, nil
			}
			r.stop(errCancelled)
		}
		return m, nil
	}
	if r.kind == promptChoice {
		k := key.String()
		for _, o := range r.prompt.Options {
			if o.Key == k {
				r.prompt.Answer(k)
				r.prompt = nil
				return m, nil
			}
		}
		return m, nil // anything else is ignored, never shown
	}
	if r.kind == promptYesNo {
		switch key.String() {
		case "y":
			r.answer("yes")
		case "n", "esc":
			r.answer("no")
		}
		return m, nil
	}
	switch key.String() {
	case "esc":
		r.stop(errCancelled)
		return m, nil
	case "enter":
		v := r.input.Value()
		r.input.SetValue("") // never kept around
		if r.kind == promptPIN {
			minLen := 4
			if r.minPIN > 0 {
				minLen = r.minPIN
			} else if r.promptKey != nil {
				if f := m.fidoOf(r.promptKey.Serial); f != nil {
					minLen = max(minLen, f.MinPINLength)
				}
			}
			if len([]rune(v)) < minLen {
				r.stop(fmt.Errorf("PIN shorter than %d characters; not sent (no attempt used)", minLen))
				return m, nil
			}
		}
		r.answer(v)
		return m, nil
	}
	var cmd tea.Cmd
	r.input, cmd = r.input.Update(key)
	return m, cmd
}

func (r *runner) answer(v string) {
	if r.kind == promptYesNo && r.prompt.Kind == askpass.KindConfirm {
		if v == "yes" {
			r.prompt.Answer("")
		} else {
			r.prompt.Refuse()
		}
	} else {
		r.prompt.Answer(v)
	}
	r.prompt = nil
}

// onlyKey is the registered YubiKey when exactly one is plugged in: the one
// a "PIN for authenticator" or sudo prompt is about.
func (m model) onlyKey() *keyring.Key {
	if m.rep == nil || len(m.rep.Keys) != 1 {
		return nil
	}
	return m.rep.Keys[0].Known
}
