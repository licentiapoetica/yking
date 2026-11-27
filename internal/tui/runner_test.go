package tui

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// The runner sets SSH_ASKPASS to os.Executable(), which in tests is this
// test binary: act as the askpass helper like the real yking does.
func TestMain(m *testing.M) {
	if os.Getenv(askpass.EnvSock) != "" {
		os.Exit(askpass.Main(os.Args[1:]))
	}
	os.Exit(m.Run())
}

type runDoneMsg struct{ r runResult }

func runModel(t *testing.T) (model, *keyring.Key) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	kr := keyring.New()
	day, _ := kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	day.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:aaaa", Path: "/home/alice/.ssh/yk-main-01", Comment: "yk-main-01", VerifyRequired: true}}
	rep := &detect.Report{Keys: []detect.KeyReport{{Serial: "11111111", Known: &kr.Keys[0],
		FIDO: &ykman.FIDOInfo{PINSet: true, PINRetries: 8, MinPINLength: 4}}}}
	m := send(t, model{width: 120, height: 40}, scanDoneMsg{rep: rep, kr: kr})
	return m, &m.kr.Keys[0]
}

// fakeSSH runs script under sh like ssh would run its askpass helper.
func fakeSSH(script string) *exec.Cmd { return exec.Command("sh", "-c", script) }

func job(cmd *exec.Cmd, key *keyring.Key) runJob {
	return runJob{title: "Test run", cmd: cmd, key: key, back: modeKeys,
		done: func(r runResult) tea.Msg { return runDoneMsg{r} }}
}

// begin starts j the way the program would: run the start command.
func begin(t *testing.T, m model, j runJob) model {
	t.Helper()
	next, cmd := m.startRun(j)
	m = next.(model)
	if cmd != nil && j.need == nil {
		m = send(t, m, cmd())
	}
	return m
}

// step feeds the runner's next background message into the model.
func step(t *testing.T, m model) model {
	t.Helper()
	select {
	case msg := <-m.run.ch:
		next, _ := m.Update(msg)
		return next.(model)
	case <-time.After(5 * time.Second):
		t.Fatalf("no message from the run (mode=%v)\n%s", m.mode, m.View())
	}
	return m
}

// until steps until cond holds.
func until(t *testing.T, m model, cond func(model) bool) model {
	t.Helper()
	for i := 0; i < 40 && !cond(m); i++ {
		m = step(t, m)
	}
	if !cond(m) {
		t.Fatalf("condition not reached:\n%s", m.View())
	}
	return m
}

// finished steps to the end and returns the screen's done message.
func finished(t *testing.T, m model) (model, runResult) {
	t.Helper()
	for i := 0; i < 40 && m.mode == modeRun; i++ {
		select {
		case msg := <-m.run.ch:
			next, cmd := m.Update(msg)
			m = next.(model)
			if m.mode != modeRun && cmd != nil {
				if d, ok := cmd().(runDoneMsg); ok {
					return m, d.r
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("run did not finish:\n%s", m.View())
		}
	}
	t.Fatal("no done message")
	return m, runResult{}
}

func typeText(t *testing.T, m model, s string) model {
	for _, r := range s {
		m = send(t, m, keyMsg(string(r)))
	}
	return m
}

func TestRunPINTouchAndOutput(t *testing.T) {
	m, day := runModel(t)
	script := `pin=$("$SSH_ASKPASS" "Enter PIN for ED25519-SK key /home/alice/.ssh/yk-main-01: ") || exit 9
SSH_ASKPASS_PROMPT=none "$SSH_ASKPASS" "Confirm user presence for key ED25519-SK SHA256:aaaa" & n=$!
sleep 0.3; kill $n; wait $n
echo "got:$pin"; echo "Authenticated to host.example" >&2`
	m = begin(t, m, job(fakeSSH(script), day))
	if m.mode != modeRun {
		t.Fatalf("mode = %v", m.mode)
	}

	m = until(t, m, func(m model) bool { return m.run.prompt != nil })
	v := m.View()
	for _, want := range []string{`FIDO2 PIN of "daily"`, "serial 11111111", "8 tries left", "yk-main-01", "asked once"} {
		if !strings.Contains(v, want) {
			t.Errorf("PIN panel lacks %q:\n%s", want, v)
		}
	}
	m = typeText(t, m, "123456")
	if strings.Contains(m.View(), "123456") {
		t.Fatal("PIN visible on screen")
	}
	m = send(t, m, keyMsg("enter"))

	m = until(t, m, func(m model) bool { return m.run.touching })
	if v := m.View(); !strings.Contains(v, `Touch "daily"`) || !strings.Contains(v, "yk-main-01") {
		t.Errorf("touch panel:\n%s", v)
	}
	m, res := finished(t, m)
	if res.err != nil || !res.pinAsked || !strings.Contains(string(res.stdout), "got:123456") {
		t.Errorf("result = %+v (stdout %q)", res, res.stdout)
	}
	if m.mode != modeKeys {
		t.Errorf("did not return: mode=%v", m.mode)
	}
}

// A second PIN request means the PIN was wrong: refuse, stop ssh, report.
func TestRunPINAskedOnlyOnce(t *testing.T) {
	m, day := runModel(t)
	script := `"$SSH_ASKPASS" "Enter PIN for authenticator: " >/dev/null
"$SSH_ASKPASS" "Enter PIN for authenticator: " >/dev/null && echo SECOND-ANSWERED
sleep 5`
	m = begin(t, m, job(fakeSSH(script), day))
	m = until(t, m, func(m model) bool { return m.run.prompt != nil })
	m = send(t, typeText(t, m, "123456"), keyMsg("enter"))
	m, res := finished(t, m)
	if res.err == nil || !strings.Contains(res.err.Error(), "not accepted") || strings.Contains(string(res.stdout), "SECOND") {
		t.Errorf("result = %v stdout=%q", res.err, res.stdout)
	}
}

func TestRunShortPINNotSent(t *testing.T) {
	m, day := runModel(t)
	m = begin(t, m, job(fakeSSH(`"$SSH_ASKPASS" "Enter PIN for authenticator: " && echo SENT; sleep 5`), day))
	m = until(t, m, func(m model) bool { return m.run.prompt != nil })
	m = send(t, typeText(t, m, "12"), keyMsg("enter"))
	_, res := finished(t, m)
	if res.err == nil || !strings.Contains(res.err.Error(), "not sent") || strings.Contains(string(res.stdout), "SENT") {
		t.Errorf("result = %v stdout=%q", res.err, res.stdout)
	}
}

// Low retries: the PIN is not even asked.
func TestRunRefusesPINWithFewTries(t *testing.T) {
	m, day := runModel(t)
	m.rep.Keys[0].FIDO.PINRetries = 2
	_, res := finished(t, begin(t, m, job(fakeSSH(`"$SSH_ASKPASS" "Enter PIN for authenticator: " && echo SENT; sleep 5`), day)))
	if res.err == nil || !strings.Contains(res.err.Error(), "not asking for the PIN") {
		t.Errorf("err = %v", res.err)
	}
}

func TestRunHostKeyAndPassword(t *testing.T) {
	m, _ := runModel(t)
	script := `a=$("$SSH_ASKPASS" "The authenticity of host 'host.example' can't be established.
ED25519 key fingerprint is SHA256:bbbb.
Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
p=$("$SSH_ASKPASS" "alice@host.example's password: ")
echo "hostkey:$a pw:$p"`
	m = until(t, begin(t, m, job(fakeSSH(script), nil)), func(m model) bool { return m.run.prompt != nil })
	if v := m.View(); !strings.Contains(v, "can't be established") || !strings.Contains(v, "y yes") {
		t.Errorf("host key panel:\n%s", v)
	}
	m = send(t, m, keyMsg("y"))
	m = until(t, m, func(m model) bool { return m.run.prompt != nil && m.run.kind == promptSecret })
	if v := m.View(); !strings.Contains(v, "alice@host.example's password") {
		t.Errorf("password panel:\n%s", v)
	}
	m = send(t, typeText(t, m, "s3cret"), keyMsg("enter"))
	_, res := finished(t, m)
	if res.err != nil || strings.TrimSpace(string(res.stdout)) != "hostkey:yes pw:s3cret" || res.pinAsked {
		t.Errorf("result = %+v stdout=%q", res, res.stdout)
	}
}

func TestRunCancel(t *testing.T) {
	m, _ := runModel(t)
	m = until(t, begin(t, m, job(fakeSSH(`echo started >&2; sleep 30`), nil)), func(m model) bool { return len(m.run.lines) > 0 })
	m = send(t, m, keyMsg("esc"))
	_, res := finished(t, m)
	if !errors.Is(res.err, errCancelled) {
		t.Errorf("err = %v", res.err)
	}
}

// Waiting for a YubiKey: the panel names it; skipping runs nothing.
func TestRunWaitsForKey(t *testing.T) {
	m, day := runModel(t)
	marker := t.TempDir() + "/ran"
	j := job(fakeSSH("touch "+marker), day)
	j.need, j.needWhy = day, "for the login with yk-main-01"
	next, _ := m.startRun(j)
	m = next.(model)
	m = send(t, m, runPlugMsg{present: false})
	v := m.View()
	for _, want := range []string{`Plug in "daily"`, "serial 11111111", "for the login with yk-main-01", "skip"} {
		if !strings.Contains(v, want) {
			t.Errorf("wait panel lacks %q:\n%s", want, v)
		}
	}
	next, cmd := m.Update(keyMsg("s"))
	m = next.(model)
	d, ok := cmd().(runDoneMsg)
	if !ok || !d.r.skipped || !errors.Is(d.r.err, errNotPlugged) || m.mode != modeKeys {
		t.Errorf("skip: %+v mode=%v", d, m.mode)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("command ran although skipped")
	}

	// Plugged in → it runs.
	next, _ = m.startRun(j)
	next, start := next.(model).Update(runPlugMsg{present: true})
	m = send(t, next.(model), start())
	_, res := finished(t, m)
	if res.err != nil {
		t.Fatal(res.err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("command did not run after the key was plugged in")
	}
}

// ssh-keygen prints its touch request on stderr instead of asking.
func TestRunKeygenTouchHint(t *testing.T) {
	m, day := runModel(t)
	m = until(t, begin(t, m, job(fakeSSH(`echo "You may need to touch your authenticator to authorize key generation." >&2; sleep 0.5`), day)), func(m model) bool { return m.run.touching })
	if v := m.View(); !strings.Contains(v, `Touch "daily"`) {
		t.Errorf("keygen touch panel:\n%s", v)
	}
	finished(t, m)
}

func TestCleanEnvDropsRedirects(t *testing.T) {
	env := cleanEnv([]string{"HOME=/home/alice", "SSH_ASKPASS=/usr/bin/x", "SSH_ASKPASS_REQUIRE=never", askpass.EnvSock + "=/tmp/x"})
	if len(env) != 1 || env[0] != "HOME=/home/alice" {
		t.Errorf("env = %v", env)
	}
}

func TestQuitStopsRun(t *testing.T) {
	m, _ := runModel(t)
	marker := t.TempDir() + "/survived"
	m = until(t, begin(t, m, job(fakeSSH(`echo up >&2; sleep 1; touch `+marker), nil)), func(m model) bool { return len(m.run.lines) > 0 })
	m = send(t, m, tea.KeyMsg{Type: tea.KeyCtrlC})
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("child kept running after quit")
	}
}

// yking's root apply asks over the socket: a choice with a deadline and
// stage headings. Here a real broker plays that side.
func TestRunApplyChoicePhaseHoldNoCancel(t *testing.T) {
	m, day := runModel(t)
	marker := t.TempDir() + "/finished"
	j := job(fakeSSH(`echo "Plan x: test" >&2; sleep 1; touch `+marker), day)
	j.noCancel, j.hold = true, true
	m = until(t, begin(t, m, j), func(m model) bool { return len(m.run.lines) > 0 })

	b, err := askpass.NewBroker()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	inject := func(f func()) model {
		go f()
		select {
		case q := <-b.Requests():
			next, _ := m.Update(runReqMsg{q})
			return next.(model)
		case <-time.After(3 * time.Second):
			t.Fatal("no request")
		}
		return m
	}

	// Stage heading: shown, and the PIN count starts over.
	m.run.pinAsked = true
	m = inject(func() { askpass.Phase(b.Sock(), "sudo test with the NEW config") })
	if m.run.pinAsked || !strings.Contains(m.View(), "sudo test with the NEW config") {
		t.Errorf("phase: pinAsked=%v\n%s", m.run.pinAsked, m.View())
	}

	// Choice with a countdown; other keys are ignored.
	got := make(chan string, 1)
	m = inject(func() {
		k, _ := askpass.Choose(b.Sock(), "Keep the PAM change?", []askpass.Option{{Key: "k", Label: "keep"}, {Key: "r", Label: "roll back now"}}, time.Now().Add(time.Minute))
		got <- k
	})
	v := m.View()
	for _, want := range []string{"Keep the PAM change?", "k keep", "r roll back now", "automatic roll back in "} {
		if !strings.Contains(v, want) {
			t.Errorf("choice view lacks %q:\n%s", want, v)
		}
	}
	m = send(t, m, keyMsg("x"), keyMsg("esc"))
	if m.run.prompt == nil {
		t.Fatal("esc/other key answered the choice")
	}
	m = send(t, m, keyMsg("k"))
	if k := <-got; k != "k" {
		t.Errorf("answer = %q", k)
	}

	// Neither esc nor Ctrl+C stops it.
	m = send(t, m, keyMsg("esc"))
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = next.(model)
	if cmd != nil || m.mode != modeRun || !strings.Contains(m.View(), "finishes by itself") {
		t.Fatalf("apply interrupted: mode=%v\n%s", m.mode, m.View())
	}

	// It finishes, the result stays until Enter.
	m = until(t, m, func(m model) bool { return m.run.phase == phaseDone })
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("process was stopped")
	}
	if v := m.View(); !strings.Contains(v, "✓ done") || !strings.Contains(v, "Plan x: test") || !strings.Contains(v, "continue") {
		t.Errorf("result view:\n%s", v)
	}
	next, cmd = m.Update(keyMsg("enter"))
	if d, ok := cmd().(runDoneMsg); !ok || d.r.err != nil || next.(model).mode != modeKeys {
		t.Errorf("done = %+v", d)
	}
}

// Applying a reviewed system plan happens on the run screen through
// `sudo -A yking apply --tui SOCKET` (nothing is executed here).
func TestReviewApplyRunsInTUI(t *testing.T) {
	m, _ := runModel(t)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	p := plan.New("test change", time.Now())
	p.WriteFile("/etc/yking/keyring.toml", []byte("version = 1\n"), 0o644)
	var err error
	m.review, err = newReview(p)
	if err != nil {
		t.Fatal(err)
	}
	m.mode = modeReview
	next, cmd := m.Update(keyMsg("a"))
	m = next.(model)
	if m.mode != modeRun || cmd == nil || !m.run.job.noCancel || !m.run.job.hold {
		t.Fatalf("mode=%v job=%+v err=%q", m.mode, m.run.job, m.review.err)
	}
	args := strings.Join(m.run.job.cmd.Args, " ")
	if !strings.Contains(args, "apply --tui "+sockArg) || (os.Geteuid() != 0 && !strings.Contains(args, "sudo -A")) {
		t.Errorf("args = %s", args)
	}
	if v := m.View(); !strings.Contains(v, "Apply: test change") {
		t.Errorf("view:\n%s", v)
	}
}
