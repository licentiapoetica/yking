package tui

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/chalresp"
	"github.com/licentiapoetica/yking/internal/keyring"
	xrunner "github.com/licentiapoetica/yking/internal/runner"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// fakeOTP is YubiKeys with an OTP slot 2 that computes real HMAC-SHA1.
type fakeOTP struct {
	plugged []string
	secrets map[string][]byte // serial → slot 2 secret
	writes  int
	failAck bool // write lands, but ykman reports failure (seen on fw 5.8)
}

func (f *fakeOTP) Run(ctx context.Context, name string, args ...string) (xrunner.Result, error) {
	return f.RunStdin(ctx, nil, name, args...)
}

func (f *fakeOTP) RunStdin(_ context.Context, stdin []byte, _ string, args ...string) (xrunner.Result, error) {
	j := strings.Join(args, " ")
	switch {
	case j == "list --serials":
		return xrunner.Result{Stdout: []byte(strings.Join(f.plugged, "\n") + "\n")}, nil
	case strings.HasSuffix(j, "otp info"):
		st := "empty"
		if f.secrets[args[1]] != nil {
			st = "programmed"
		}
		return xrunner.Result{Stdout: []byte("Slot 1: empty\nSlot 2: " + st + "\n")}, nil
	case strings.Contains(j, "otp chalresp"):
		sec, _ := hex.DecodeString(strings.SplitN(string(stdin), "\n", 2)[0])
		f.secrets[args[1]] = sec
		f.writes++
		if f.failAck {
			return xrunner.Result{}, &xrunner.ExitError{Name: ykman.Binary, Code: 1, Stderr: "ERROR: Failed to write to the YubiKey."}
		}
		return xrunner.Result{}, nil
	case strings.Contains(j, "otp delete 2"):
		delete(f.secrets, args[1])
		return xrunner.Result{}, nil
	case strings.Contains(j, "otp calculate"):
		ch, _ := hex.DecodeString(args[len(args)-1])
		return xrunner.Result{Stdout: []byte(hex.EncodeToString(chalresp.Response(f.secrets[args[1]], ch)) + "\n")}, nil
	}
	return xrunner.Result{}, &xrunner.ExitError{Name: ykman.Binary, Code: 2}
}

// run executes cmd and feeds its message back (one level; enough here).
// The fake ykman answers at once; slower commands are timers and skipped.
func run(t *testing.T, m model, cmd tea.Cmd) model {
	t.Helper()
	if cmd == nil {
		return m
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	select {
	case msg := <-ch:
		if _, tick := msg.(kpTickMsg); tick || msg == nil {
			return m
		}
		next, _ := m.Update(msg)
		return next.(model)
	case <-time.After(100 * time.Millisecond): // a timer (cursor blink): not ours
		return m
	}
}

func press(t *testing.T, m model, k string) model {
	t.Helper()
	next, cmd := m.Update(keyMsg(k))
	return run(t, next.(model), cmd)
}

func kpOpen(t *testing.T, krPath string, f *fakeOTP) model {
	kpPollEvery = time.Millisecond
	otpCheck = func() string { return "" }
	return press(t, model{cfg: Config{KeyringPath: krPath, Client: ykman.New(f)}, width: 120, height: 40}, "v")
}

func TestKeePassSameSecretOnEveryKey(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	kr.Keys[0].Protected = false
	if err := kr.Save(krPath); err != nil {
		t.Fatal(err)
	}
	f := &fakeOTP{plugged: []string{"11111111"}, secrets: map[string][]byte{}}
	m := kpOpen(t, krPath, f)
	if m.mode != modeKeePass || m.kp.secret == nil || len(m.kp.plugged) != 1 {
		t.Fatalf("%+v", m.kp)
	}

	m = press(t, m, "w")
	if _, ok := m.kp.written["11111111"]; !ok || m.kp.err != "" {
		t.Fatalf("daily not written: %q", m.kp.err)
	}
	if m = press(t, m, "w"); f.writes != 1 || !strings.Contains(m.kp.err, "already") {
		t.Fatalf("second write into a used slot: writes=%d err=%q", f.writes, m.kp.err)
	}

	// Swap keys; home-backup is protected: the label must be typed.
	f.plugged = []string{"22222222"}
	m = run(t, m, m.kpRead())
	m = press(t, m, "w")
	if m.kp.inputFor != kpInputConfirm || f.writes != 1 {
		t.Fatal("protected key written without confirmation")
	}
	for _, r := range "home-backup" {
		m = press(t, m, string(r))
	}
	m = press(t, m, "enter")
	if f.writes != 2 || hex.EncodeToString(f.secrets["11111111"]) != hex.EncodeToString(f.secrets["22222222"]) {
		t.Fatalf("secrets differ or not written: %d", f.writes)
	}

	m = press(t, m, "esc") // all keys done: straight to the record plan
	if m.mode != modeReview || m.kp.secret != nil {
		t.Fatalf("mode=%v", m.mode)
	}
	diff := strings.Join(m.review.lines, "\n")
	if strings.Count(diff, "+[key.hmac]") != 2 || strings.Contains(diff, hex.EncodeToString(f.secrets["11111111"])) {
		t.Fatalf("record plan:\n%s", diff)
	}
}

func TestKeePassWarnsBeforeLosingTheSecret(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Add("22222222", "offsite", keyring.RoleOffsite, t0())
	kr.Keys[0].Protected = false
	kr.Save(krPath)
	f := &fakeOTP{plugged: []string{"11111111"}, secrets: map[string][]byte{}}
	m := kpOpen(t, krPath, f)
	m = press(t, m, "w")
	m = press(t, m, "esc")
	if !m.kp.leave || m.mode != modeKeePass || !strings.Contains(m.View(), "offsite can't get this secret") {
		t.Fatalf("no warning:\n%s", m.View())
	}
	if m = press(t, m, "n"); m.mode != modeKeePass {
		t.Fatal("n should stay")
	}
}

func TestKeePassWithoutOTPAccess(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Keys[0].Protected = false
	kr.Save(krPath)
	f := &fakeOTP{plugged: []string{"11111111"}, secrets: map[string][]byte{}}
	m := kpOpen(t, krPath, f)
	otpCheck = func() string { return "OTP interface not accessible (/dev/hidraw9)" }
	m = run(t, m, m.kpRead())
	if m = press(t, m, "w"); f.writes != 0 || !strings.Contains(m.kp.err, "u adds") {
		t.Fatalf("wrote without OTP access: %d %q", f.writes, m.kp.err)
	}
	m = press(t, m, "u")
	if _, err := os.Stat(chalresp.RulePath); err == nil { // installed on this machine
		if !strings.Contains(m.kp.err, "re-plug") {
			t.Fatalf("%q", m.kp.err)
		}
		return
	}
	if m.mode != modeReview || !strings.Contains(strings.Join(m.review.lines, "\n"), "uaccess") {
		t.Fatalf("mode %v", m.mode)
	}
	secret := m.kp.secret
	m = send(t, m, applyDoneMsg{id: "x"})
	if m.mode != modeKeePass || m.kp.secret == nil || &m.kp.secret[0] != &secret[0] {
		t.Fatal("secret lost after applying the rule")
	}
}

// A key written while the test could not run keeps its record; c adopts
// a key that already holds the secret.
func TestKeePassUnverifiedWriteIsKept(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Save(krPath)
	f := &fakeOTP{plugged: []string{"11111111"}, secrets: map[string][]byte{}}
	m := kpOpen(t, krPath, f)
	m = send(t, m, kpWriteMsg{serial: "11111111", written: true, err: errors.New("test challenge: no access")})
	if _, ok := m.kp.written["11111111"]; !ok || !m.kp.unsure["11111111"] {
		t.Fatal("written key forgotten")
	}
	f.secrets["11111111"] = m.kp.secret
	m.kp.plugged[0].slot2 = ykman.SlotProgrammed
	m = press(t, m, "c")
	if m.kp.unsure["11111111"] || m.kp.err != "" {
		t.Fatalf("test did not clear: %q", m.kp.err)
	}
}

func TestKeePassClearsOnlyAFailedSlot(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Save(krPath)
	f := &fakeOTP{plugged: []string{"11111111"}, secrets: map[string][]byte{"11111111": []byte("an earlier secret!!!")}}
	m := kpOpen(t, krPath, f)
	if m = press(t, m, "x"); m.kp.inputFor != kpInputNone {
		t.Fatal("x offered before a failed test")
	}
	m = press(t, m, "c")
	if !m.kp.foreign["11111111"] {
		t.Fatalf("mismatch not noted: %q", m.kp.err)
	}
	m = press(t, m, "x")
	m.kp.input.SetValue("wrong")
	if m = press(t, m, "enter"); f.secrets["11111111"] == nil {
		t.Fatal("cleared without the label")
	}
	m = press(t, m, "x")
	m.kp.input.SetValue("daily")
	m = press(t, m, "enter")
	if f.secrets["11111111"] != nil || m.kp.plugged[0].slot2 != ykman.SlotEmpty {
		t.Fatalf("not cleared: %q", m.kp.err)
	}
}

func TestKeePassWriteReportedFailedButLanded(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "offsite", keyring.RoleOffsite, t0())
	kr.Keys[0].Protected = false
	kr.Save(krPath)
	f := &fakeOTP{plugged: []string{"11111111"}, secrets: map[string][]byte{}, failAck: true}
	m := kpOpen(t, krPath, f)
	m = press(t, m, "w")
	if _, ok := m.kp.written["11111111"]; !ok || m.kp.err != "" {
		t.Fatalf("landed write not accepted: %q", m.kp.err)
	}
}

func TestKeePassPicksAmongPluggedKeys(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Add("22222222", "offsite", keyring.RoleOffsite, t0())
	kr.Keys[0].Protected, kr.Keys[1].Protected = false, false
	kr.Save(krPath)
	f := &fakeOTP{plugged: []string{"22222222", "11111111"}, secrets: map[string][]byte{}}
	m := kpOpen(t, krPath, f)
	if p, _ := m.kp.selected(); p.serial != "11111111" { // keyring order
		t.Fatalf("first selected %s", p.serial)
	}
	m = press(t, m, "down")
	m = press(t, m, "w")
	if f.secrets["22222222"] == nil || f.secrets["11111111"] != nil {
		t.Fatalf("wrong key written: %v", f.secrets)
	}
	if v := m.View(); !strings.Contains(v, "▸ offsite") {
		t.Fatalf("selection not shown:\n%s", v)
	}
}
