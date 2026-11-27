package tui

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/luks"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/sshkey"
	"github.com/licentiapoetica/yking/internal/transfer"
	"github.com/licentiapoetica/yking/internal/ykman"
)

func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func send(t *testing.T, m tea.Model, msgs ...tea.Msg) model {
	t.Helper()
	for _, msg := range msgs {
		m, _ = m.Update(msg)
	}
	return m.(model)
}

func TestEnrollFlowBuildsReview(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	rep := &detect.Report{Keys: []detect.KeyReport{{
		Serial: "12345678",
		Info:   ykman.DeviceInfo{DeviceType: "YubiKey 5 NFC", Firmware: "5.4.3"},
	}}}
	m0 := model{cfg: Config{KeyringPath: krPath}, width: 120, height: 40}
	m := send(t, m0, scanDoneMsg{rep: rep, kr: keyring.New()})

	m = send(t, m, keyMsg("e"))
	if m.mode != modeEnroll {
		t.Fatalf("mode = %v, want enroll", m.mode)
	}
	if got := m.enroll.label.Value(); got != "daily" {
		t.Errorf("suggested label %q", got)
	}

	// Move to role, pick next role (home-backup); label follows since untouched.
	m = send(t, m, keyMsg("tab"), keyMsg("right"))
	if m.enroll.role() != keyring.RoleHomeBackup || m.enroll.label.Value() != "home-backup" {
		t.Errorf("role=%s label=%s", m.enroll.role(), m.enroll.label.Value())
	}

	m = send(t, m, keyMsg("enter"))
	if m.mode != modeReview {
		t.Fatalf("mode = %v, want review (err %q)", m.mode, m.enroll.err)
	}
	v := m.View()
	for _, want := range []string{`+serial = "12345678"`, `+role = "home-backup"`, "create " + krPath} {
		if !strings.Contains(v, want) {
			t.Errorf("review view missing %q:\n%s", want, v)
		}
	}

	m = send(t, m, keyMsg("esc"))
	if m.mode != modeEnroll {
		t.Errorf("esc from review should return to form")
	}
}

func TestEnrollRefusedForKnownKey(t *testing.T) {
	kr := keyring.New()
	k, _ := kr.Add("12345678", "daily", keyring.RoleDaily, t0())
	rep := &detect.Report{Keys: []detect.KeyReport{{Serial: "12345678", Known: k}}}
	m := send(t, model{}, scanDoneMsg{rep: rep, kr: kr}, keyMsg("e"))
	if m.mode != modeKeys || !strings.Contains(m.status, "already registered") {
		t.Errorf("mode=%v status=%q", m.mode, m.status)
	}
}

func t0() time.Time { return time.Date(2026, 11, 26, 22, 0, 0, 0, time.UTC) }

func TestSSHFormProtectedNeedsLabel(t *testing.T) {
	kr := keyring.New()
	k, _ := kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	rep := &detect.Report{Keys: []detect.KeyReport{{
		Serial: "22222222", Known: k,
		Info: ykman.DeviceInfo{Firmware: "5.8.0"},
	}}}
	t.Setenv("HOME", t.TempDir()) // NextName scans ~/.ssh
	m := send(t, model{width: 120, height: 40}, scanDoneMsg{rep: rep, kr: kr}, keyMsg("s"))
	if m.mode != modeSSH {
		t.Fatalf("mode = %v", m.mode)
	}
	v := m.View()
	for _, want := range []string{"yk-main-01", "-C yk-main-01", "ssh-keygen -t ed25519-sk -N ''", "Confirm"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	m = send(t, m, keyMsg("enter"))
	if !strings.Contains(m.ssh.err, "protected") || m.ssh.busy != "" {
		t.Errorf("enter without label: err=%q busy=%q", m.ssh.err, m.ssh.busy)
	}
	// Type the label in the confirm field (focus moved there) and retry.
	for _, r := range "home-backup" {
		m = send(t, m, keyMsg(string(r)))
	}
	m2, cmd := m.Update(keyMsg("enter"))
	if mm := m2.(model); mm.ssh.err != "" || mm.ssh.busy == "" || cmd == nil {
		t.Errorf("after label: err=%q busy=%q", mm.ssh.err, mm.ssh.busy)
	}
}

func TestSSHRequiresRegisteredKey(t *testing.T) {
	rep := &detect.Report{Keys: []detect.KeyReport{{Serial: "1"}}}
	m := send(t, model{}, scanDoneMsg{rep: rep, kr: keyring.New()}, keyMsg("s"))
	if m.mode != modeKeys || !strings.Contains(m.status, "Register") {
		t.Errorf("mode=%v status=%q", m.mode, m.status)
	}
}

func TestSSHLoginSelector(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	kr := keyring.New()
	k, _ := kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	k.Protected = false
	rep := &detect.Report{Keys: []detect.KeyReport{{Serial: "22222222", Known: k, Info: ykman.DeviceInfo{Firmware: "5.8.0"}}}}
	m := send(t, model{width: 120, height: 40}, scanDoneMsg{rep: rep, kr: kr}, keyMsg("s"))
	if v := m.View(); !strings.Contains(v, "[PIN + touch]") || !strings.Contains(v, "-O verify-required") {
		t.Fatalf("default should be PIN + touch:\n%s", v)
	}
	m = send(t, m, keyMsg("tab"), keyMsg("tab"), keyMsg("right")) // to Login, next option
	v := m.View()
	if !strings.Contains(v, "[PIN only]") || !strings.Contains(v, "-O no-touch-required") || !strings.Contains(v, "authorized_keys") {
		t.Fatalf("PIN only not selected/explained:\n%s", v)
	}
	m = send(t, m, keyMsg("right"))
	if v := m.View(); !strings.Contains(v, "[touch only]") || strings.Contains(v, "verify-required") {
		t.Fatalf("touch only:\n%s", v)
	}
	m = send(t, m, keyMsg("right"))
	if m.ssh.use != sshkey.UsePINTouch {
		t.Error("selector should wrap around")
	}
}

const testPub = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIIL6uVZ5n1kp0yl6PpvgxBGNAY8L1kE2JgVyF2yWqX+lAAAABHNzaDo= yk-main-02"

func deployModel(t *testing.T) (model, string) {
	t.Helper()
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.toml")
	priv := filepath.Join(dir, "yk-main-02")
	os.WriteFile(priv+".pub", []byte(testPub+"\n"), 0o644)
	pk, _ := sshkey.ParsePub(testPub)

	kr := keyring.New()
	k, _ := kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	k.SSH = []keyring.SSHKey{{Fingerprint: pk.Fingerprint, Type: pk.Type, Path: priv, Comment: "yk-main-02", VerifyRequired: true, CreatedAt: t0()}}
	if err := kr.Save(krPath); err != nil {
		t.Fatal(err)
	}
	rep := &detect.Report{Keys: []detect.KeyReport{{Serial: "22222222", Known: k}}}
	m := send(t, model{cfg: Config{KeyringPath: krPath}, width: 120, height: 40}, scanDoneMsg{rep: rep, kr: kr})
	return m, priv
}

func TestDeployNeedsSSHKey(t *testing.T) {
	kr := keyring.New()
	k, _ := kr.Add("1", "x", keyring.RoleDaily, t0())
	m := send(t, model{}, scanDoneMsg{rep: &detect.Report{Keys: []detect.KeyReport{{Serial: "1", Known: k}}}, kr: kr}, keyMsg("d"))
	if m.mode != modeKeys || !strings.Contains(m.status, "No SSH key") {
		t.Errorf("mode=%v status=%q", m.mode, m.status)
	}
}

func TestDeployFlow(t *testing.T) {
	m, _ := deployModel(t)
	m = send(t, m, keyMsg("d"))
	if m.mode != modeDeploy {
		t.Fatalf("mode = %v", m.mode)
	}
	// Bad target is refused before anything runs.
	for _, r := range "-oProxyCommand=x" {
		m = send(t, m, keyMsg(string(r)))
	}
	m2, cmd := m.Update(keyMsg("enter"))
	if mm := m2.(model); cmd != nil || !strings.Contains(mm.deploy.err, "invalid target") {
		t.Fatalf("bad target: cmd=%v err=%q", cmd != nil, mm.deploy.err)
	}

	// Simulated failed ssh: nothing recorded, stays in form.
	s := m.deploy.selected()
	m = send(t, m, deployDoneMsg{target: "user@host2.example", ssh: s, err: errors.New("exit status 255")})
	if m.mode != modeDeploy || !strings.Contains(m.deploy.err, "Nothing was recorded") {
		t.Fatalf("failed deploy: mode=%v err=%q", m.mode, m.deploy.err)
	}

	// Simulated success without test → review of the keyring change.
	m = send(t, m, deployDoneMsg{target: "user@host2.example", ssh: s, out: []byte("yking-result:added\n")})
	if m.mode != modeReview {
		t.Fatalf("mode = %v err=%q", m.mode, m.deploy.err)
	}
	if v := m.View(); !strings.Contains(v, `+hosts = ["user@host2.example"]`) || !strings.Contains(v, "ssh -i") {
		t.Errorf("review:\n%s", v)
	}
}

func TestDeployTestFailureStillRecords(t *testing.T) {
	m, _ := deployModel(t)
	m = send(t, m, keyMsg("d"))
	s := m.deploy.selected()
	m = send(t, m, testDoneMsg{target: "host2", ssh: s, result: sshkey.DeployAdded, err: errors.New("exit status 255"), pinRequested: true})
	if m.mode != modeReview || !strings.Contains(m.status, "FAILED") || !strings.Contains(m.status, "one attempt") {
		t.Errorf("mode=%v status=%q", m.mode, m.status)
	}
}

func TestIntroExecPausesOnErrorAndKeepsStderr(t *testing.T) {
	e := &introExec{cmd: exec.Command("sh", "-c", "echo line1 >&2; echo 'Permission denied (publickey,password).' >&2; exit 255"), intro: "hello\n"}
	var out, errw bytes.Buffer
	e.SetStdin(strings.NewReader("\n")) // the user pressing Enter
	e.SetStdout(&out)
	e.SetStderr(&errw)
	err := withTail(e.Run(), e)
	if err == nil || !strings.Contains(err.Error(), "Permission denied") || !strings.Contains(err.Error(), "line1") {
		t.Errorf("err = %v", err)
	}
	if !strings.Contains(out.String(), "Press Enter to return") || !strings.Contains(errw.String(), "Permission denied") {
		t.Errorf("stdout=%q stderr=%q", out.String(), errw.String())
	}

	ok := &introExec{cmd: exec.Command("true")}
	var o2 bytes.Buffer
	ok.SetStdin(strings.NewReader(""))
	ok.SetStdout(&o2)
	ok.SetStderr(&o2)
	if err := ok.Run(); err != nil || strings.Contains(o2.String(), "Press Enter") {
		t.Errorf("success should not pause: %v %q", err, o2.String())
	}
}

// Regression: the PAM screen must count registered keys from the keyring
// file, not from a scan that may not have finished (it showed 0).
func TestPAMScreenReadsKeyringItself(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	kr.Add("33333333", "offsite", keyring.RoleOffsite, t0())
	if err := kr.Save(krPath); err != nil {
		t.Fatal(err)
	}
	m := model{cfg: Config{KeyringPath: krPath}, scanning: true} // no scan result yet
	m = send(t, m, keyMsg("p"))
	if m.mode != modePAM || m.pam.facts.RegisteredKeys != 2 {
		t.Errorf("mode=%v registered=%d", m.mode, m.pam.facts.RegisteredKeys)
	}
}

func u2fModel(t *testing.T) (model, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	mp := filepath.Join(home, ".config", "Yubico", "u2f_keys")
	os.MkdirAll(filepath.Dir(mp), 0o755)
	os.WriteFile(mp, []byte(currentUser()+":khA,pkA,es256,:khB,pkB,es256,\n"), 0o644)

	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	k, _ := kr.Add("33333333", "offsite", keyring.RoleOffsite, t0())
	kr.Save(krPath)
	m := model{cfg: Config{KeyringPath: krPath}, width: 120, height: 40, mode: modeU2F}
	m.u2f = u2fScreen{key: detect.KeyReport{Serial: "33333333", Known: k}}
	return m, mp
}

func TestU2FMatchRecords(t *testing.T) {
	m, _ := u2fModel(t)
	m = send(t, m, u2fCheckMsg{res: &u2fResult{user: currentUser(), total: 2, matched: []int{2}, handles: []string{"khB"}}})
	if v := m.View(); !strings.Contains(v, "owns credential #2 of 2") || !strings.Contains(v, "Press Enter to record") {
		t.Fatalf("view:\n%s", v)
	}
	m = send(t, m, keyMsg("enter"))
	if m.mode != modeReview || m.review.plan == nil || m.review.userPlan != nil {
		t.Fatalf("mode=%v review=%+v err=%q", m.mode, m.review, m.u2f.err)
	}
	if v := m.View(); !strings.Contains(v, `+key_handle = "khB"`) {
		t.Errorf("review:\n%s", v)
	}
}

func TestU2FMissingAddsBothPlans(t *testing.T) {
	m, mp := u2fModel(t)
	m = send(t, m, u2fCheckMsg{res: &u2fResult{user: currentUser(), total: 2}})
	if v := m.View(); !strings.Contains(v, "None of your 2") || !strings.Contains(v, "a to add") {
		t.Fatalf("view:\n%s", v)
	}
	// Simulate pamu2fcfg finished and the new credential verified on the key.
	cred, _ := pam.ParseCred("khNEW,pkNEW,es256,")
	m = send(t, m, u2fVerifiedMsg{cred: cred})
	if m.mode != modeReview || m.review.userPlan == nil || m.review.plan == nil {
		t.Fatalf("mode=%v err=%q", m.mode, m.u2f.err)
	}
	v := m.View()
	if !strings.Contains(v, ":khNEW,pkNEW,es256,") || !strings.Contains(v, `+key_handle = "khNEW"`) || !strings.Contains(v, "no sudo needed") {
		t.Errorf("review:\n%s", v)
	}
	// "a": the user part is applied in-process; the sudo part is returned as a command.
	m2, cmd := m.Update(keyMsg("a"))
	mm := m2.(model)
	if mm.review.userDone == "" || cmd == nil {
		t.Fatalf("userDone=%q cmd=%v err=%q", mm.review.userDone, cmd != nil, mm.review.err)
	}
	b, _ := os.ReadFile(mp)
	if !strings.HasSuffix(strings.TrimSpace(string(b)), ":khNEW,pkNEW,es256,") || !strings.Contains(string(b), "khA,pkA") {
		t.Errorf("mapping = %q", b)
	}
}

func TestU2FVerifyFailureWritesNothing(t *testing.T) {
	m, mp := u2fModel(t)
	before, _ := os.ReadFile(mp)
	m = send(t, m, u2fCheckMsg{res: &u2fResult{user: currentUser(), total: 2}})
	m = send(t, m, u2fVerifiedMsg{err: errors.New("plug in ONLY key 33333333")})
	if m.mode != modeU2F || !strings.Contains(m.u2f.err, "nothing was changed") {
		t.Errorf("mode=%v err=%q", m.mode, m.u2f.err)
	}
	if after, _ := os.ReadFile(mp); string(after) != string(before) {
		t.Error("mapping changed")
	}
}

func revokeModel(t *testing.T) (model, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	user := currentUser()
	mp := filepath.Join(home, ".config", "Yubico", "u2f_keys")
	os.MkdirAll(filepath.Dir(mp), 0o755)
	os.WriteFile(mp, []byte(user+":kh1,p,es256,:kh2,p,es256,:kh3,p,es256,:kh4,p,es256,\n"), 0o600)
	sshd := filepath.Join(home, ".ssh")
	os.MkdirAll(sshd, 0o700)
	priv := filepath.Join(sshd, "yk-main-04")
	os.WriteFile(priv, []byte("handle"), 0o600)
	os.WriteFile(priv+".pub", []byte(testPub+"\n"), 0o644)
	pk, _ := sshkey.ParsePub(testPub)

	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	kr.Add("33333333", "offsite", keyring.RoleOffsite, t0())
	kr.Find("11111111").U2F = []keyring.U2FCred{{User: user, KeyHandle: "kh1"}, {User: user, KeyHandle: "kh2"}}
	kr.Find("11111111").SSH = []keyring.SSHKey{{Fingerprint: pk.Fingerprint, Type: pk.Type, Comment: "yk-main-04", Path: priv, Hosts: []string{"a@one", "b@two"}, CreatedAt: t0()}}
	kr.Find("22222222").U2F = []keyring.U2FCred{{User: user, KeyHandle: "kh3"}}
	kr.Find("33333333").U2F = []keyring.U2FCred{{User: user, KeyHandle: "kh4"}}
	if err := kr.Save(krPath); err != nil {
		t.Fatal(err)
	}
	m := model{cfg: Config{KeyringPath: krPath}, width: 140, height: 50}
	m = send(t, m, scanDoneMsg{rep: &detect.Report{}, kr: kr}, keyMsg("x"))
	return m, priv, mp
}

func TestRevokeFlow(t *testing.T) {
	m, priv, mp := revokeModel(t)
	if m.mode != modeRevoke || len(m.revoke.keys) != 3 {
		t.Fatalf("mode=%v keys=%d err=%q", m.mode, len(m.revoke.keys), m.revoke.err)
	}
	m = send(t, m, keyMsg("enter")) // daily is first
	a := m.revoke.a
	if a == nil || a.Key.Label != "daily" || len(a.Recorded) != 2 || len(a.Hosts) != 2 || len(a.Files) != 2 {
		t.Fatalf("analysis = %+v err=%q", a, m.revoke.err)
	}
	v := m.View()
	for _, want := range []string{"remove credential(s) #1, #2", "SSH: remove yk-main-04 from a@one", "home-backup, offsite", "websites"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	// The revoked key's own file is never offered for logging in.
	for _, l := range m.revoke.logins {
		if l == priv {
			t.Error("revoked key offered as login identity")
		}
	}

	// Wrong label refused.
	m = send(t, m, keyMsg("n"), keyMsg("o"), keyMsg("enter"))
	if !strings.Contains(m.revoke.err, "Type the key's label") {
		t.Fatalf("err = %q", m.revoke.err)
	}
	m.revoke.confirm.SetValue("daily")

	// Enter starts the first host on the run screen (nothing is executed
	// here: the start command is not run).
	m2, cmd := m.Update(keyMsg("enter"))
	m = m2.(model)
	if cmd == nil || m.mode != modeRun || m.revoke.busy == "" || len(m.revoke.queue) != 1 || !strings.Contains(m.View(), "from a@one") {
		t.Fatalf("first host not started: mode=%v busy=%q queue=%v err=%q", m.mode, m.revoke.busy, m.revoke.queue, m.revoke.err)
	}
	// Host 0 cleaned, host 1 refused (last key there).
	m2, cmd = m.finish(runResult{stdout: []byte("yking-result:removed /home/a/.ssh/authorized_keys.yking-bak-1\n")})
	m2, cmd = m2.(model).Update(cmd())
	m = m2.(model)
	if cmd == nil || m.mode != modeRun || !strings.Contains(m.View(), "from b@two") {
		t.Fatal("second host not started")
	}
	m2, cmd = m.finish(runResult{stdout: []byte("yking-result:last\n")})
	m = send(t, m2, cmd())
	if m.mode != modeReview || m.review.userPlan == nil || m.review.plan == nil {
		t.Fatalf("mode=%v err=%q", m.mode, m.revoke.err)
	}
	rv := m.View() + strings.Join(m.review.lines, "\n")
	for _, want := range []string{"b@two: NOT removed", `+host = "b@two"`, "-serial = \"11111111\"", ":kh3,p,es256,:kh4,p,es256,"} {
		if !strings.Contains(rv, want) {
			t.Errorf("review missing %q:\n%s", want, rv)
		}
	}
	if strings.Contains(strings.Join(m.review.lines, "\n"), `+host = "a@one"`) {
		t.Error("cleaned host recorded as leftover")
	}
	if len(m.pendingArchive) != 2 {
		t.Errorf("pendingArchive = %v", m.pendingArchive)
	}
	// Nothing moved or changed before apply.
	if _, err := os.Stat(priv); err != nil {
		t.Error("key file moved before apply")
	}
	if b, _ := os.ReadFile(mp); !strings.Contains(string(b), "kh1") {
		t.Error("mapping changed before apply")
	}
	// Simulate a successful apply: files are archived.
	m = send(t, m, applyDoneMsg{id: "20261127-100000-abcdef", userID: "u"})
	if _, err := os.Stat(priv); !os.IsNotExist(err) {
		t.Error("key file not archived after apply")
	}
	if !strings.Contains(m.status, "moved to") {
		t.Errorf("status = %q", m.status)
	}
}

func TestRevokeFailedApplyKeepsFiles(t *testing.T) {
	m, priv, _ := revokeModel(t)
	m.pendingArchive = []string{priv, priv + ".pub"}
	m.reviewBack = modeRevoke
	m = send(t, m, applyDoneMsg{id: "20261127-100000-abcdef", err: errors.New("exit status 1")})
	if _, err := os.Stat(priv); err != nil {
		t.Error("files moved although apply failed")
	}
}

func TestLinkFlow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshd := filepath.Join(home, ".ssh")
	os.MkdirAll(sshd, 0o700)
	pubPath := filepath.Join(sshd, "yk-main-01.pub")
	os.WriteFile(pubPath, []byte(testPub+"\n"), 0o644)
	pk, _ := sshkey.ReadPub(pubPath)

	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Save(krPath)
	k := kr.Find("11111111")
	rep := &detect.Report{Keys: []detect.KeyReport{{Serial: "11111111", Known: k}}}
	m := send(t, model{cfg: Config{KeyringPath: krPath}, width: 140, height: 50}, scanDoneMsg{rep: rep, kr: kr, sshKeys: []sshkey.PubKey{pk}}, keyMsg("l"))
	if m.mode != modeLink || len(m.link.cands) != 1 {
		t.Fatalf("mode=%v cands=%d", m.mode, len(m.link.cands))
	}
	// Bad host refused before any test runs.
	m = send(t, m, keyMsg("tab"))
	for _, r := range "-oProxy" {
		m = send(t, m, keyMsg(string(r)))
	}
	m2, cmd := m.Update(keyMsg("enter"))
	if mm := m2.(model); cmd != nil || !strings.Contains(mm.link.err, "invalid target") {
		t.Fatalf("bad host: cmd=%v err=%q", cmd != nil, mm.link.err)
	}
	m.link.hosts.SetValue("user@server.example, nas")

	h := sshkey.SKHandle{Type: sshkey.TypeEd25519SK, Application: "ssh:", Flags: sshkey.FlagUserPresence | sshkey.FlagUserVerification | sshkey.FlagResident, KeyHandle: []byte{1}}
	// Wrong key: marked, nothing recorded.
	m = send(t, m, linkSignedMsg{pub: pk, handle: h, err: errors.New("exit status 255: Signing failed: device not found"), pinRequested: true})
	if m.mode != modeLink || !strings.Contains(m.View(), "not on this key") {
		t.Fatalf("wrong key:\n%s", m.View())
	}
	// Right key: review with resident + hosts.
	m = send(t, m, linkSignedMsg{pub: pk, handle: h})
	if m.mode != modeReview {
		t.Fatalf("mode=%v err=%q", m.mode, m.link.err)
	}
	d := strings.Join(m.review.lines, "\n")
	for _, want := range []string{"+resident = true", "+verify_required = true", `+hosts = ["user@server.example", "nas"]`, "+public_key = ", "yk-main-01"} {
		if !strings.Contains(d, want) {
			t.Errorf("diff missing %q:\n%s", want, d)
		}
	}
}

func TestEventsScreenDefaultsAndPlan(t *testing.T) {
	old, oldPAM := eventsConfigPath, discoverPAM
	eventsConfigPath = filepath.Join(t.TempDir(), "none.toml") // as if not set up yet
	discoverPAM = func() ([]pam.State, error) { return nil, nil }
	defer func() { eventsConfigPath, discoverPAM = old, oldPAM }()
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	kr.Save(krPath)
	m := send(t, model{cfg: Config{KeyringPath: krPath}, width: 140, height: 60}, keyMsg("u"))
	if m.mode != modeEvents {
		t.Fatalf("mode = %v", m.mode)
	}
	s := m.events
	if !s.triggers["11111111"] || s.triggers["22222222"] || !s.cfg.OnRemove.Lock || !s.cfg.OnInsert.Wake {
		t.Fatalf("defaults: %+v", s)
	}
	// Untick daily → no trigger with lock on → refused.
	m = send(t, m, keyMsg(" "), keyMsg("enter"))
	if !strings.Contains(m.events.err, "at least one trigger") {
		t.Fatalf("err = %q", m.events.err)
	}
	m = send(t, m, keyMsg(" "), keyMsg("enter"))
	if m.mode != modeReview {
		t.Fatalf("mode=%v err=%q", m.mode, m.events.err)
	}
	var kinds []string
	for _, st := range m.review.plan.Steps {
		kinds = append(kinds, string(st.Kind)+" "+st.Path)
	}
	all := strings.Join(kinds, "\n")
	wants := []string{"install /usr/local/bin/yking", "write_file /etc/yking/events.toml"}
	for _, f := range []struct{ path, content string }{{"/etc/udev/rules.d/90-yking.rules", events.Rule}, {"/etc/systemd/system/yking-event@.service", events.Unit}} {
		if b, err := os.ReadFile(f.path); err != nil || string(b) != f.content {
			wants = append(wants, "write_file "+f.path) // only planned when not already identical
		}
	}
	for _, want := range wants {
		if !strings.Contains(all, want) {
			t.Errorf("plan missing %q:\n%s", want, all)
		}
	}
}

// Regression (host lockout 2026-11-27): "lock when the key is pulled" must be
// refused while the lock screen is key-only without pam_u2f "interactive".
func TestEventsRefuseLockWithLockoutRisk(t *testing.T) {
	old, oldPAM := eventsConfigPath, discoverPAM
	eventsConfigPath = filepath.Join(t.TempDir(), "none.toml")
	risky := pam.State{Service: pam.Service{Name: "kde", Desc: "KDE lock screen", LockScreen: true}, Current: pam.Config{Mode: pam.ModeOnly}}
	discoverPAM = func() ([]pam.State, error) { return []pam.State{risky}, nil }
	defer func() { eventsConfigPath, discoverPAM = old, oldPAM }()

	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Save(krPath)
	m := send(t, model{cfg: Config{KeyringPath: krPath}}, keyMsg("u"), keyMsg("enter"))
	if m.mode != modeEvents || !strings.Contains(m.events.err, "never unlock") {
		t.Fatalf("mode=%v err=%q", m.mode, m.events.err)
	}
	fixed := risky
	fixed.Current.Interactive = true
	discoverPAM = func() ([]pam.State, error) { return []pam.State{fixed}, nil }
	m = send(t, m, keyMsg("enter"))
	if m.mode != modeReview {
		t.Fatalf("with interactive: mode=%v err=%q", m.mode, m.events.err)
	}
}

func TestLUKSScreen(t *testing.T) {
	oldV, oldB, oldP := luksVolumes, luksDiscoverBoot, luksPending
	defer func() { luksVolumes, luksDiscoverBoot, luksPending = oldV, oldB, oldP }()
	root := luks.Volume{Device: "/dev/nvme0n1p2", UUID: "aaaa1111", Version: 2, Mapper: "cryptroot", Root: true, RootLV: true}
	luksVolumes = func() ([]luks.Volume, error) {
		return []luks.Volume{root, {Device: "/dev/sdb1", UUID: "x", Version: 1}}, nil
	}
	luksDiscoverBoot = func() luks.Boot { return luks.Boot{Method: "encrypt", GRUB: true} }
	luksPending = func() string { return "" }

	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	kr.Save(krPath)

	m := send(t, model{cfg: Config{KeyringPath: krPath}, width: 140, height: 50}, keyMsg("b"))
	v := m.View()
	for _, want := range []string{"/dev/nvme0n1p2 · LUKS2 · cryptroot → LVM", "IGNORED at boot", "daily", "not enrolled", "LUKS1: FIDO2 needs LUKS2"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	// Switching boot with nothing enrolled is refused before any sudo.
	m2, cmd := m.Update(keyMsg("m"))
	if mm := m2.(model); cmd != nil || !strings.Contains(mm.luks.err, "enroll at least one key") {
		t.Fatalf("migrate without keys: cmd=%v err=%q", cmd != nil, mm.luks.err)
	}
	// With daily enrolled (per keyring) it runs sudo yking luks migrate.
	kr.Find("11111111").LUKS = []keyring.LUKSSlot{{DeviceUUID: "aaaa1111", Keyslot: 1, PINRequired: true, UPRequired: true}}
	kr.Save(krPath)
	m = send(t, model{cfg: Config{KeyringPath: krPath}, width: 140, height: 50}, keyMsg("b"))
	if v := m.View(); !strings.Contains(v, "✓ daily        slot 1 · PIN + touch") || !strings.Contains(v, "only one key enrolled") {
		t.Errorf("enrolled view:\n%s", v)
	}
	if _, cmd := m.Update(keyMsg("m")); cmd == nil {
		t.Error("migrate did not start")
	}
	// Interrupted boot change is shown prominently.
	luksPending = func() string { return "20261127-000147-a4c9d4" }
	m = send(t, model{cfg: Config{KeyringPath: krPath}}, keyMsg("b"))
	if !strings.Contains(m.View(), "Press R to repair BEFORE rebooting") {
		t.Error("pending marker not shown")
	}
}

func TestImportChecklist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldEv := eventsConfigPath
	eventsConfigPath = filepath.Join(t.TempDir(), "none.toml")
	defer func() { eventsConfigPath = oldEv }()

	pk, _ := sshkey.ParsePub(testPub)
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Find("11111111").SSH = []keyring.SSHKey{{Fingerprint: pk.Fingerprint, Type: pk.Type, Path: "yk-main-02", PublicKey: testPub, CreatedAt: t0()}}
	kr.Find("11111111").LUKS = []keyring.LUKSSlot{{DeviceUUID: "aaaaaaaa-0000-1111-2222-333333333333", Keyslot: 1}}
	exp := &transfer.Export{Version: transfer.Version, Created: t0(), Keys: kr.Keys,
		PAM:      map[string]transfer.PAMSetting{"sudo": {Mode: "only", Unlock: "pin"}},
		SSHFiles: []transfer.SSHFile{{Name: "yk-main-02", Private: "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K", Public: testPub}}}
	if err := transfer.SavePending(home, exp); err != nil {
		t.Fatal(err)
	}
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	m := send(t, model{cfg: Config{KeyringPath: krPath}, width: 140, height: 50}, keyMsg("i"))
	v := m.View()
	for _, want := range []string{"1. Register the keys", "daily not registered yet", "PAM credential per key", "sudo: key only · PIN only", "Disk encryption (optional): enroll daily"} {
		if !strings.Contains(v, want) {
			t.Errorf("checklist missing %q:\n%s", want, v)
		}
	}
	m = send(t, m, keyMsg("1"))
	if m.mode != modeReview || !strings.Contains(strings.Join(m.review.lines, "\n"), `+serial = "11111111"`) {
		t.Fatalf("step 1: mode=%v err=%q", m.mode, m.imp.err)
	}
	if fi, err := os.Stat(filepath.Join(home, ".ssh", "yk-main-02")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("ssh handle not written privately: %v %v", fi, err)
	}
}

// Ticking "SSH config" puts the Host block (user file) and the keyring
// record (system file) into the same review; nothing is written yet.
func TestDeployWithSSHConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	m, priv := deployModel(t)
	os.WriteFile(priv, []byte("handle"), 0o600)
	m = send(t, m, keyMsg("d"))
	if strings.Contains(m.View(), "[x] yes — then review a Host block") {
		t.Fatal("SSH config must be off by default")
	}
	m = send(t, m, keyMsg("tab"), keyMsg("tab"), keyMsg("tab"), keyMsg("tab"), keyMsg(" "))
	if !m.deploy.config {
		t.Fatal("config toggle did not switch on")
	}
	s := m.deploy.selected()
	m = send(t, m, deployDoneMsg{target: "alice@host2.example", ssh: s, out: []byte("yking-result:added\n"), config: true})
	if m.mode != modeReview || m.review.userPlan == nil || m.review.plan == nil {
		t.Fatalf("mode=%v user=%v root=%v err=%q", m.mode, m.review.userPlan != nil, m.review.plan != nil, m.deploy.err)
	}
	v := m.View()
	for _, want := range []string{"+Host host2.example", "+    User alice", "+    IdentityFile " + priv, `+hosts = ["alice@host2.example"]`, "ssh alice@host2.example (after applying)"} {
		if !strings.Contains(v, want) {
			t.Errorf("review lacks %q:\n%s", want, v)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "config")); err == nil {
		t.Error("config written before apply")
	}
}

func TestDeployConfigSkippedWhenTestFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	m, priv := deployModel(t)
	os.WriteFile(priv, []byte("handle"), 0o600)
	m = send(t, m, keyMsg("d"))
	m.deploy.config = true
	s := m.deploy.selected()
	m = send(t, m, testDoneMsg{target: "host2.example", ssh: s, result: sshkey.DeployAdded, err: errors.New("exit status 255"), config: true})
	if m.mode != modeReview || m.review.userPlan != nil || !strings.Contains(m.status, "~/.ssh/config not changed") {
		t.Errorf("mode=%v user=%v status=%q", m.mode, m.review.userPlan != nil, m.status)
	}
}

// The hosts screen writes one host's block, in-process, with a backup.
func TestHostsScreenWritesBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.toml")
	kr := keyring.New()
	k1, k2 := filepath.Join(home, ".ssh", "yk-main-01"), filepath.Join(home, ".ssh", "yk-main-02")
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(k1, []byte("h"), 0o600)
	os.WriteFile(k2, []byte("h"), 0o600)
	// Fill each key before the next Add: Add may move the slice.
	day, _ := kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	day.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:a", Path: k1, Comment: "yk-main-01", VerifyRequired: true, Hosts: []string{"alice@host1.example"}}}
	bak, _ := kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	bak.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:b", Path: k2, Comment: "yk-main-02", VerifyRequired: true}}
	kr.Save(krPath)
	cfg := filepath.Join(home, ".ssh", "config")
	os.WriteFile(cfg, []byte("Host *\n    ServerAliveInterval 30\n"), 0o600)

	m := send(t, model{cfg: Config{KeyringPath: krPath}, width: 160, height: 50}, keyMsg("o"))
	v := m.View()
	for _, want := range []string{"host1.example", "yk-main-01 (daily)", "only one YubiKey can log in", "not here: yk-main-02 (home-backup)", "no yking block"} {
		if !strings.Contains(v, want) {
			t.Errorf("hosts screen lacks %q:\n%s", want, v)
		}
	}
	m = send(t, m, keyMsg("enter"))
	if m.mode != modeReview || m.review.plan != nil || m.review.userPlan == nil {
		t.Fatalf("mode=%v err=%q", m.mode, m.hosts.err)
	}
	m = send(t, m, keyMsg("a"))
	got, _ := os.ReadFile(cfg)
	if !strings.HasPrefix(string(got), "# yking-begin host1.example") || !strings.Contains(string(got), "IdentityFile ~/.ssh/yk-main-01") ||
		!strings.HasSuffix(string(got), "\nHost *\n    ServerAliveInterval 30\n") {
		t.Errorf("config after apply:\n%s", got)
	}
	m = send(t, model{cfg: Config{KeyringPath: krPath}, width: 160, height: 50}, keyMsg("o"))
	if !strings.Contains(m.View(), "up to date") {
		t.Errorf("state after apply:\n%s", m.View())
	}
	if m = send(t, m, keyMsg("enter")); m.mode != modeHosts || !strings.Contains(m.status, "already has") {
		t.Errorf("second enter: mode=%v status=%q", m.mode, m.status)
	}
}

// Deploying the backup key's SSH key while logging in with the daily key:
// the key being deployed is not offered for login, and each choice says
// which YubiKey it needs, whether it is plugged in and on the server.
func TestDeployLoginHints(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ssh := filepath.Join(home, ".ssh")
	os.MkdirAll(ssh, 0o700)
	for _, n := range []string{"id_ed25519", "yk-main-01", "yk-main-02"} {
		os.WriteFile(filepath.Join(ssh, n), []byte("x"), 0o600)
		os.WriteFile(filepath.Join(ssh, n+".pub"), []byte(testPub+"\n"), 0o644)
	}
	kr := keyring.New()
	day, _ := kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	day.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:a", Path: filepath.Join(ssh, "yk-main-01"), Comment: "yk-main-01", Hosts: []string{"alice@host1.example"}}}
	bak, _ := kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	bak.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:b", Path: filepath.Join(ssh, "yk-main-02"), Comment: "yk-main-02"}}
	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	if err := kr.Save(krPath); err != nil {
		t.Fatal(err)
	}
	rep := &detect.Report{Keys: []detect.KeyReport{{Serial: "22222222", Known: bak}}} // only the backup is plugged in
	m := send(t, model{cfg: Config{KeyringPath: krPath}, width: 200, height: 50}, scanDoneMsg{rep: rep, kr: kr}, keyMsg("d"))
	for _, r := range "alice@host1.example" {
		m = send(t, m, keyMsg(string(r)))
	}

	choices := m.deploy.loginChoices()
	if slices.Contains(choices, filepath.Join(ssh, "yk-main-02")) || len(choices) != 3 {
		t.Fatalf("choices = %v (must not offer the key being deployed)", choices)
	}
	m = send(t, m, keyMsg("tab"), keyMsg("tab"), keyMsg("right")) // Login: id_ed25519
	if v := m.View(); !strings.Contains(v, "regular key") {
		t.Errorf("legacy key hint:\n%s", v)
	}
	m = send(t, m, keyMsg("right")) // yk-main-01
	v := m.View()
	for _, want := range []string{"daily", "not plugged in", "on this server", "swap daily → home-backup"} {
		if !strings.Contains(v, want) {
			t.Errorf("yk-main-01 hint lacks %q:\n%s", want, v)
		}
	}
	if o := m.deploy.login().owner; o == nil || o.Serial != "11111111" {
		t.Errorf("login key owner = %+v", o)
	}
	m = send(t, m, keyMsg("right")) // wraps to ssh default
	if m.deploy.loginPath != "" {
		t.Errorf("did not wrap: %q", m.deploy.loginPath)
	}

	m.deploy.target.SetValue("alice@host2.example")
	m.deploy.loginPath = filepath.Join(ssh, "yk-main-01")
	if v := m.View(); !strings.Contains(v, "not on this server") {
		t.Errorf("unknown server not flagged:\n%s", v)
	}

	// Test skipped because the backup was not plugged back in: recorded, not FAILED.
	s := m.deploy.selected()
	m = send(t, m, testDoneMsg{target: "alice@host2.example", ssh: s, result: sshkey.DeployAdded, skipped: true})
	if m.mode != modeReview || !strings.Contains(m.status, "test skipped (home-backup was not plugged in)") || strings.Contains(m.status, "FAILED") {
		t.Errorf("mode=%v status=%q", m.mode, m.status)
	}
}

// U only works when the installed copy differs, and then reviews a plan
// that installs exactly one file: /usr/local/bin/yking (nothing else).
func TestUpdateInstalledPlan(t *testing.T) {
	m := send(t, model{width: 120, height: 40}, scanDoneMsg{rep: &detect.Report{}, kr: keyring.New()}, keyMsg("U"))
	if m.mode != modeKeys {
		t.Fatalf("U without a stale install: mode=%v", m.mode)
	}
	m = send(t, model{width: 120, height: 40}, scanDoneMsg{rep: &detect.Report{}, kr: keyring.New(), stale: "Nov 27 02:53, this build Nov 27 02:58"})
	if v := m.View(); !strings.Contains(v, "U to update") || !strings.Contains(v, "this build Nov 27 02:58") {
		t.Errorf("no banner:\n%s", m.View())
	}
	m = send(t, m, keyMsg("U"))
	if m.mode != modeReview || m.review.plan == nil || m.review.userPlan != nil {
		t.Fatalf("mode=%v status=%q", m.mode, m.status)
	}
	st := m.review.plan.Steps
	self, _ := os.Executable()
	if len(st) != 1 || st[0].Kind != plan.KindInstall || st[0].Path != events.BinaryPath || st[0].Source != self || st[0].Mode != 0o755 {
		t.Errorf("steps = %+v", st)
	}
}

func TestLoadingScreen(t *testing.T) {
	ch1 := make(chan tea.Msg)
	m := model{scanning: true, width: 100}
	m = send(t, m,
		scanProgressMsg{p: detect.Progress{Step: "list", Text: "looking for YubiKeys on USB"}, ch: ch1},
		scanProgressMsg{p: detect.Progress{Step: "list", Text: "found 2 YubiKeys", Done: true}, ch: ch1},
		scanProgressMsg{p: detect.Progress{Step: "key:11111111", Text: "reading daily (11111111)"}, ch: ch1})
	if len(m.scanLog) != 2 || !m.scanLog[0].Done {
		t.Fatalf("log = %+v", m.scanLog)
	}
	v := m.View()
	for _, want := range []string{"Scanning your YubiKeys", "✓ found 2 YubiKeys", "reading daily (11111111)", "●", "quit"} {
		if !strings.Contains(v, want) {
			t.Errorf("loading view lacks %q:\n%s", want, v)
		}
	}
	if strings.Contains(v, "e enroll") {
		t.Error("key commands shown while scanning")
	}
	// A new scan starts a fresh log.
	m = send(t, m, scanProgressMsg{p: detect.Progress{Step: "keyring", Text: "reading the keyring"}, ch: make(chan tea.Msg)})
	if len(m.scanLog) != 1 || m.scanLog[0].Step != "keyring" {
		t.Errorf("log not reset: %+v", m.scanLog)
	}

	// The frame clock starts once and stops itself after the scan.
	next, cmd := m.Update(animTickMsg{})
	m = next.(model)
	if !m.ticking || cmd == nil || m.frame != 1 {
		t.Fatalf("ticking=%v frame=%d", m.ticking, m.frame)
	}
	m = send(t, m, scanDoneMsg{rep: &detect.Report{}, kr: keyring.New()})
	next, cmd = m.Update(animTickMsg{})
	if m = next.(model); m.ticking || cmd != nil {
		t.Errorf("clock kept running after the scan: ticking=%v", m.ticking)
	}
	// Narrow terminals skip the drawing but keep the progress.
	m = model{scanning: true, width: 40, scanLog: []detect.Progress{{Step: "x", Text: "found 1 YubiKey", Done: true}}}
	if v := m.View(); strings.Contains(v, "●") || !strings.Contains(v, "found 1 YubiKey") {
		t.Errorf("narrow view:\n%s", v)
	}
}

// The login name has its own field; empty means what ssh would use, and
// the deploy then uses that name explicitly.
func TestDeployUserField(t *testing.T) {
	m, _ := deployModel(t)
	m = send(t, m, keyMsg("d"))
	for _, r := range "host2.example" {
		m = send(t, m, keyMsg(string(r)))
	}
	if v := m.View(); !strings.Contains(v, "User") || !strings.Contains(v, "empty = ssh default") {
		t.Errorf("user field:\n%s", v)
	}
	// What ssh would use (normally looked up in the background).
	m = send(t, m, deployUserMsg{host: "host2.example", user: "alice"})
	if got, err := m.deploy.fullTarget(); err != nil || got != "alice@host2.example" {
		t.Errorf("default target = %q, %v", got, err)
	}
	if !strings.Contains(m.View(), "alice@host2.example") {
		t.Errorf("resolved login not shown:\n%s", m.View())
	}
	// An explicit user wins.
	m = send(t, m, keyMsg("tab"))
	for _, r := range "deploy" {
		m = send(t, m, keyMsg(string(r)))
	}
	if got, _ := m.deploy.fullTarget(); got != "deploy@host2.example" {
		t.Errorf("explicit target = %q", got)
	}
	// A stale lookup for another host is not used.
	m.deploy.user.SetValue("")
	m.deploy.target.SetValue("host3.example")
	if got, _ := m.deploy.fullTarget(); got != "host3.example" {
		t.Errorf("stale default used: %q", got)
	}
	// user@host in the Server field still works, but not together with User.
	m.deploy.target.SetValue("bob@host2.example")
	if got, err := m.deploy.fullTarget(); err != nil || got != "bob@host2.example" {
		t.Errorf("user@host = %q, %v", got, err)
	}
	m.deploy.user.SetValue("carol")
	if _, err := m.deploy.fullTarget(); err == nil {
		t.Error("user given twice accepted")
	}
	next, cmd := m.Update(keyMsg("enter"))
	if mm := next.(model); cmd != nil || !strings.Contains(mm.deploy.err, "user given twice") {
		t.Errorf("enter: err=%q", mm.deploy.err)
	}
	// Bad user name is refused before anything runs.
	m.deploy.target.SetValue("host2.example")
	m.deploy.user.SetValue("-oProxyCommand=x")
	if _, err := m.deploy.fullTarget(); err == nil {
		t.Error("bad user accepted")
	}
}
