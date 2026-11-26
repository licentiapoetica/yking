package tui

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"yking/internal/detect"
	"yking/internal/keyring"
	"yking/internal/pam"
	"yking/internal/sshkey"
	"yking/internal/ykman"
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
	if m.mode != modeKeys || !strings.Contains(m.status, "no SSH key") {
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
	if v := m.View(); !strings.Contains(v, "None of your 2") || !strings.Contains(v, "Press a to add") {
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

	// Enter starts the first host (returns an exec command).
	m2, cmd := m.Update(keyMsg("enter"))
	m = m2.(model)
	if cmd == nil || m.revoke.busy == "" || len(m.revoke.queue) != 1 {
		t.Fatalf("first host not started: busy=%q queue=%v err=%q", m.revoke.busy, m.revoke.queue, m.revoke.err)
	}
	// Host 0 cleaned, host 1 refused (last key there).
	m2, cmd = m.Update(revokeHostDoneMsg{host: 0, out: []byte("yking-result:removed /home/a/.ssh/authorized_keys.yking-bak-1\n")})
	m = m2.(model)
	if cmd == nil {
		t.Fatal("second host not started")
	}
	m = send(t, m, revokeHostDoneMsg{host: 1, out: []byte("yking-result:last\n")})
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
	for _, want := range []string{"install /usr/local/bin/yking", "write_file /etc/yking/events.toml", "write_file /etc/udev/rules.d/90-yking.rules", "write_file /etc/systemd/system/yking-event@.service"} {
		if !strings.Contains(all, want) {
			t.Errorf("plan missing %q:\n%s", want, all)
		}
	}
}
