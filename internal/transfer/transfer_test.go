package transfer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// Invented test values only (public repo).
const pub = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIIL6uVZ5n1kp0yl6PpvgxBGNAY8L1kE2JgVyF2yWqX+lAAAABHNzaDo= yk-main-02"
const priv = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n"

var t0 = time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

func oldMachine(t *testing.T) (Options, string) {
	t.Helper()
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	os.WriteFile(filepath.Join(sshDir, "yk-main-02"), []byte(priv), 0o600)
	os.WriteFile(filepath.Join(sshDir, "yk-main-02.pub"), []byte(pub+"\n"), 0o644)
	pk, _ := sshkey.ParsePub(pub)

	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0)
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0)
	k := kr.Find("22222222")
	k.U2F = []keyring.U2FCred{{User: "alice", KeyHandle: "khX"}}
	k.LUKS = []keyring.LUKSSlot{{DeviceUUID: "aaaaaaaa-0000-1111-2222-333333333333", Keyslot: 1}}
	k.SSH = []keyring.SSHKey{{Fingerprint: pk.Fingerprint, Type: pk.Type, Path: filepath.Join(sshDir, "yk-main-02"), User: "alice", PublicKey: pub, Hosts: []string{"user@server.example"}, CreatedAt: t0}}

	sts := []pam.State{
		{Service: pam.Service{Name: "sudo"}, Current: pam.Config{Mode: pam.ModeOnly, Unlock: pam.UnlockPIN}},
		{Service: pam.Service{Name: "kde"}, Current: pam.Config{Mode: pam.ModeOnly, Unlock: pam.UnlockPIN, Interactive: true}},
		{Service: pam.Service{Name: "login"}, Current: pam.Config{Mode: pam.ModeOff}},
	}
	ev := &events.Config{Version: 1, Users: []string{"alice"}, Triggers: []string{"11111111"}, OnRemove: events.Remove{Lock: true}}
	return Options{Keyring: kr, PAM: sts, Events: ev, User: "alice", SSHFiles: true, Now: t0}, sshDir
}

func TestExportRoundTrip(t *testing.T) {
	o, _ := oldMachine(t)
	e, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, bad := range []string{"khX", "alice"} {
		if strings.Contains(s, bad) {
			t.Errorf("export contains machine/user-specific %q", bad)
		}
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keys) != 2 || len(got.SSHFiles) != 1 || got.Keys[1].SSH[0].Path != "yk-main-02" {
		t.Errorf("keys/files: %+v", got)
	}
	if d := got.DesiredPAM(); d["sudo"].Mode != pam.ModeOnly || !d["kde"].Interactive || len(d) != 2 {
		t.Errorf("pam: %+v", d)
	}
	if ev := got.DesiredEvents("bob"); ev == nil || ev.Users[0] != "bob" || !ev.OnRemove.Lock {
		t.Errorf("events: %+v", ev)
	}
	if l := got.LUKSKeys(); len(l) != 1 || l[0] != "home-backup" {
		t.Errorf("luks keys: %v", l)
	}
}

func TestValidateRefusesTampering(t *testing.T) {
	o, _ := oldMachine(t)
	e, _ := Build(o)
	for name, mod := range map[string]func(*Export){
		"wrong pubkey":     func(x *Export) { x.SSHFiles[0].Public = strings.Replace(pub, "AAAAIIL6", "AAAAIIL7", 1) },
		"path traversal":   func(x *Export) { x.SSHFiles[0].Name = "../.bashrc" },
		"not a key file":   func(x *Export) { x.SSHFiles[0].Private = "aGVsbG8=" },
		"unknown service":  func(x *Export) { x.PAM["evil"] = PAMSetting{Mode: "only", Unlock: "pin"} },
		"bad mode":         func(x *Export) { x.PAM["sudo"] = PAMSetting{Mode: "always", Unlock: "pin"} },
		"duplicate serial": func(x *Export) { x.Keys = append(x.Keys, x.Keys[0]) },
	} {
		x := *e
		x.SSHFiles = append([]SSHFile(nil), e.SSHFiles...)
		x.PAM = map[string]PAMSetting{}
		for k, v := range e.PAM {
			x.PAM[k] = v
		}
		x.Keys = append([]keyring.Key(nil), e.Keys...)
		mod(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestImportFilesAndKeyring(t *testing.T) {
	o, _ := oldMachine(t)
	e, _ := Build(o)
	newSSH := filepath.Join(t.TempDir(), ".ssh")
	w, err := WriteSSHFiles(e, newSSH)
	if err != nil || len(w) != 2 {
		t.Fatalf("written %v %v", w, err)
	}
	if fi, _ := os.Stat(filepath.Join(newSSH, "yk-main-02")); fi.Mode().Perm() != 0o600 {
		t.Errorf("handle mode %v", fi.Mode().Perm())
	}
	if w, err := WriteSSHFiles(e, newSSH); err != nil || len(w) != 0 {
		t.Errorf("second import: %v %v", w, err)
	}
	os.WriteFile(filepath.Join(newSSH, "yk-main-02"), []byte("other"), 0o600)
	if _, err := WriteSSHFiles(e, newSSH); err == nil {
		t.Error("overwrote a different existing key file")
	}

	krPath := filepath.Join(t.TempDir(), "keyring.toml")
	p, err := KeyringPlan(krPath, e, "bob", newSSH, t0)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := keyring.Parse([]byte(p.Steps[0].Content))
	if err != nil {
		t.Fatal(err)
	}
	k := kr.Find("22222222")
	if k == nil || len(k.U2F) != 0 || len(k.LUKS) != 0 || k.SSH[0].Path != filepath.Join(newSSH, "yk-main-02") || k.SSH[0].User != "bob" || k.SSH[0].Hosts[0] != "user@server.example" {
		t.Errorf("imported key: %+v", k)
	}
	os.WriteFile(krPath, []byte(p.Steps[0].Content), 0o644)
	if _, err := KeyringPlan(krPath, e, "bob", newSSH, t0); !errors.Is(err, plan.ErrNoChanges) {
		t.Errorf("second import should change nothing: %v", err)
	}
}

func TestPending(t *testing.T) {
	o, _ := oldMachine(t)
	e, _ := Build(o)
	home := t.TempDir()
	if p, err := LoadPending(home); p != nil || err != nil {
		t.Fatal("pending before save")
	}
	if err := SavePending(home, e); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(PendingPath(home)); fi.Mode().Perm() != 0o600 {
		t.Errorf("pending mode %v", fi.Mode().Perm())
	}
	if p, err := LoadPending(home); err != nil || len(p.Keys) != 2 {
		t.Errorf("load: %v %v", p, err)
	}
}
