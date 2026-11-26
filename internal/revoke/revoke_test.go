package revoke

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
)

var t0 = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

func setup(t *testing.T, recordBackups bool) (*keyring.Keyring, *pam.Mapping, string) {
	t.Helper()
	dir := t.TempDir()
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, t0)
	d := kr.Find("11111111")
	d.U2F = []keyring.U2FCred{{User: "alice", KeyHandle: "kh1"}, {User: "alice", KeyHandle: "kh2"}}
	priv := filepath.Join(dir, "yk-main-04")
	os.WriteFile(priv, []byte("x"), 0o600)
	os.WriteFile(priv+".pub", []byte("x"), 0o644)
	d.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:d", Comment: "yk-main-04", Path: priv, Hosts: []string{"a@one", "b@two"}}}
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0)
	kr.Add("33333333", "offsite", keyring.RoleOffsite, t0)
	if recordBackups {
		kr.Find("22222222").U2F = []keyring.U2FCred{{User: "alice", KeyHandle: "kh3"}}
		kr.Find("33333333").U2F = []keyring.U2FCred{{User: "alice", KeyHandle: "kh4"}}
	}
	m, err := pam.ParseMapping("alice:kh1,p,es256,:kh2,p,es256,:kh3,p,es256,:kh4,p,es256,:kh5,p,es256,\n")
	if err != nil {
		t.Fatal(err)
	}
	return kr, m, dir
}

func services(modes ...pam.Mode) []pam.State {
	var out []pam.State
	for i, m := range modes {
		out = append(out, pam.State{Service: pam.Service{Name: []string{"sudo", "sddm", "login"}[i]}, Current: pam.Config{Mode: m}})
	}
	return out
}

func TestAnalyze(t *testing.T) {
	kr, m, _ := setup(t, true)
	a, err := Analyze(kr, m, "alice", "11111111", services(pam.ModeOnly, pam.ModeOnly, pam.ModeOr))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Recorded) != 2 || a.Recorded[0].Pos != 1 || len(a.Unassigned) != 1 || a.Unassigned[0].Handle != "kh5" {
		t.Errorf("recorded=%v unassigned=%v", a.Recorded, a.Unassigned)
	}
	if !a.UnassignedAreThisKeys || len(a.RemainingConfirmed) != 2 {
		t.Errorf("others confirmed: %v %v", a.UnassignedAreThisKeys, a.RemainingConfirmed)
	}
	if len(a.Hosts) != 2 || len(a.Files) != 2 || len(a.KeyServices) != 2 || len(a.Warnings) != 0 {
		t.Errorf("hosts=%v files=%v services=%v warns=%v", a.Hosts, a.Files, a.KeyServices, a.Warnings)
	}
}

func TestAnalyzeWarnings(t *testing.T) {
	kr, m, _ := setup(t, false) // backups not confirmed
	a, _ := Analyze(kr, m, "alice", "11111111", services(pam.ModeOnly))
	w := strings.Join(a.Warnings, "|")
	if !strings.Contains(w, "NO confirmed key opens sudo") {
		t.Errorf("warnings: %v", a.Warnings)
	}
	if a.UnassignedAreThisKeys {
		t.Error("unassigned must not be attributed while other keys are unconfirmed")
	}
	if got := a.Handles(Choices{RemoveRecorded: true, RemoveUnassigned: true}); len(got) != 2 {
		t.Errorf("unassigned removed although not attributable: %v", got)
	}
	// Revoking a key with no recorded creds while others are unconfirmed.
	b, _ := Analyze(kr, m, "alice", "22222222", nil)
	if !strings.Contains(strings.Join(b.Warnings, "|"), "does not know which PAM credentials") {
		t.Errorf("warnings: %v", b.Warnings)
	}
}

func TestPlans(t *testing.T) {
	kr, m, dir := setup(t, true)
	krPath := filepath.Join(dir, "keyring.toml")
	kr.Save(krPath)
	mpPath := filepath.Join(dir, "u2f_keys")
	os.WriteFile(mpPath, []byte(m.String()), 0o600)

	a, _ := Analyze(kr, m, "alice", "11111111", nil)
	ch := Choices{RemoveRecorded: true, RemoveUnassigned: true, HostsCleaned: map[string]bool{HostKey(a.Hosts[0]): true}}

	base, _ := plan.ReadBase(mpPath)
	up, err := UserPlan(a, ch, "alice", base, t0)
	if err != nil {
		t.Fatal(err)
	}
	if got := up.Steps[0].Content; got != "alice:kh3,p,es256,:kh4,p,es256,\n" || up.Steps[0].Mode != 0o600 {
		t.Errorf("mapping = %q mode %o", got, up.Steps[0].Mode)
	}

	rp, err := RootPlan(krPath, a, ch, t0)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := keyring.Parse([]byte(rp.Steps[0].Content))
	if len(got.Keys) != 2 || got.Find("11111111") != nil {
		t.Errorf("key not removed: %+v", got.Keys)
	}
	if len(got.Revoked) != 1 || len(got.Revoked[0].Leftovers) != 1 || got.Revoked[0].Leftovers[0].Host != "b@two" {
		t.Errorf("revoked = %+v", got.Revoked)
	}

	if p, _ := UserPlan(a, Choices{}, "alice", base, t0); p != nil {
		t.Error("no credentials chosen should give no user plan")
	}
	// Mapping changed underneath: refuse.
	stale, _ := plan.ReadBase(mpPath)
	stale.Data = []byte("alice:kh3,p,es256,\n")
	if _, err := UserPlan(a, ch, "alice", stale, t0); err == nil {
		t.Error("stale mapping accepted")
	}
}

func TestArchive(t *testing.T) {
	_, _, dir := setup(t, true)
	files := []string{filepath.Join(dir, "yk-main-04"), filepath.Join(dir, "yk-main-04.pub")}
	arch := ArchiveDir(dir)
	moved, err := Archive(files, arch)
	if err != nil || len(moved) != 2 {
		t.Fatalf("moved=%v err=%v", moved, err)
	}
	if fi, _ := os.Stat(arch); fi.Mode().Perm() != 0o700 {
		t.Errorf("archive dir mode %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(files[0]); !os.IsNotExist(err) {
		t.Error("original still there")
	}
	// Same name again: never overwrite.
	os.WriteFile(files[0], []byte("y"), 0o600)
	moved2, err := Archive(files[:1], arch)
	if err != nil || moved2[0] == moved[0] {
		t.Errorf("overwrote archived file: %v %v", moved2, err)
	}
}
