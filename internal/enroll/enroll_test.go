package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yking/internal/detect"
	"yking/internal/keyring"
	"yking/internal/ykman"
)

var t0 = time.Date(2026, 11, 26, 22, 0, 0, 0, time.UTC)

func report(serial string) detect.KeyReport {
	return detect.KeyReport{Serial: serial, Info: ykman.DeviceInfo{DeviceType: "YubiKey 5 NFC", Firmware: "5.4.3"}}
}

func TestPlanFirstKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.toml")
	p, err := Plan(path, report("12345678"), Request{Label: " daily ", Role: keyring.RoleDaily, Protected: true}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 1 || !p.Steps[0].ExpectAbsent {
		t.Fatalf("steps = %+v", p.Steps)
	}
	kr, err := keyring.Parse([]byte(p.Steps[0].Content))
	if err != nil {
		t.Fatal(err)
	}
	k := kr.Keys[0]
	if k.Label != "daily" || !k.Protected || k.Model != "YubiKey 5 NFC" || k.Firmware != "5.4.3" {
		t.Errorf("entry = %+v", k)
	}
}

func TestPlanSecondKeyAndDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("12345678", "daily", keyring.RoleDaily, t0)
	kr.Save(path)

	p, err := Plan(path, report("23456789"), Request{Label: "home", Role: keyring.RoleHomeBackup}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Steps[0].ExpectSHA256 == "" {
		t.Error("modify step should pin the current hash")
	}
	d, _ := p.Diff()
	if !strings.Contains(d, `+serial = "23456789"`) || strings.Contains(d, `-serial`) {
		t.Errorf("diff:\n%s", d)
	}

	if _, err := Plan(path, report("12345678"), Request{Label: "again", Role: keyring.RoleDaily}, t0); err == nil {
		t.Error("enrolling an already registered serial should fail")
	}
	if _, err := Plan(path, report("34567890"), Request{Label: "daily", Role: keyring.RoleOffsite}, t0); err == nil {
		t.Error("duplicate label should fail")
	}
}

func TestPlanRejectsCorruptKeyring(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.toml")
	os.WriteFile(path, []byte("not toml ["), 0o644)
	if _, err := Plan(path, report("12345678"), Request{Label: "d", Role: keyring.RoleDaily}, t0); err == nil {
		t.Error("corrupt keyring must not be overwritten")
	}
}

func TestSuggest(t *testing.T) {
	kr := keyring.New()
	if r := SuggestRole(kr); r != keyring.RoleDaily {
		t.Errorf("got %s", r)
	}
	kr.Add("1", "daily", keyring.RoleDaily, t0)
	if r := SuggestRole(kr); r != keyring.RoleHomeBackup {
		t.Errorf("got %s", r)
	}
	if l := SuggestLabel(kr, keyring.RoleDaily); l != "daily-2" {
		t.Errorf("got %s", l)
	}
}
