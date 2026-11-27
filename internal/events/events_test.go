package events

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type fake struct {
	serials  []string
	sessions []Session
	locked   []string
	woken    []string
	sudo     []string
	logs     []string
}

func (f *fake) deps(state string) Deps {
	return Deps{
		Serials:   func() ([]string, error) { return slices.Clone(f.serials), nil },
		Sessions:  func([]string) ([]Session, error) { return f.sessions, nil },
		Lock:      func(id string) error { f.locked = append(f.locked, id); return nil },
		Wake:      func(u string) error { f.woken = append(f.woken, u); return nil },
		SudoReset: func(u string) error { f.sudo = append(f.sudo, u); return nil },
		StatePath: state,
		Log:       func(format string, a ...any) { f.logs = append(f.logs, fmt.Sprintf(format, a...)) },
	}
}

var (
	daily, home, offsite = "11111111", "22222222", "33333333"
	registered           = []string{daily, home, offsite}
)

func cfg() *Config {
	return &Config{Version: 1, Users: []string{"alice"}, Triggers: []string{daily},
		OnRemove: Remove{Lock: true, SudoReset: true}, OnInsert: Insert{Wake: true}}
}

func TestRemoveTriggerLocks(t *testing.T) {
	state := filepath.Join(t.TempDir(), "connected.json")
	f := &fake{serials: []string{daily, home}, sessions: []Session{{ID: "2", User: "alice", Type: "wayland"}, {ID: "3", User: "alice", Type: "unspecified"}}}
	Handle("add", cfg(), registered, f.deps(state)) // initial state

	// Backup key pulled: nothing.
	f.serials = []string{daily}
	r, _ := Handle("remove", cfg(), registered, f.deps(state))
	if len(f.locked) != 0 || len(f.sudo) != 0 || !slices.Equal(r.Removed, []string{home}) {
		t.Fatalf("backup removal acted: %+v locked=%v", r, f.locked)
	}
	// Daily pulled: lock the graphical session only, reset sudo.
	f.serials = nil
	Handle("remove", cfg(), registered, f.deps(state))
	if !slices.Equal(f.locked, []string{"2"}) || !slices.Equal(f.sudo, []string{"alice"}) {
		t.Fatalf("locked=%v sudo=%v", f.locked, f.sudo)
	}
}

func TestRemoveSkipsLockWhenBlocked(t *testing.T) {
	state := filepath.Join(t.TempDir(), "connected.json")
	f := &fake{serials: []string{daily}, sessions: []Session{{ID: "2", User: "alice", Type: "wayland"}}}
	Handle("add", cfg(), registered, f.deps(state))
	f.serials = nil
	d := f.deps(state)
	d.LockBlocked = func() string { return "lock screen not interactive" }
	r, err := Handle("remove", cfg(), registered, d)
	if err != nil || len(f.locked) != 0 || !slices.Contains(r.Actions, "lock-skipped") {
		t.Fatalf("locked=%v r=%+v err=%v", f.locked, r, err)
	}
	if !slices.Equal(f.sudo, []string{"alice"}) {
		t.Fatalf("sudo reset skipped: %v", f.sudo)
	}
}

func TestRemoveWithoutStateFallsBack(t *testing.T) {
	state := filepath.Join(t.TempDir(), "connected.json")
	f := &fake{serials: []string{daily}, sessions: []Session{{ID: "2", User: "alice", Type: "x11"}}}
	Handle("remove", cfg(), registered, f.deps(state)) // trigger still there
	if len(f.locked) != 0 {
		t.Fatal("locked although the trigger key is still connected")
	}
	os.Remove(state)
	f.serials = []string{home}
	Handle("remove", cfg(), registered, f.deps(state)) // no trigger left
	if len(f.locked) != 1 {
		t.Fatal("did not lock with no trigger key left")
	}
}

func TestEmptyTriggersMeansAnyRegistered(t *testing.T) {
	state := filepath.Join(t.TempDir(), "connected.json")
	c := cfg()
	c.Triggers = nil
	f := &fake{serials: []string{home, "99999999"}, sessions: []Session{{ID: "2", User: "alice", Type: "wayland"}}}
	Handle("add", c, registered, f.deps(state))
	f.serials = []string{home} // unregistered key removed
	Handle("remove", c, registered, f.deps(state))
	if len(f.locked) != 0 {
		t.Fatal("unregistered key triggered")
	}
	f.serials = nil
	Handle("remove", c, registered, f.deps(state))
	if len(f.locked) != 1 {
		t.Fatal("registered key did not trigger")
	}
}

func TestAddWakesOnlyLockedSessions(t *testing.T) {
	state := filepath.Join(t.TempDir(), "connected.json")
	f := &fake{sessions: []Session{{ID: "2", User: "alice", Type: "wayland", Locked: false}}}
	Handle("remove", cfg(), registered, f.deps(state))
	f.serials = []string{daily}
	Handle("add", cfg(), registered, f.deps(state))
	if len(f.woken) != 0 {
		t.Fatal("woke an unlocked session")
	}
	f.serials = nil
	Handle("remove", cfg(), registered, f.deps(state))
	f.sessions[0].Locked = true
	f.serials = []string{daily}
	Handle("add", cfg(), registered, f.deps(state))
	if !slices.Equal(f.woken, []string{"alice"}) {
		t.Fatalf("woken = %v", f.woken)
	}
	// Unregistered key plugged in: nothing.
	f.woken = nil
	f.serials = []string{daily, "12121212"}
	Handle("add", cfg(), registered, f.deps(state))
	if len(f.woken) != 0 {
		t.Error("unregistered key woke the screen")
	}
}

func TestConfigRoundTripAndValidation(t *testing.T) {
	b, err := cfg().Encode()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b)
	if err != nil || !c.OnRemove.Lock || c.Triggers[0] != daily {
		t.Fatalf("round trip: %+v %v", c, err)
	}
	for _, bad := range []string{
		"version = 2\nusers = [\"alice\"]\n",
		"version = 1\nusers = []\n",
		"version = 1\nusers = [\"root\"]\n",
		"version = 1\nusers = [\"alice; rm\"]\n",
		"version = 1\nusers = [\"alice\"]\ntriggers = [\"abc\"]\n",
		"version = 1\nusers = [\"alice\"]\nrun = \"/bin/sh\"\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestStrictValidators(t *testing.T) {
	if err := ValidateRule(RulePath, []byte(Rule)); err != nil {
		t.Error(err)
	}
	if err := ValidateRule(RulePath, []byte(Rule+`RUN+="/bin/sh -c evil"`+"\n")); err == nil {
		t.Error("modified rule accepted")
	}
	if err := ValidateRule("/etc/udev/rules.d/99-other.rules", []byte(Rule)); err == nil {
		t.Error("other rule file accepted")
	}
	if err := ValidateUnit(UnitPath, []byte(Unit)); err != nil {
		t.Error(err)
	}
	if err := ValidateUnit(UnitPath, []byte(strings.Replace(Unit, BinaryPath, "/home/alice/yking", 1))); err == nil {
		t.Error("unit pointing elsewhere accepted")
	}
	if err := ValidateBinary(BinaryPath, []byte("\x7fELF...")); err != nil {
		t.Error(err)
	}
	if err := ValidateBinary(BinaryPath, []byte("#!/bin/sh\n")); err == nil {
		t.Error("script accepted as binary")
	}
	if err := ValidateBinary("/usr/local/bin/sudo", []byte("\x7fELF")); err == nil {
		t.Error("other binary name accepted")
	}
	if !strings.Contains(Rule, `ENV{PRODUCT}=="1050/*"`) || !strings.Contains(Unit, "ExecStart="+BinaryPath+" event %i") {
		t.Error("rule/unit content changed unexpectedly")
	}
}

func TestResetSudo(t *testing.T) {
	dir := t.TempDir()
	old := SudoTimestampDir
	SudoTimestampDir = dir
	defer func() { SudoTimestampDir = old }()
	os.WriteFile(filepath.Join(dir, "alice"), []byte("x"), 0o600)
	if err := ResetSudo("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "alice")); !os.IsNotExist(err) {
		t.Error("timestamp not removed")
	}
	if err := ResetSudo("alice"); err != nil {
		t.Errorf("missing file: %v", err)
	}
	if err := ResetSudo("../etc/passwd"); err == nil {
		t.Error("path traversal accepted")
	}
}
