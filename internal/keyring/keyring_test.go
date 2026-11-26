package keyring

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func TestLoadMissingIsEmpty(t *testing.T) {
	k, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Keys) != 0 || k.Version != SchemaVersion {
		t.Errorf("got %+v", k)
	}
}

func TestRoundTrip(t *testing.T) {
	k := New()
	key, err := k.Add("12345678", "daily", RoleDaily, t0)
	if err != nil {
		t.Fatal(err)
	}
	key.SSH = append(key.SSH, SSHKey{
		Fingerprint: "SHA256:abc", Type: "sk-ssh-ed25519@openssh.com",
		Hosts: []string{"me@nas"}, CreatedAt: t0,
	})
	if _, err := k.Add("23456789", "offsite", RoleOffsite, t0); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "etc", "keyring.toml")
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v", st.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keys) != 2 || !got.Keys[0].Protected || got.Keys[0].SSH[0].Hosts[0] != "me@nas" {
		t.Errorf("got %+v", got)
	}
	if !got.Keys[0].AddedAt.Equal(t0) {
		t.Errorf("added_at = %v", got.Keys[0].AddedAt)
	}
	if !got.MeetsMinimumKeys() {
		t.Error("two keys should meet minimum")
	}
}

func TestAddRejects(t *testing.T) {
	k := New()
	if _, err := k.Add("12345678", "a", RoleDaily, t0); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		serial, label string
		role          Role
	}{
		{"12345678", "b", RoleDaily},     // dup serial
		{"23456789", "a", RoleDaily},     // dup label
		{"x1", "c", RoleDaily},           // bad serial
		{"34567890", "", RoleDaily},      // empty label
		{"34567890", "d", Role("spare")}, // bad role
	} {
		if _, err := k.Add(c.serial, c.label, c.role, t0); err == nil {
			t.Errorf("Add(%+v) succeeded", c)
		}
	}
	if len(k.Keys) != 1 {
		t.Errorf("failed adds left %d keys", len(k.Keys))
	}
}

func TestLoadRejectsUnknownAndFuture(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown.toml": "version = 1\nbogus = true\n",
		"future.toml":  "version = 99\n",
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: loaded without error", name)
		}
	}
}
