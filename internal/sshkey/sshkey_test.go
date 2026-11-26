package sshkey

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"yking/internal/detect"
	"yking/internal/keyring"
	"yking/internal/plan"
	"yking/internal/ykman"
)

// A real sk-ssh-ed25519 public key (test vector, not anyone's key).
const skPub = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIIL6uVZ5n1kp0yl6PpvgxBGNAY8L1kE2JgVyF2yWqX+lAAAABHNzaDo= test@host"

func TestParsePub(t *testing.T) {
	p, err := ParsePub(skPub)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsSK() || p.Comment != "test@host" || !strings.HasPrefix(p.Fingerprint, "SHA256:") || len(p.Fingerprint) != 50 {
		t.Errorf("got %+v", p)
	}
	if _, err := ParsePub("ssh-ed25519 AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIIL6uVZ5n1kp0yl6PpvgxBGNAY8L1kE2JgVyF2yWqX+lAAAABHNzaDo="); err == nil {
		t.Error("type/blob mismatch accepted")
	}
}

func TestScanSK(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.pub"), []byte(skPub+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.pub"), []byte("garbage\n"), 0o644)
	got, err := ScanSK(dir)
	if err != nil || len(got) != 1 || filepath.Base(got[0].Path) != "a.pub" {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestFirmwareAndType(t *testing.T) {
	for v, want := range map[string]bool{"5.8.0": true, "5.2.3": true, "5.2.2": false, "5.1.9": false, "4.3.7": false, "": false, "6.0": true} {
		if got := FirmwareAtLeast(v, 5, 2, 3); got != want {
			t.Errorf("FirmwareAtLeast(%q) = %v", v, got)
		}
	}
	if (GenRequest{Firmware: "5.8.0"}).KeyType() != "ed25519-sk" || (GenRequest{Firmware: "5.1.2"}).KeyType() != "ecdsa-sk" {
		t.Error("key type selection")
	}
}

func TestArgs(t *testing.T) {
	base := []string{"-t", "ed25519-sk", "-N", "", "-C", "c", "-f", "/home/u/.ssh/id_x"}
	r := GenRequest{Firmware: "5.8.0", Dir: "/home/u/.ssh", Name: "id_x", Comment: "c"}
	for use, extra := range map[Use][]string{
		UsePINTouch: {"-O", "verify-required"},
		UsePIN:      {"-O", "verify-required", "-O", "no-touch-required"},
		UseTouch:    nil,
	} {
		r.Use = use
		if want := append(slices.Clone(base), extra...); !slices.Equal(r.Args(), want) {
			t.Errorf("%s: args = %q", use, r.Args())
		}
		for _, a := range r.Args() {
			if a == "resident" || a == "-K" {
				t.Errorf("%s: forbidden arg %q", use, a)
			}
		}
	}
}

// No mode may produce a key that needs neither PIN nor touch.
func TestNeverNoTouchWithoutPIN(t *testing.T) {
	for _, u := range Uses {
		a := GenRequest{Firmware: "5.8.0", Use: u}.Args()
		if slices.Contains(a, "no-touch-required") && !slices.Contains(a, "verify-required") {
			t.Errorf("%s: no-touch-required without verify-required", u)
		}
	}
	if Use(0) != UsePINTouch {
		t.Error("zero value must be the safest default, PIN + touch")
	}
}

func TestNextName(t *testing.T) {
	dir := t.TempDir()
	if n := NextName(dir); n != "yk-main-01" {
		t.Errorf("empty dir: %q", n)
	}
	for _, f := range []string{"yk-main-01", "yk-main-01.pub", "yk-main-03.pub", "yk-main-x", "yk-main-99.bak", "id_ed25519"} {
		os.WriteFile(filepath.Join(dir, f), nil, 0o600)
	}
	if n := NextName(dir); n != "yk-main-04" {
		t.Errorf("got %q, want yk-main-04 (gap at 02 is not reused)", n)
	}
	os.WriteFile(filepath.Join(dir, "yk-main-09"), nil, 0o600)
	if n := NextName(dir); n != "yk-main-10" {
		t.Errorf("got %q", n)
	}
	if c := DefaultComment("yk-main-02"); c != "yk-main-02" {
		t.Errorf("comment %q", c)
	}
}

func goodState() State {
	return State{
		Key: detect.KeyReport{
			Serial: "22222222",
			Known:  &keyring.Key{Serial: "22222222", Label: "home-backup"},
			Info:   ykman.DeviceInfo{Apps: map[string]ykman.AppState{"FIDO2": {USB: "Enabled"}}},
			FIDO:   &ykman.FIDOInfo{PINSet: true, PINRetries: 8},
		},
		Serials: []string{"22222222"}, YubiKeys: 1, FIDODevices: 1,
	}
}

func TestPreflight(t *testing.T) {
	dir := t.TempDir()
	req := GenRequest{Serial: "22222222", Firmware: "5.8.0", Dir: dir, Name: "id_ok", Comment: "c"}
	if p := Preflight(req, goodState()); len(p) != 0 {
		t.Fatalf("good state refused: %v", p)
	}

	cases := map[string]func(*GenRequest, *State){
		"two fido devices": func(_ *GenRequest, s *State) { s.FIDODevices = 2 },
		"other serial":     func(_ *GenRequest, s *State) { s.Serials = []string{"1"} },
		"no-serial key":    func(_ *GenRequest, s *State) { s.YubiKeys = 2 },
		"unregistered":     func(_ *GenRequest, s *State) { s.Key.Known = nil },
		"fido disabled":    func(_ *GenRequest, s *State) { s.Key.Info.Apps["FIDO2"] = ykman.AppState{USB: "Disabled"} },
		"low retries":      func(_ *GenRequest, s *State) { s.Key.FIDO.PINRetries = 3 },
		"blocked":          func(_ *GenRequest, s *State) { s.Key.FIDO.PINBlocked = true },
		"pin mode, no pin set": func(r *GenRequest, s *State) {
			r.Use = UsePIN
			s.Key.FIDO.PINSet = false
		},
		"bad name":   func(r *GenRequest, _ *State) { r.Name = "../evil" },
		"pub name":   func(r *GenRequest, _ *State) { r.Name = "x.pub" },
		"comment nl": func(r *GenRequest, _ *State) { r.Comment = "a\nb" },
		"exists":     func(r *GenRequest, _ *State) { os.WriteFile(filepath.Join(dir, "taken"), nil, 0o600); r.Name = "taken" },
		"pub exists": func(r *GenRequest, _ *State) {
			os.WriteFile(filepath.Join(dir, "half.pub"), nil, 0o600)
			r.Name = "half"
		},
		"no fido state": func(_ *GenRequest, s *State) { s.Key.FIDO = nil },
	}
	for name, mod := range cases {
		r, s := req, goodState()
		mod(&r, &s)
		if p := Preflight(r, s); len(p) == 0 {
			t.Errorf("%s: preflight passed", name)
		}
	}
}

func TestRecordPlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.toml")
	now := time.Date(2026, 11, 26, 23, 0, 0, 0, time.UTC)
	kr := keyring.New()
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, now)
	kr.Save(path)

	e := keyring.SSHKey{Fingerprint: "SHA256:abc", Type: TypeEd25519SK, User: "alice", Path: "/home/alice/.ssh/id_x", CreatedAt: now}
	p, err := RecordPlan(path, "22222222", e, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := keyring.Parse([]byte(p.Steps[0].Content))
	if err != nil || len(got.Keys[0].SSH) != 1 || got.Keys[0].SSH[0].Path != e.Path {
		t.Fatalf("got %+v %v", got, err)
	}

	os.WriteFile(path, []byte(p.Steps[0].Content), 0o644)
	if _, err := RecordPlan(path, "22222222", e, now); err == nil {
		t.Error("duplicate fingerprint accepted")
	}
	if _, err := RecordPlan(path, "11111111", keyring.SSHKey{Fingerprint: "SHA256:new"}, now); err == nil {
		t.Error("unknown serial accepted")
	}
}

// TestNoKeygenOutsidePackage: only this package may run ssh-keygen or ssh.
func TestNoKeygenOutsidePackage(t *testing.T) {
	self, _ := filepath.Abs(".")
	filepath.WalkDir(filepath.Join("..", ".."), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if abs, _ := filepath.Abs(filepath.Dir(path)); abs == self {
			return nil
		}
		// askpass only compares its parent's process name to ssh-keygen/ssh
		// before killing it; it never runs either.
		if filepath.Base(filepath.Dir(path)) == "askpass" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, _ := strconv.Unquote(lit.Value); s == KeygenBinary || s == SSHBinary {
					t.Errorf("%s: %q literal outside internal/sshkey", path, s)
				}
			}
			return true
		})
		return nil
	})
}

// runRemote executes the deploy script locally under sh with a fake HOME.
func runRemote(t *testing.T, home, line string) DeployResult {
	t.Helper()
	cmd, err := DeployCommand("host", line, "")
	if err != nil {
		t.Fatal(err)
	}
	sh := exec.Command("sh", "-c", remoteAdd)
	sh.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	sh.Stdin = cmd.Stdin
	out, err := sh.Output()
	if err != nil {
		t.Fatalf("script failed: %v %s", err, out)
	}
	return ParseDeployOutput(out)
}

func TestRemoteAddScript(t *testing.T) {
	if strings.Contains(remoteAdd, "'") {
		t.Fatal("remote script must not contain single quotes")
	}
	home := t.TempDir()
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	line, _ := AuthorizedLine(skPub, keyring.SSHKey{})

	if r := runRemote(t, home, line); r != DeployAdded {
		t.Fatalf("first: %s", r)
	}
	if fi, _ := os.Stat(filepath.Dir(ak)); fi.Mode().Perm() != 0o700 {
		t.Errorf(".ssh mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(ak); fi.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode %v", fi.Mode().Perm())
	}
	if r := runRemote(t, home, line); r != DeployAlready {
		t.Fatalf("second: %s", r)
	}
	pinOnly, _ := AuthorizedLine(skPub, keyring.SSHKey{NoTouchRequired: true})
	if !strings.HasPrefix(pinOnly, "no-touch-required sk-ssh-ed25519") {
		t.Fatalf("pin-only line %q", pinOnly)
	}
	if r := runRemote(t, home, pinOnly); r != DeployDifferent {
		t.Fatalf("different options: %s", r)
	}
	b, _ := os.ReadFile(ak)
	if strings.Count(string(b), "\n") != 1 {
		t.Errorf("file should hold exactly one line:\n%s", b)
	}

	// Existing file without trailing newline must not get merged lines.
	os.WriteFile(ak, []byte("ssh-ed25519 AAAAexisting other@host"), 0o600)
	if r := runRemote(t, home, line); r != DeployAdded {
		t.Fatalf("no-newline file: %s", r)
	}
	b, _ = os.ReadFile(ak)
	if want := "ssh-ed25519 AAAAexisting other@host\n" + line + "\n"; string(b) != want {
		t.Errorf("got %q want %q", b, want)
	}
}

func TestDeployCommandArgs(t *testing.T) {
	line, _ := AuthorizedLine(skPub, keyring.SSHKey{})
	for _, bad := range []string{"-oProxyCommand=x", "a b", "", "host;rm", "@host", "user@"} {
		if _, err := DeployCommand(bad, line, ""); err == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
	cmd, err := DeployCommand("user@host2.example", line, "")
	if err != nil {
		t.Fatal(err)
	}
	a := cmd.Args
	if i := slices.Index(a, "--"); i < 0 || a[i+1] != "user@host2.example" {
		t.Errorf("target must follow --: %q", a)
	}
	if slices.Contains(a, "-i") {
		t.Errorf("default must not pass -i: %q", a)
	}

	dir := t.TempDir()
	id := filepath.Join(dir, "4ckey")
	os.WriteFile(id, []byte("x"), 0o600)
	os.WriteFile(id+".pub", []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "orphan.pub"), []byte("x"), 0o644)
	if got := IdentityFiles(dir); len(got) != 1 || got[0] != id {
		t.Errorf("IdentityFiles = %v", got)
	}
	cmd, err = DeployCommand("host2", line, id)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.Index(cmd.Args, "-i"); i < 0 || cmd.Args[i+1] != id || !slices.Contains(cmd.Args, "IdentitiesOnly=yes") {
		t.Errorf("identity args: %q", cmd.Args)
	}
	if i, j := slices.Index(cmd.Args, "-i"), slices.Index(cmd.Args, "--"); i > j {
		t.Errorf("-i must come before --: %q", cmd.Args)
	}
	for _, bad := range []string{"relative/key", filepath.Join(dir, "missing"), dir} {
		if _, err := DeployCommand("host2", line, bad); err == nil {
			t.Errorf("identity %q accepted", bad)
		}
	}
	tc, _ := TestLoginCommand("host2", "/k", nil)
	for _, want := range []string{"IdentitiesOnly=yes", "PasswordAuthentication=no", "IdentityAgent=none"} {
		if !slices.Contains(tc.Args, want) {
			t.Errorf("test login missing %s: %q", want, tc.Args)
		}
	}
}

func TestRecordHostPlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.toml")
	now := time.Date(2026, 11, 26, 23, 0, 0, 0, time.UTC)
	kr := keyring.New()
	k, _ := kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, now)
	k.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:a", Comment: "yk-main-02", CreatedAt: now}}
	kr.Save(path)

	p, err := RecordHostPlan(path, "SHA256:a", "user@host2.example", now)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte(p.Steps[0].Content), 0o644)
	got, _ := keyring.Load(path)
	if h := got.Keys[0].SSH[0].Hosts; len(h) != 1 || h[0] != "user@host2.example" {
		t.Errorf("hosts = %v", h)
	}
	if _, err := RecordHostPlan(path, "SHA256:a", "user@host2.example", now); !errors.Is(err, plan.ErrNoChanges) {
		t.Errorf("second record: %v", err)
	}
	if _, err := RecordHostPlan(path, "SHA256:zzz", "x", now); err == nil {
		t.Error("unknown fingerprint accepted")
	}
}

func runRemoteRemove(t *testing.T, home, blob string) RemoveResult {
	t.Helper()
	cmd, err := RemoveCommand("host", blob, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(remoteRemove, "'") {
		t.Fatal("remote script must not contain single quotes")
	}
	sh := exec.Command("sh", "-c", remoteRemove)
	sh.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	sh.Stdin = cmd.Stdin
	out, err := sh.Output()
	if err != nil {
		t.Fatalf("script failed: %v %s", err, out)
	}
	return ParseRemoveOutput(out)
}

func TestRemoteRemoveScript(t *testing.T) {
	blob, err := BlobOf(skPub)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	if r := runRemoteRemove(t, home, blob); r.Kind != "absent" {
		t.Fatalf("no file: %+v", r)
	}
	os.MkdirAll(filepath.Dir(ak), 0o700)

	// Only key (plus a comment): must refuse.
	os.WriteFile(ak, []byte("# my keys\n"+skPub+"\n"), 0o600)
	if r := runRemoteRemove(t, home, blob); r.Kind != "last" || r.Done() {
		t.Fatalf("last key: %+v", r)
	}
	if b, _ := os.ReadFile(ak); !strings.Contains(string(b), blob) {
		t.Fatal("last key was removed")
	}

	// With another key (and a no-touch-required variant of ours): remove ours only.
	other := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIother me@laptop"
	os.WriteFile(ak, []byte(other+"\nno-touch-required "+skPub+"\n"+skPub+"\n"), 0o600)
	r := runRemoteRemove(t, home, blob)
	if r.Kind != "removed" || !r.Done() || !strings.Contains(r.Backup, "authorized_keys.yking-bak-") {
		t.Fatalf("remove: %+v", r)
	}
	b, _ := os.ReadFile(ak)
	if string(b) != other+"\n" {
		t.Errorf("after remove: %q", b)
	}
	if fi, _ := os.Stat(ak); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if bk, _ := os.ReadFile(r.Backup); !strings.Contains(string(bk), blob) {
		t.Error("backup missing the removed lines")
	}
	if r := runRemoteRemove(t, home, blob); r.Kind != "absent" {
		t.Errorf("second run: %+v", r)
	}
}

func TestRemoveCommandArgs(t *testing.T) {
	for _, bad := range []string{"", "a b", "x;rm"} {
		if _, err := RemoveCommand("host", bad, ""); err == nil {
			t.Errorf("blob %q accepted", bad)
		}
	}
	if _, err := RemoveCommand("-oProxyCommand=x", "AAAA", ""); err == nil {
		t.Error("bad target accepted")
	}
}

// buildSKPrivate builds a minimal unencrypted sk-ssh-ed25519 key file body.
func buildSKPrivate(app string, flags byte, handle []byte, cipher string) []byte {
	str := func(b []byte) []byte {
		out := []byte{byte(len(b) >> 24), byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
		return append(out, b...)
	}
	var priv []byte
	priv = append(priv, 1, 2, 3, 4, 1, 2, 3, 4) // check ints
	priv = append(priv, str([]byte(TypeEd25519SK))...)
	priv = append(priv, str(make([]byte, 32))...)
	priv = append(priv, str([]byte(app))...)
	priv = append(priv, flags)
	priv = append(priv, str(handle)...)
	priv = append(priv, str(nil)...) // reserved
	var b []byte
	b = append(b, []byte("openssh-key-v1\x00")...)
	b = append(b, str([]byte(cipher))...)
	b = append(b, str([]byte("none"))...)
	b = append(b, str(nil)...)
	b = append(b, 0, 0, 0, 1)
	b = append(b, str([]byte("pubblob"))...)
	b = append(b, str(priv)...)
	return b
}

func TestParseSKPrivate(t *testing.T) {
	h, err := parseSKPrivate(buildSKPrivate("ssh:", FlagUserPresence|FlagUserVerification|FlagResident, []byte{9, 8, 7}, "none"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Application != "ssh:" || !h.TouchRequired() || !h.PINRequired() || !h.Resident() || h.KeyHandleB64() != "CQgH" {
		t.Errorf("got %+v", h)
	}
	if _, err := parseSKPrivate(buildSKPrivate("ssh:", 1, []byte{1}, "aes256-ctr")); !errors.Is(err, ErrEncrypted) {
		t.Errorf("encrypted: %v", err)
	}
	if _, err := parseSKPrivate([]byte("garbage")); err == nil {
		t.Error("garbage accepted")
	}
	full := buildSKPrivate("ssh:", 1, []byte{1, 2}, "none")
	if _, err := parseSKPrivate(full[:len(full)-10]); err == nil {
		t.Error("truncated accepted")
	}
}

func TestSignTestArgs(t *testing.T) {
	a := strings.Join(SignTestArgs("/k/yk-main-01", "/tmp/x"), " ")
	if a != "-Y sign -f /k/yk-main-01 -n yking-link-test /tmp/x" {
		t.Errorf("args = %q", a)
	}
}
