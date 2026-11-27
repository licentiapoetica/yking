package sshkey

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
)

const testHome = "/home/alice"

func testKeyring(t *testing.T) *keyring.Keyring {
	t.Helper()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	kr := keyring.New()
	// Registered out of role order on purpose: the block lists daily first.
	off, _ := kr.Add("33333333", "offsite", keyring.RoleOffsite, now)
	off.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:c", Path: testHome + "/.ssh/yk-main-03", Comment: "yk-main-03", VerifyRequired: true,
		Hosts: []string{"alice@a.example"}}}
	bak, _ := kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, now)
	bak.SSH = []keyring.SSHKey{{Fingerprint: "SHA256:b", Path: testHome + "/.ssh/yk-main-02", Comment: "yk-main-02", VerifyRequired: true,
		Hosts: []string{"alice@b.example"}}}
	day, _ := kr.Add("11111111", "daily", keyring.RoleDaily, now)
	day.SSH = []keyring.SSHKey{
		{Fingerprint: "SHA256:a", Path: testHome + "/.ssh/yk-main-01", Comment: "yk-main-01", VerifyRequired: true,
			Hosts: []string{"alice@a.example", "root@b.example"}},
		{Fingerprint: "SHA256:gone", Path: testHome + "/.ssh/yk-old", Comment: "yk-old", Hosts: []string{"alice@a.example"}},
	}
	return kr
}

func exceptOld(p string) bool { return !strings.HasSuffix(p, "yk-old") }

func TestHosts(t *testing.T) {
	hs := Hosts(testKeyring(t), exceptOld)
	if len(hs) != 2 || hs[0].Host != "a.example" || hs[1].Host != "b.example" {
		t.Fatalf("hosts = %+v", hs)
	}
	a := hs[0]
	if len(a.Keys) != 2 || a.Keys[0].Serial != "11111111" || a.Keys[1].Serial != "33333333" {
		t.Errorf("a.example keys not daily-first: %+v", a.Keys)
	}
	if len(a.Missing) != 1 || a.Missing[0].Comment != "yk-old" {
		t.Errorf("missing = %+v", a.Missing)
	}
	if a.User() != "alice" {
		t.Errorf("user = %q", a.User())
	}
	if b := hs[1]; b.User() != "" || len(b.Users) != 2 {
		t.Errorf("b.example users = %v", b.Users)
	}
}

func TestBlock(t *testing.T) {
	got, err := FindHost(Hosts(testKeyring(t), exceptOld), "a.example").Block(testHome)
	if err != nil {
		t.Fatal(err)
	}
	want := `# yking-begin a.example — managed by yking; edits inside are replaced
Host a.example
    User alice
    # daily (11111111)
    IdentityFile ~/.ssh/yk-main-01
    # offsite (33333333)
    IdentityFile ~/.ssh/yk-main-03
    IdentitiesOnly yes
# yking-end a.example
`
	if got != want {
		t.Errorf("block:\n%s\nwant:\n%s", got, want)
	}
	if err := ValidateConfig("/home/alice/.ssh/config", []byte(got)); err != nil {
		t.Errorf("own block fails validation: %v", err)
	}
	b, _ := FindHost(Hosts(testKeyring(t), exceptOld), "b.example").Block(testHome)
	if strings.Contains(b, "User ") || !strings.Contains(b, "several logins") {
		t.Errorf("multi-user block:\n%s", b)
	}
	if b, _ := (HostEntry{Host: "c.example"}).Block(testHome); b != "" {
		t.Errorf("no keys → %q, want empty", b)
	}
	sp := HostEntry{Host: "c.example", Keys: []HostKey{{Path: testHome + "/my keys/k"}}}
	if b, _ := sp.Block(testHome); !strings.Contains(b, `IdentityFile "~/my keys/k"`) {
		t.Errorf("path with space not quoted:\n%s", b)
	}
	if _, err := (HostEntry{Host: "-oProxyCommand=x"}).Block(testHome); err == nil {
		t.Error("bad host accepted")
	}
}

const userCfg = `# my settings
ServerAliveInterval 30

# work
Host work.example
    User bob

Host *
    IdentitiesOnly no
`

func TestSetBlockInsertReplaceRemove(t *testing.T) {
	blk := "# yking-begin a.example x\nHost a.example\n    IdentitiesOnly yes\n# yking-end a.example\n"
	got, err := SetBlock(userCfg, "a.example", blk)
	if err != nil {
		t.Fatal(err)
	}
	// Before the first Host section and its comment; global lines stay global.
	want := "# my settings\nServerAliveInterval 30\n\n" + blk + "\n# work\nHost work.example\n"
	if !strings.HasPrefix(got, want) {
		t.Errorf("insert:\n%s", got)
	}
	if !strings.HasSuffix(got, "Host *\n    IdentitiesOnly no\n") {
		t.Errorf("tail changed:\n%s", got)
	}

	blk2 := strings.Replace(blk, "IdentitiesOnly yes", "User alice\n    IdentitiesOnly yes", 1)
	got2, _ := SetBlock(got, "a.example", blk2)
	if strings.Count(got2, "yking-begin") != 1 || !strings.Contains(got2, "User alice") {
		t.Errorf("replace:\n%s", got2)
	}
	back, _ := SetBlock(got2, "a.example", "")
	if back != userCfg {
		t.Errorf("remove did not restore the file:\n%q\nwant\n%q", back, userCfg)
	}

	// A second host goes next to the first, not between the user's lines.
	both, _ := SetBlock(got, "b.example", strings.ReplaceAll(blk, "a.example", "b.example"))
	bm, err := ParseManaged(both)
	if err != nil || len(bm) != 2 {
		t.Fatalf("two blocks: %v %+v\n%s", err, bm, both)
	}
	if !strings.HasPrefix(both, "# my settings\nServerAliveInterval 30\n\n# yking-begin b.example") {
		t.Errorf("second block placement:\n%s", both)
	}

	empty, _ := SetBlock("", "a.example", blk)
	if empty != blk {
		t.Errorf("empty file: %q", empty)
	}
	noHost, _ := SetBlock("ServerAliveInterval 30", "a.example", blk)
	if noHost != "ServerAliveInterval 30\n\n"+blk {
		t.Errorf("no Host section: %q", noHost)
	}
	if same, _ := SetBlock(userCfg, "a.example", ""); same != userCfg {
		t.Error("removing an absent block changed the file")
	}
}

func TestParseManagedRejectsBrokenMarkers(t *testing.T) {
	for name, cfg := range map[string]string{
		"unclosed":  "# yking-begin a.example\nHost a.example\n",
		"mismatch":  "# yking-begin a.example\n# yking-end b.example\n",
		"nested":    "# yking-begin a.example\n# yking-begin b.example\n",
		"stray end": "# yking-end a.example\n",
		"duplicate": "# yking-begin a.example\n# yking-end a.example\n# yking-begin a.example\n# yking-end a.example\n",
	} {
		if _, err := ParseManaged(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
		if _, err := SetBlock(cfg, "a.example", ""); err == nil {
			t.Errorf("%s: SetBlock edited a broken file", name)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	ok := "Host x\n  ProxyCommand anything\n# yking-begin a.example\nHost a.example\n  User alice\n  IdentityFile ~/.ssh/k\n  IdentitiesOnly=yes\n# yking-end a.example\n"
	if err := ValidateConfig("/home/alice/.ssh/config", []byte(ok)); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	for name, c := range map[string]string{
		"proxy in block": "# yking-begin a.example\nHost a.example\n  ProxyCommand nc %h %p\n# yking-end a.example\n",
		"other host":     "# yking-begin a.example\nHost evil.example\n# yking-end a.example\n",
		"two hosts":      "# yking-begin a.example\nHost a.example\nHost a.example\n# yking-end a.example\n",
		"no host":        "# yking-begin a.example\n  User alice\n# yking-end a.example\n",
		"match":          "# yking-begin a.example\nHost a.example\nMatch exec true\n# yking-end a.example\n",
	} {
		if err := ValidateConfig("/home/alice/.ssh/config", []byte(c)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := ValidateConfig("/home/alice/.ssh/authorized_keys", []byte("")); err == nil {
		t.Error("other file in ~/.ssh accepted")
	}
}

func TestOwnHostLines(t *testing.T) {
	cfg := "Host a.example b.example\n# yking-begin a.example\nHost a.example\n# yking-end a.example\nHost=a.example\n"
	if got := OwnHostLines(cfg, "a.example"); len(got) != 2 || got[0] != 1 || got[1] != 5 {
		t.Errorf("own lines = %v", got)
	}
}

func TestConfigPlan(t *testing.T) {
	h := t.TempDir()
	path := ConfigPath(h)
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte(userCfg), 0o644)
	key := filepath.Join(h, ".ssh", "yk-main-01")
	e := HostEntry{Host: "a.example", Users: []string{"alice"}, Keys: []HostKey{{Path: key, Label: "daily", Serial: "11111111"}}}

	p, _, err := ConfigPlan(path, h, e, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := p.Steps[0]
	if st.Mode != 0o644 || st.ExpectSHA256 == "" || !strings.Contains(st.Content, "IdentityFile ~/.ssh/yk-main-01") {
		t.Errorf("step = %+v", st)
	}
	os.WriteFile(path, []byte(st.Content), 0o644)
	if _, _, err := ConfigPlan(path, h, e, time.Now()); !errors.Is(err, plan.ErrNoChanges) {
		t.Errorf("second plan: %v", err)
	}
	st2, orphans, _ := ConfigState(st.Content, h, []HostEntry{e, {Host: "b.example"}})
	if st2["a.example"] != BlockCurrent || st2["b.example"] != BlockAbsent || len(orphans) != 0 {
		t.Errorf("state = %v %v", st2, orphans)
	}
	e.Users = []string{"bob"}
	if st3, _, _ := ConfigState(st.Content, h, []HostEntry{e}); st3["a.example"] != BlockStale {
		t.Errorf("changed user not stale: %v", st3)
	}
	if _, orphans, _ := ConfigState(st.Content, h, nil); len(orphans) != 1 || orphans[0] != "a.example" {
		t.Errorf("orphans = %v", orphans)
	}

	// Removing (no keys left) restores the user's file.
	rp, _, err := ConfigPlan(path, h, HostEntry{Host: "a.example"}, time.Now())
	if err != nil || rp.Steps[0].Content != userCfg {
		t.Errorf("removal: %v", err)
	}

	// New file: created 0600.
	os.Remove(path)
	np, _, err := ConfigPlan(path, h, e, time.Now())
	if err != nil || np.Steps[0].Mode != 0o600 || !np.Steps[0].ExpectAbsent {
		t.Errorf("new file: %v %+v", err, np)
	}

	// Symlinked config (dotfile managers): refused.
	real := filepath.Join(h, "dotfiles-config")
	os.WriteFile(real, []byte(userCfg), 0o644)
	os.Symlink(real, path)
	if _, _, err := ConfigPlan(path, h, e, time.Now()); err == nil {
		t.Error("symlinked config accepted")
	}
}

func TestCheckResolved(t *testing.T) {
	e := HostEntry{Host: "a.example", Users: []string{"alice"}, Keys: []HostKey{{Path: "/k/yk-main-01"}, {Path: "/k/yk-main-02"}}}
	good := "user alice\nidentitiesonly yes\nidentityfile /k/yk-main-01\nidentityfile /k/yk-main-02\n"
	if w := checkResolved(good, e); len(w) != 0 {
		t.Errorf("warnings for a good config: %v", w)
	}
	bad := "user root\nidentitiesonly no\nidentityfile /k/yk-main-01\n"
	if w := checkResolved(bad, e); len(w) != 3 {
		t.Errorf("want 3 warnings, got %v", w)
	}
}

// TestVerifyConfigWithSSH runs the real `ssh -G` (no connection) when an
// ssh client is installed.
func TestVerifyConfigWithSSH(t *testing.T) {
	if _, err := exec.LookPath(SSHBinary); err != nil {
		t.Skip("no ssh client")
	}
	dir := t.TempDir()
	e := HostEntry{Host: "a.example", Users: []string{"alice"}, Keys: []HostKey{{Path: filepath.Join(dir, "yk-main-01"), Label: "daily", Serial: "11111111"}}}
	blk, _ := e.Block("/nonexistent-home")
	cfg, _ := SetBlock(userCfg, "a.example", blk)
	if w := VerifyConfig(cfg, e); len(w) != 0 {
		t.Errorf("unexpected warnings: %v", w)
	}
	// A global "IdentitiesOnly no" before any Host wins over yking's block.
	cfg2, _ := SetBlock("IdentitiesOnly no\n", "a.example", blk)
	if w := VerifyConfig(cfg2, e); len(w) != 1 || !strings.Contains(w[0], "IdentitiesOnly") {
		t.Errorf("global override not reported: %v", w)
	}
	if w := VerifyConfig("Match exec \"touch /tmp/x\"\n"+blk, e); len(w) != 1 || !strings.Contains(w[0], "Match exec") {
		t.Errorf("Match exec not skipped: %v", w)
	}
}

func TestConfigPlanAdoptsOwnSection(t *testing.T) {
	h := t.TempDir()
	path := ConfigPath(h)
	os.MkdirAll(filepath.Dir(path), 0o700)
	k1, k2 := filepath.Join(h, ".ssh", "yk-main-01"), filepath.Join(h, ".ssh", "yk-main-02")
	e := HostEntry{Host: "a.example", Users: []string{"alice"}, Keys: []HostKey{{Path: k1, Label: "daily", Serial: "11111111"}, {Path: k2, Label: "home-backup", Serial: "22222222"}}}
	tail := "\n# work\nHost work.example\n    User bob\n"
	plan := func(cfg string) (string, []string) {
		t.Helper()
		os.WriteFile(path, []byte(cfg), 0o600)
		p, notes, err := ConfigPlan(path, h, e, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return p.Steps[0].Content, notes
	}

	// Hand-written section with only managed settings: replaced in place.
	got, notes := plan("Compression yes\n\nHost a.example\n    User alice\n    IdentityFile ~/.ssh/yk-main-01\n    IdentitiesOnly yes\n" + tail)
	if strings.Count(got, "Host a.example") != 1 || !strings.HasPrefix(got, "Compression yes\n\n# yking-begin a.example") || !strings.HasSuffix(got, "# yking-end a.example\n"+tail) {
		t.Errorf("adopt:\n%s", got)
	}
	if len(notes) == 0 || !strings.Contains(notes[0], "replaced by yking's block") {
		t.Errorf("notes = %v", notes)
	}

	// Anything yking would drop keeps the user's section.
	for name, own := range map[string]string{
		"port":       "Host a.example\n    Port 2222\n",
		"other user": "Host a.example\n    User root\n",
		"other key":  "Host a.example\n    IdentityFile ~/.ssh/id_ed25519\n",
		"two names":  "Host a.example b.example\n    User alice\n",
	} {
		got, notes := plan(own + tail)
		if !strings.Contains(got, own) || strings.Count(got, "yking-begin") != 1 {
			t.Errorf("%s: own section not kept:\n%s", name, got)
		}
		if !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, "is kept") }) {
			t.Errorf("%s: notes = %v", name, notes)
		}
	}
}

func TestLoginUser(t *testing.T) {
	if LoginUser("alice@a.example") != "" || LoginUser("-oProxyCommand=x") != "" {
		t.Error("user@host / bad host must not be resolved")
	}
	if _, err := exec.LookPath(SSHBinary); err != nil {
		t.Skip("no ssh client")
	}
	cfg := filepath.Join(t.TempDir(), "config")
	os.WriteFile(cfg, []byte("Host a.example\n    User alice\n"), 0o600)
	if u := loginUser("a.example", cfg); u != "alice" {
		t.Errorf("configured user = %q", u)
	}
	if u := loginUser("b.example", cfg); u == "" || u == "alice" {
		t.Errorf("default user = %q (want the local name)", u)
	}
	os.WriteFile(cfg, []byte("Match exec \"true\"\n    User bob\n"), 0o600)
	if u := loginUser("a.example", cfg); u != "" {
		t.Errorf("Match exec config resolved: %q", u)
	}
}
