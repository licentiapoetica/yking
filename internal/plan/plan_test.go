package plan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yking/internal/keyring"
)

var t0 = time.Date(2026, 11, 26, 22, 0, 0, 0, time.UTC)

func TestUnified(t *testing.T) {
	if d := Unified("a", "b", "x\n", "x\n", 3); d != "" {
		t.Errorf("equal inputs gave diff %q", d)
	}
	d := Unified("/dev/null", "f", "", "one\ntwo\n", 3)
	want := "--- /dev/null\n+++ f\n@@ -0,0 +1,2 @@\n+one\n+two\n"
	if d != want {
		t.Errorf("create diff:\n%s\nwant:\n%s", d, want)
	}

	var a, b []string
	for i := 1; i <= 20; i++ {
		a = append(a, "l"+strings.Repeat("x", i))
	}
	b = append(b, a...)
	b[1] = "changed-2"
	b[17] = "changed-18"
	d = Unified("a", "b", strings.Join(a, "\n")+"\n", strings.Join(b, "\n")+"\n", 3)
	if n := strings.Count(d, "@@ -"); n != 2 {
		t.Errorf("want 2 hunks, got %d:\n%s", n, d)
	}
	if !strings.Contains(d, "@@ -1,5 +1,5 @@\n") || !strings.Contains(d, "@@ -15,6 +15,6 @@\n") {
		t.Errorf("bad hunk headers:\n%s", d)
	}
	if !strings.Contains(d, "-lxx\n+changed-2\n") {
		t.Errorf("missing change:\n%s", d)
	}
}

type env struct {
	dir string // stands in for /etc/yking
	kr  string // keyring path
	a   *Applier
}

func newEnv(t *testing.T) env {
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "yking")
	os.MkdirAll(dir, 0o755)
	return env{
		dir: dir,
		kr:  filepath.Join(dir, "keyring.toml"),
		a: &Applier{
			BackupRoot: filepath.Join(root, "var", "backups"),
			Targets:    []Target{{Dir: dir, Validate: validateYkingFile}},
			Now:        func() time.Time { return t0 },
		},
	}
}

func keyringBytes(t *testing.T, labels ...string) []byte {
	t.Helper()
	k := keyring.New()
	for i, l := range labels {
		if _, err := k.Add(string(rune('1'+i))+"0000000", l, keyring.RoleDaily, t0); err != nil {
			t.Fatal(err)
		}
	}
	b, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestApplyCreateThenRollback(t *testing.T) {
	e := newEnv(t)
	p := New("register daily", t0)
	if err := p.WriteFile(e.kr, keyringBytes(t, "daily"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !p.Steps[0].ExpectAbsent {
		t.Fatal("new file should expect absent")
	}
	m, err := e.a.Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Complete {
		t.Error("manifest not complete")
	}
	if fi, err := os.Stat(e.kr); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("keyring not written: %v %v", fi, err)
	}
	if _, err := e.a.Apply(p); err == nil {
		t.Error("re-applying the same plan should fail")
	}

	latest, err := e.a.Latest()
	if err != nil || latest.ID != p.ID {
		t.Fatalf("latest = %v %v", latest, err)
	}
	if _, err := e.a.Rollback(p.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.kr); !os.IsNotExist(err) {
		t.Error("rollback should remove created file")
	}
	if _, err := e.a.Rollback(p.ID, false); err == nil {
		t.Error("double rollback should fail")
	}
}

func TestApplyModifyThenRollbackRestoresOriginal(t *testing.T) {
	e := newEnv(t)
	orig := keyringBytes(t, "daily")
	os.WriteFile(e.kr, orig, 0o644)

	p := New("add backup", t0)
	p.WriteFile(e.kr, keyringBytes(t, "daily", "backup"), 0o644)
	diff, _ := p.Diff()
	if !strings.Contains(diff, `+label = "backup"`) {
		t.Errorf("diff missing new key:\n%s", diff)
	}
	if _, err := e.a.Apply(p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.Rollback(p.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(e.kr); string(got) != string(orig) {
		t.Error("rollback did not restore original content")
	}
}

func TestRollbackRefusesIfChangedAfter(t *testing.T) {
	e := newEnv(t)
	p := New("x", t0)
	p.WriteFile(e.kr, keyringBytes(t, "daily"), 0o644)
	e.a.Apply(p)
	os.WriteFile(e.kr, keyringBytes(t, "edited"), 0o644)
	if _, err := e.a.Rollback(p.ID, false); err == nil {
		t.Fatal("rollback should refuse when file changed after apply")
	}
	if _, err := e.a.Rollback(p.ID, true); err != nil {
		t.Fatalf("forced rollback: %v", err)
	}
}

func TestStalePlanRefused(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(e.kr, keyringBytes(t, "daily"), 0o644)
	p := New("x", t0)
	p.WriteFile(e.kr, keyringBytes(t, "daily", "b"), 0o644)
	os.WriteFile(e.kr, keyringBytes(t, "other"), 0o644) // changed after planning
	if _, err := e.a.Apply(p); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Fatalf("got %v", err)
	}

	os.Remove(e.kr)
	p2 := New("y", t0)
	p2.WriteFile(e.kr, keyringBytes(t, "daily"), 0o644)
	os.WriteFile(e.kr, keyringBytes(t, "other"), 0o644) // created after planning
	if err := e.a.Check(p2); err == nil {
		t.Fatal("expected refusal when file appeared after planning")
	}
}

func TestCheckRefuses(t *testing.T) {
	e := newEnv(t)
	good := string(keyringBytes(t, "daily"))
	step := func(mod func(*Step)) *Plan {
		p := New("x", t0)
		s := Step{Kind: KindWriteFile, Path: e.kr, Mode: 0o644, Content: good, ExpectAbsent: true}
		mod(&s)
		p.Steps = []Step{s}
		return p
	}
	cases := map[string]*Plan{
		"outside target":  step(func(s *Step) { s.Path = "/etc/passwd" }),
		"relative":        step(func(s *Step) { s.Path = "etc/yking/keyring.toml" }),
		"dotdot":          step(func(s *Step) { s.Path = e.dir + "/../yking/keyring.toml" }),
		"subdir":          step(func(s *Step) { s.Path = e.dir + "/sub/keyring.toml" }),
		"unknown file":    step(func(s *Step) { s.Path = e.dir + "/other.toml" }),
		"invalid content": step(func(s *Step) { s.Content = "version = 1\n[[key]]\nserial = \"abc\"\n" }),
		"world writable":  step(func(s *Step) { s.Mode = 0o666 }),
		"setuid":          step(func(s *Step) { s.Mode = 0o4755 }),
		"bad kind":        step(func(s *Step) { s.Kind = "run_command" }),
	}
	for name, p := range cases {
		if err := e.a.Check(p); err == nil {
			t.Errorf("%s: Check passed", name)
		}
	}
	if err := e.a.Check(New("empty", t0)); !errors.Is(err, ErrNoChanges) {
		t.Errorf("empty plan: %v", err)
	}
}

func TestSymlinkRefused(t *testing.T) {
	e := newEnv(t)
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("x"), 0o644)
	os.Symlink(victim, e.kr)
	p := New("x", t0)
	p.Steps = []Step{{Kind: KindWriteFile, Path: e.kr, Mode: 0o644, Content: string(keyringBytes(t, "d")), ExpectSHA256: "whatever"}}
	if err := e.a.Check(p); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("got %v", err)
	}
}

func TestFailedWriteRestoresEarlierSteps(t *testing.T) {
	e := newEnv(t)
	orig := keyringBytes(t, "daily")
	os.WriteFile(e.kr, orig, 0o644)

	// Second target dir is read-only, so its write fails after the first succeeded.
	ro := filepath.Join(filepath.Dir(e.dir), "ro")
	os.MkdirAll(ro, 0o755)
	e.a.Targets = append(e.a.Targets, Target{Dir: ro, Validate: validateYkingFile})
	os.Chmod(ro, 0o555)
	defer os.Chmod(ro, 0o755)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	p := New("two files", t0)
	p.WriteFile(e.kr, keyringBytes(t, "daily", "b"), 0o644)
	p.WriteFile(filepath.Join(ro, "keyring.toml"), keyringBytes(t, "x"), 0o644)
	m, err := e.a.Apply(p)
	if err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("got %v", err)
	}
	if got, _ := os.ReadFile(e.kr); string(got) != string(orig) {
		t.Error("first file not restored after second write failed")
	}
	if m.Complete || m.RolledBack == nil {
		t.Errorf("manifest = %+v", m)
	}
}

func TestSaveLoad(t *testing.T) {
	e := newEnv(t)
	p := New("x", t0)
	p.WriteFile(e.kr, keyringBytes(t, "daily"), 0o644)
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("plan mode %v", fi.Mode().Perm())
	}
	q, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if q.ID != p.ID || q.Steps[0].Content != p.Steps[0].Content {
		t.Error("round trip mismatch")
	}
}

func TestInstallBinary(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "usr", "local", "bin")
	os.MkdirAll(bin, 0o755)
	target := filepath.Join(bin, "yking")
	src := filepath.Join(root, "build", "yking")
	os.MkdirAll(filepath.Dir(src), 0o755)
	newBin := []byte{0x7f, 'E', 'L', 'F', 0xff, 0xfe, 0x00, 0xc3, 0x28} // not valid UTF-8
	os.WriteFile(src, newBin, 0o755)
	old := []byte{0x7f, 'E', 'L', 'F', 1}
	os.WriteFile(target, old, 0o755)

	a := &Applier{
		BackupRoot: filepath.Join(root, "backups"),
		Targets:    []Target{{Dir: bin, Validate: func(string, []byte) error { return nil }}},
		Now:        func() time.Time { return t0 },
	}
	p := New("install", t0)
	if err := p.Install(target, src, 0o755); err != nil {
		t.Fatal(err)
	}
	// Through a JSON round trip, like the real sudo apply.
	pp := filepath.Join(root, "plan.json")
	p.Save(pp)
	q, err := Load(pp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(q); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != string(newBin) {
		t.Fatalf("installed bytes differ: %x", got)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if _, err := a.Rollback(q.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != string(old) {
		t.Error("rollback did not restore the old binary")
	}

	// Source changed after planning: refused.
	p2 := New("install", t0)
	p2.Install(target, src, 0o755)
	os.WriteFile(src, []byte("tampered"), 0o755)
	if err := a.Check(p2); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Errorf("tampered source: %v", err)
	}
	// Same bytes already installed: no step.
	os.WriteFile(src, old, 0o755)
	p3 := New("install", t0)
	p3.Install(target, src, 0o755)
	if !p3.Empty() {
		t.Error("identical binary produced a step")
	}
	// setuid refused.
	// setuid: Install only takes permission bits, and a hand-edited plan
	// with special bits is refused by the elevated check.
	p4 := New("install", t0)
	os.WriteFile(src, newBin, 0o755)
	p4.Install(target, src, 0o755)
	p4.Steps[0].Mode = 0o4755
	if err := a.Check(p4); err == nil {
		t.Error("setuid install accepted")
	}
}
