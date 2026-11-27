package pam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
)

var t0 = time.Date(2026, 11, 26, 23, 30, 0, 0, time.UTC)

// fixtures copies testdata (this machine's real PAM files) to a temp dir.
func fixtures(t *testing.T) (etc, vendor string) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"etc", "vendor"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
		ents, _ := os.ReadDir(filepath.Join("testdata", d))
		for _, e := range ents {
			b, _ := os.ReadFile(filepath.Join("testdata", d, e.Name()))
			os.WriteFile(filepath.Join(root, d, e.Name()), b, 0o644)
		}
	}
	return filepath.Join(root, "etc"), filepath.Join(root, "vendor")
}

func discoverMap(t *testing.T) map[string]State {
	t.Helper()
	etc, vendor := fixtures(t)
	sts, err := Discover(etc, vendor)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]State{}
	for _, s := range sts {
		m[s.Service.Name] = s
	}
	return m
}

func TestParseBrackets(t *testing.T) {
	ls, err := Parse("#%PAM-1.0\n-auth      [success=2 default=ignore]  pam_systemd_home.so\nauth include system-auth\n")
	if err != nil {
		t.Fatal(err)
	}
	if !ls[0].Comment || !ls[1].Optional || ls[1].Control != "[success=2 default=ignore]" || ls[1].Module != "pam_systemd_home.so" {
		t.Errorf("got %+v", ls[1])
	}
	if !ls[2].IsInclude() || ls[2].Module != "system-auth" {
		t.Errorf("include = %+v", ls[2])
	}
	for _, bad := range []string{"auth", "bogus sufficient x.so", "auth [success=1 x.so"} {
		if _, err := Parse(bad + "\n"); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestDiscoverThisMachine(t *testing.T) {
	m := discoverMap(t)
	want := map[string]Config{
		"sudo":     {Mode: ModeOr, Unlock: UnlockPIN},
		"sddm":     {Mode: ModeOr, Unlock: UnlockPIN},
		"kde":      {Mode: ModeOnly, Unlock: UnlockPIN}, // the one-line override
		"polkit-1": {Mode: ModeOff},
		"login":    {Mode: ModeOff},
	}
	for name, cfg := range want {
		s, ok := m[name]
		if !ok {
			t.Errorf("%s not discovered", name)
			continue
		}
		if s.Custom != "" || s.Current.Mode != cfg.Mode || (cfg.Mode != ModeOff && s.Current.Unlock != cfg.Unlock) {
			t.Errorf("%s: got %+v custom=%q, want %+v", name, s.Current, s.Custom, cfg)
		}
		if s.Managed {
			t.Errorf("%s: hand-written line reported as managed", name)
		}
	}
	if m["polkit-1"].Source == m["polkit-1"].Path {
		t.Error("polkit-1 should come from the vendor dir")
	}
	if _, ok := m["systemd-run0"]; ok {
		t.Error("absent service discovered")
	}
}

func TestTakeOverKeepsBehaviour(t *testing.T) {
	m := discoverMap(t)
	for _, name := range []string{"sudo", "sddm", "kde"} {
		s := m[name]
		out, err := s.Render(s.Current)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ls, _ := Parse(out)
		got, ok, why := Classify(ls)
		if !ok || got.Mode != s.Current.Mode || got.Unlock != s.Current.Unlock {
			t.Errorf("%s: re-classified as %+v (%s), want %+v", name, got, why, s.Current)
		}
		if !strings.Contains(out, markerPrefix) {
			t.Errorf("%s: no marker", name)
		}
	}
	// kde is rebuilt on the vendor file and stays key-only.
	kde, _ := m["kde"].Render(m["kde"].Current)
	if !strings.Contains(kde, "auth [success=done default=die] pam_u2f.so pinverification=1 userpresence=0 cue") ||
		!strings.Contains(kde, "include                     system-local-login") {
		t.Errorf("kde takeover:\n%s", kde)
	}
	// sudo: yking line replaces the hand-written one at the same place.
	sudo, _ := m["sudo"].Render(m["sudo"].Current)
	ls, _ := Parse(sudo)
	if !ls[1].Comment || !ls[2].IsU2F() || ls[2].Control != "sufficient" || !ls[3].IsInclude() {
		t.Errorf("sudo takeover order:\n%s", sudo)
	}
	if strings.Count(sudo, "pam_u2f.so") != 1 {
		t.Errorf("duplicate pam_u2f lines:\n%s", sudo)
	}
}

func TestModesRender(t *testing.T) {
	m := discoverMap(t)
	s := m["sudo"]

	and, err := s.Render(Config{Mode: ModeAnd, Unlock: UnlockPINTouch})
	if err != nil {
		t.Fatal(err)
	}
	ls, _ := Parse(and)
	var order []string
	for _, l := range ls {
		if l.IsAuth() {
			order = append(order, l.Module)
		}
	}
	if strings.Join(order, ",") != "system-auth,pam_u2f.so" {
		t.Errorf("password + key order = %v", order)
	}
	if !strings.Contains(and, "auth required pam_u2f.so pinverification=1 userpresence=1 cue") {
		t.Errorf("and:\n%s", and)
	}

	off, _ := s.Render(Config{Mode: ModeOff})
	if strings.Contains(off, "pam_u2f") || strings.Contains(off, "yking") {
		t.Errorf("off still has u2f:\n%s", off)
	}

	// Polkit (vendor only): "key or password" before its auth include.
	p := m["polkit-1"]
	or, err := p.Render(Config{Mode: ModeOr, Unlock: UnlockTouch})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(or, "auth sufficient pam_u2f.so pinverification=0 userpresence=1 cue") {
		t.Errorf("polkit:\n%s", or)
	}

	if _, err := Apply(nil, Config{Mode: ModeOr}); err == nil {
		t.Error("or without a password rule accepted")
	}
	if _, err := Apply(nil, Config{Mode: ModeAnd}); err == nil {
		t.Error("and without a password rule accepted")
	}
}

func TestClassifyCustom(t *testing.T) {
	for _, c := range []string{
		"auth sufficient pam_u2f.so\nauth sufficient pam_u2f.so\nauth include system-auth\n",
		"auth include system-auth\nauth sufficient pam_u2f.so\n",
		"auth [success=1 default=bad] pam_u2f.so\nauth include system-auth\n",
		"-auth sufficient pam_u2f.so\nauth include system-auth\n",
	} {
		ls, _ := Parse(c)
		if _, ok, _ := Classify(ls); ok {
			t.Errorf("classified custom setup:\n%s", c)
		}
	}
	ls, _ := Parse("auth sufficient pam_u2f.so authfile=/etc/x cue\nauth include system-auth\n")
	cfg, ok, _ := Classify(ls)
	if !ok || cfg.Unlock != UnlockTouch || len(cfg.Extra) != 1 || cfg.Extra[0] != "authfile=/etc/x" {
		t.Errorf("extra args: %+v", cfg)
	}
	out, _ := Apply(Base(ls), cfg)
	if !strings.Contains(Render(out), "authfile=/etc/x") {
		t.Error("extra args dropped")
	}
}

func TestBuildPlan(t *testing.T) {
	etc, vendor := fixtures(t)
	sts, _ := Discover(etc, vendor)
	p, err := BuildPlan(sts, []Change{
		{"sudo", Config{Mode: ModeOr, Unlock: UnlockPIN}},     // takeover
		{"polkit-1", Config{Mode: ModeOr, Unlock: UnlockPIN}}, // new override
		{"login", Config{Mode: ModeOff}},                      // no-op
	}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 2 {
		t.Fatalf("steps = %d: %s", len(p.Steps), p.Summary())
	}
	if !p.Steps[1].ExpectAbsent || p.Steps[1].Path != filepath.Join(etc, "polkit-1") {
		t.Errorf("polkit step = %+v", p.Steps[1])
	}
	if p.Steps[0].ExpectSHA256 == "" {
		t.Error("sudo step must pin the current hash")
	}
	if _, err := BuildPlan(sts, []Change{{"login", Config{Mode: ModeOff}}}, t0); err == nil {
		t.Error("no-op plan accepted")
	}
}

func TestCheck(t *testing.T) {
	m := discoverMap(t)
	var sts []State
	for _, n := range []string{"sudo", "sddm", "kde", "polkit-1", "login"} {
		sts = append(sts, m[n])
	}
	one := Facts{ModuleInstalled: true, Credentials: 4, RegisteredKeys: 2, ConfirmedKeys: 1}
	two := Facts{ModuleInstalled: true, Credentials: 4, RegisteredKeys: 2, ConfirmedKeys: 2}

	// Taking over the existing key-only lock screen with 1 key: warn only.
	b, w := Check(sts, []Change{{"kde", m["kde"].Current}}, one)
	if len(b) != 0 || len(w) != 1 || !strings.Contains(w[0], "kde") {
		t.Errorf("kde takeover: blocks=%v warns=%v", b, w)
	}
	// Many services at once: one grouped message, not one per service.
	many := []Change{{"sudo", Config{Mode: ModeOnly}}, {"sddm", Config{Mode: ModeOnly}}, {"polkit-1", Config{Mode: ModeOnly}}}
	if b, _ := Check(sts, many, one); len(b) != 1 || !strings.Contains(b[0], "sudo, sddm, polkit-1") {
		t.Errorf("grouped blocks = %q", b)
	}
	// Switching sudo to key only / password+key with 1 key: blocked.
	for _, mode := range []Mode{ModeOnly, ModeAnd} {
		if b, _ := Check(sts, []Change{{"sudo", Config{Mode: mode}}}, one); len(b) == 0 {
			t.Errorf("sudo → %s with one key allowed", mode)
		}
	}
	if b, _ := Check(sts, []Change{{"sudo", Config{Mode: ModeAnd}}}, two); len(b) != 0 {
		t.Errorf("two keys should allow password + key: %v", b)
	}
	// No password path left.
	all := []Change{{"sudo", Config{Mode: ModeOnly}}, {"sddm", Config{Mode: ModeOnly}}, {"login", Config{Mode: ModeAnd}}}
	if b, _ := Check(sts, all, two); len(b) == 0 || !strings.Contains(strings.Join(b, "|"), "No way in with a password") {
		t.Errorf("no password path: %v", b)
	}
	// No credentials / module.
	if b, _ := Check(sts, []Change{{"polkit-1", Config{Mode: ModeOr}}}, Facts{ModuleInstalled: true}); len(b) == 0 {
		t.Error("enable without credentials allowed")
	}
	if b, _ := Check(sts, []Change{{"polkit-1", Config{Mode: ModeOr}}}, Facts{Credentials: 4, RegisteredKeys: 2}); len(b) == 0 {
		t.Error("enable without module allowed")
	}
}

func TestValidate(t *testing.T) {
	etc, vendor := fixtures(t)
	mods := t.TempDir()
	for _, mod := range []string{"pam_u2f.so", "pam_unix.so", "pam_systemd.so"} {
		os.WriteFile(filepath.Join(mods, mod), nil, 0o644)
	}
	oldM, oldI := ModuleDirs, IncludeDirs
	ModuleDirs, IncludeDirs = []string{mods}, []string{etc, vendor}
	defer func() { ModuleDirs, IncludeDirs = oldM, oldI }()

	good := "auth sufficient pam_u2f.so cue\nauth include system-auth\nsession optional pam_systemd.so\n-auth optional pam_missing.so\n"
	if err := Validate("/etc/pam.d/sudo", []byte(good)); err != nil {
		t.Errorf("good file: %v", err)
	}
	for name, bad := range map[string]string{
		"missing module":  "auth required pam_nothere.so\n",
		"missing include": "auth include no-such-service\n",
		"empty":           "# only a comment\n",
		"unparseable":     "auth\n",
		"custom u2f":      "auth include system-auth\nauth sufficient pam_u2f.so\n",
	} {
		if err := Validate("/etc/pam.d/x", []byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCountCredentials(t *testing.T) {
	p := filepath.Join(t.TempDir(), "u2f_keys")
	os.WriteFile(p, []byte("alice:kh1,pk1,es256,:kh2,pk2,es256,+presence\nother:kh3,pk3,es256,\n"), 0o644)
	if n, _ := CountCredentials(p, "alice"); n != 2 {
		t.Errorf("alice = %d", n)
	}
	if n, _ := CountCredentials(p, "nobody"); n != 0 {
		t.Errorf("nobody = %d", n)
	}
	if n, err := CountCredentials(p+"-missing", "alice"); n != 0 || err != nil {
		t.Errorf("missing = %d %v", n, err)
	}
}

func TestMapping(t *testing.T) {
	m, err := ParseMapping("alice:khA,pkA,es256,:khB,pkB,es256,+presence\nother:khC,pkC,es256,\n")
	if err != nil {
		t.Fatal(err)
	}
	if c := m.Creds("alice"); len(c) != 2 || c[1].KeyHandle != "khB" || c[1].Options != "+presence" {
		t.Fatalf("creds = %+v", c)
	}
	newC, _ := ParseCred("khD,pkD,es256,")
	if err := m.Append("alice", newC); err != nil {
		t.Fatal(err)
	}
	if err := m.Append("alice", newC); err == nil {
		t.Error("duplicate key handle accepted")
	}
	m.Append("fresh", newC)
	want := "alice:khA,pkA,es256,:khB,pkB,es256,+presence:khD,pkD,es256,\nother:khC,pkC,es256,\nfresh:khD,pkD,es256,\n"
	if m.String() != want {
		t.Errorf("got %q\nwant %q", m.String(), want)
	}
	for _, bad := range []string{"alice\n", "alice:kh\n", "alice:k h,pk,es256\n", "alice:a,b,c\nalice:d,e,f\n"} {
		if _, err := ParseMapping(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := ValidateMapping("/home/u/.config/Yubico/u2f_keys", []byte(want)); err != nil {
		t.Error(err)
	}
	if err := ValidateMapping("/home/u/.bashrc", []byte(want)); err == nil {
		t.Error("validator accepted another file")
	}
}

func TestRegisterOutputAndArgs(t *testing.T) {
	c, err := ParseRegisterOutput([]byte("Please touch the device.\n:khN,pkN,es256,\n"))
	if err != nil || c.KeyHandle != "khN" || c.Raw != "khN,pkN,es256," {
		t.Fatalf("got %+v %v", c, err)
	}
	if _, err := ParseRegisterOutput([]byte("error\n")); err == nil {
		t.Error("garbage accepted")
	}
	a := strings.Join(RegisterArgs("pam://myhost"), " ")
	if a != "-n -P -o pam://myhost -i pam://myhost" || strings.Contains(a, "-r") {
		t.Errorf("args = %q (must be non-resident)", a)
	}
}

func TestRecordCredsAndCoverage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.toml")
	kr := keyring.New()
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0)
	kr.Add("33333333", "offsite", keyring.RoleOffsite, t0)
	kr.Keys[1].U2F = []keyring.U2FCred{{User: "alice", KeyHandle: "khC", CreatedAt: t0}} // wrongly recorded earlier
	kr.Save(path)

	p, err := RecordCredsPlan(path, "22222222", "alice", []string{"khC"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := keyring.Parse([]byte(p.Steps[0].Content))
	if len(got.Keys[0].U2F) != 1 || len(got.Keys[1].U2F) != 0 {
		t.Errorf("handle not moved: %+v", got.Keys)
	}
	os.WriteFile(path, []byte(p.Steps[0].Content), 0o644)
	if _, err := RecordCredsPlan(path, "22222222", "alice", []string{"khC"}, t0); err != plan.ErrNoChanges {
		t.Errorf("second record: %v", err)
	}

	m, _ := ParseMapping("alice:khC,pk,es256,\n")
	cov := Coverage(got, m, "alice")
	if !cov["22222222"] || cov["33333333"] {
		t.Errorf("coverage = %v", cov)
	}
	m2, _ := ParseMapping("alice:other,pk,es256,\n") // credential removed from mapping
	if Coverage(got, m2, "alice")["22222222"] {
		t.Error("coverage must require the handle to still be in the mapping")
	}
}

func TestMappingRemove(t *testing.T) {
	m, _ := ParseMapping("alice:khA,pkA,es256,:khB,pkB,es256,:khC,pkC,es256,\nother:khA,pkA,es256,\n")
	if n := m.Remove("alice", []string{"khA", "khC", "nope"}); n != 2 {
		t.Errorf("removed %d", n)
	}
	if m.String() != "alice:khB,pkB,es256,\nother:khA,pkA,es256,\n" {
		t.Errorf("got %q", m.String())
	}
	m.Remove("alice", []string{"khB"})
	if m.String() != "other:khA,pkA,es256,\n" {
		t.Errorf("empty user line not dropped: %q", m.String())
	}
}

// Regression (host lockout 2026-11-27): lock screens always get
// "interactive"; the hand-written key-only lock screen is a lockout risk.
func TestLockScreenInteractive(t *testing.T) {
	m := discoverMap(t)
	kde := m["kde"]
	if !kde.Service.LockScreen || !kde.LockoutRisk() {
		t.Fatalf("this machine's key-only lock screen must be flagged: %+v", kde)
	}
	out, err := kde.Render(kde.Current)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pam_u2f.so pinverification=1 userpresence=0 cue interactive") {
		t.Errorf("kde without interactive:\n%s", out)
	}
	ls, _ := Parse(out)
	cfg, ok, _ := Classify(ls)
	if !ok || !cfg.Interactive || len(cfg.Extra) != 0 {
		t.Errorf("re-classified: %+v", cfg)
	}
	fixed := kde
	fixed.Current = cfg
	if fixed.LockoutRisk() {
		t.Error("fixed lock screen still flagged")
	}
	// Non-lock-screen services do not get it.
	sudo, _ := m["sudo"].Render(Config{Mode: ModeOnly, Unlock: UnlockPIN})
	if strings.Contains(sudo, "interactive") {
		t.Errorf("sudo got interactive:\n%s", sudo)
	}
}

// Regression (Flatpak "Deploy not allowed", 2026-11-27): when polkit would
// authenticate root, key-only polkit must be refused (new) or warned (kept).
func TestPolkitAsksRoot(t *testing.T) {
	m := discoverMap(t)
	sts := []State{m["sudo"], m["login"], m["polkit-1"]}
	f := Facts{ModuleInstalled: true, Credentials: 3, RegisteredKeys: 3, ConfirmedKeys: 3, PolkitAsksRoot: true}
	b, _ := Check(sts, []Change{{"polkit-1", Config{Mode: ModeOnly}}}, f)
	if !strings.Contains(strings.Join(b, "|"), "polkit asks for ROOT") {
		t.Errorf("blocks = %v", b)
	}
	if b, _ := Check(sts, []Change{{"polkit-1", Config{Mode: ModeOr}}}, f); len(b) != 0 {
		t.Errorf("key or password must stay allowed: %v", b)
	}
	f.PolkitAsksRoot = false
	if b, _ := Check(sts, []Change{{"polkit-1", Config{Mode: ModeOnly}}}, f); len(b) != 0 {
		t.Errorf("wheel member: %v", b)
	}
}
