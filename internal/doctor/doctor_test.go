package doctor

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/ykman"
)

var now = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

func baseInputs(t *testing.T) Inputs {
	t.Helper()
	kr := keyring.New()
	kr.Add("11111111", "daily", keyring.RoleDaily, now)
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, now)
	kr.Add("33333333", "offsite", keyring.RoleOffsite, now)
	kr.Find("11111111").U2F = []keyring.U2FCred{{User: "alice", KeyHandle: "kh1"}}
	kr.Find("22222222").U2F = []keyring.U2FCred{{User: "alice", KeyHandle: "kh3"}}
	kr.Find("33333333").U2F = []keyring.U2FCred{{User: "alice", KeyHandle: "kh4"}}
	m, _ := pam.ParseMapping("alice:kh1,p,es256,:kh3,p,es256,:kh4,p,es256,\n")
	return Inputs{
		Now: now, User: "alice", Keyring: kr, Mapping: m, MappingPath: "/home/alice/.config/Yubico/u2f_keys", MappingMode: 0o644,
		ModuleInstalled: true,
		PAM: []pam.State{
			{Service: pam.Service{Name: "sudo", LoginPath: true}, Current: pam.Config{Mode: pam.ModeOnly}, Managed: true},
			{Service: pam.Service{Name: "login", LoginPath: true}, Current: pam.Config{Mode: pam.ModeOr}, Managed: true},
		},
		Tests: map[string]time.Time{"11111111": now, "22222222": now, "33333333": now},
	}
}

func messages(f []Finding, min Severity) string {
	var s []string
	for _, x := range f {
		if x.Severity >= min {
			s = append(s, x.Severity.String()+": "+x.Message)
		}
	}
	return strings.Join(s, "\n")
}

func TestHealthy(t *testing.T) {
	f := Run(baseInputs(t))
	if w := Worst(f); w > Info {
		t.Errorf("healthy setup reported problems:\n%s", messages(f, Warn))
	}
}

func TestFindsProblems(t *testing.T) {
	cases := map[string]struct {
		mod  func(*Inputs)
		want string
		sev  Severity
	}{
		"offsite untested": {func(in *Inputs) { in.Tests["33333333"] = now.Add(-100 * 24 * time.Hour) }, `"offsite" last tested`, Warn},
		"never tested":     {func(in *Inputs) { delete(in.Tests, "22222222") }, "never been tested", Info},
		"unknown cred": {func(in *Inputs) {
			in.Mapping, _ = pam.ParseMapping("alice:kh1,p,es256,:kh3,p,es256,:kh4,p,es256,:kh9,p,es256,\n")
		}, "credential #4 belongs to no registered key", Warn},
		"one confirmed": {func(in *Inputs) {
			in.Mapping, _ = pam.ParseMapping("alice:kh1,p,es256,\n")
		}, "only daily is confirmed", Warn},
		"no password door": {func(in *Inputs) { in.PAM[1].Current.Mode = pam.ModeOnly }, "no login path accepts the password", Error},
		"mapping writable": {func(in *Inputs) { in.MappingMode = 0o666 }, "writable by others", Error},
		"pub 0777": {func(in *Inputs) {
			in.SSHFiles = []File{{"/home/alice/.ssh/id_ed25519.pub", 0o777}}
		}, "id_ed25519.pub is writable by others", Warn},
		"private readable": {func(in *Inputs) { in.SSHFiles = []File{{"/home/alice/.ssh/id_ed25519", 0o644}} }, "readable by others", Warn},
		"authorized_keys": {func(in *Inputs) {
			in.SSHFiles = []File{{"/home/alice/.ssh/authorized_keys", 0o666}}
		}, "anyone could add a login key", Error},
		"pin tries": {func(in *Inputs) {
			in.Connected = []detect.KeyReport{{Serial: "1", FIDO: &ykman.FIDOInfo{PINSet: true, PINRetries: 6}}}
		}, "6 of 8 PIN tries", Warn},
		"pin low": {func(in *Inputs) {
			in.Connected = []detect.KeyReport{{Serial: "1", FIDO: &ykman.FIDOInfo{PINSet: true, PINRetries: 2}}}
		}, "only 2 PIN tries", Error},
		"pam edited": {func(in *Inputs) {
			in.PAMWrites = []PAMWrite{{Path: "/etc/pam.d/sudo", WrittenSHA256: "a", CurrentSHA256: "b"}}
		}, "changed after yking wrote it", Warn},
		"stale binary": {func(in *Inputs) {
			in.Events = Events{Configured: true, BinaryInstalled: true, RuleExists: true, RuleCurrent: true, UnitExists: true, UnitCurrent: true}
		}, "older than this yking", Warn},
		"single-key host": {func(in *Inputs) {
			in.Keyring.Find("22222222").SSH = []keyring.SSHKey{{Comment: "yk-main-02", Hosts: []string{"user@server.example"}}}
		}, `user@server.example accepts only "home-backup"`, Warn},
		"revoked leftover": {func(in *Inputs) {
			in.Keyring.Revoked = []keyring.RevokedKey{{Label: "old", Leftovers: []keyring.Leftover{{Comment: "yk-main-00", Host: "nas"}}}}
		}, "still on nas", Warn},
		"one key": {func(in *Inputs) { in.Keyring.Keys = in.Keyring.Keys[:1] }, "only one key registered", Warn},
		"lockout combo": {func(in *Inputs) {
			in.PAM = append(in.PAM, pam.State{Service: pam.Service{Name: "kde", Desc: "KDE lock screen", LockScreen: true}, Current: pam.Config{Mode: pam.ModeOnly}})
			in.Events = Events{Configured: true, LockOnRemove: true, BinaryInstalled: true, BinaryCurrent: true, RuleExists: true, RuleCurrent: true, UnitExists: true, UnitCurrent: true}
		}, "cannot unlock after pulling the key", Error},
	}
	for name, c := range cases {
		in := baseInputs(t)
		c.mod(&in)
		f := Run(in)
		found := false
		for _, x := range f {
			if strings.Contains(x.Message, c.want) && x.Severity == c.sev {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want %s %q, got:\n%s", name, c.sev, c.want, messages(f, Info))
		}
		if f[0].Severity < f[len(f)-1].Severity {
			t.Errorf("%s: not sorted most severe first", name)
		}
	}
}

func TestCoverage(t *testing.T) {
	in := baseInputs(t)
	in.Keyring.Find("11111111").SSH = []keyring.SSHKey{{Hosts: []string{"a", "b"}}, {Hosts: []string{"a"}}}
	in.Mapping, _ = pam.ParseMapping("alice:kh1,p,es256,\n")
	in.Connected = []detect.KeyReport{{Serial: "11111111"}}
	rows := Coverage(in)
	if len(rows) != 3 || !rows[0].PAM || rows[1].PAM || rows[0].SSHKeys != 2 || len(rows[0].Hosts) != 2 || !rows[0].Connected {
		t.Errorf("rows = %+v", rows)
	}
}

func TestRecordTest(t *testing.T) {
	home := t.TempDir()
	if err := RecordTest(home, "33333333", now); err != nil {
		t.Fatal(err)
	}
	if got := LoadTests(home)["33333333"]; !got.Equal(now) {
		t.Errorf("got %v", got)
	}
	_ = fs.ModePerm
}
