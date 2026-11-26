package detect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/runner"
	"github.com/licentiapoetica/yking/internal/ykman"
)

type fakeRunner struct {
	out   map[string]string
	calls []string
}

func (f *fakeRunner) Run(_ context.Context, _ string, args ...string) (runner.Result, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if s, ok := f.out[key]; ok {
		return runner.Result{Stdout: []byte(s)}, nil
	}
	return runner.Result{ExitCode: 1}, &runner.ExitError{Name: "fake", Code: 1, Stderr: "no fixture for " + key}
}

func fx(t *testing.T, name string) string {
	b, err := os.ReadFile(filepath.Join("../ykman/testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestScan(t *testing.T) {
	fr := &fakeRunner{out: map[string]string{
		"--version":                   fx(t, "version.txt"),
		"list":                        fx(t, "list.txt"),
		"list --serials":              fx(t, "list_serials.txt"),
		"--device 12345678 info":      fx(t, "info.txt"),
		"--device 12345678 fido info": fx(t, "fido_info.txt"),
		"--device 12345678 otp info":  fx(t, "otp_info.txt"),
		"--device 23456789 info":      fx(t, "info.txt"),
		"--device 23456789 fido info": "PIN: 2 attempt(s) remaining\n",
		// 23456789 otp info missing -> partial error
	}}
	kr := keyring.New()
	kr.Add("12345678", "daily", keyring.RoleDaily, time.Now())
	kr.Add("99999999", "offsite", keyring.RoleOffsite, time.Now())

	rep, err := Scan(context.Background(), ykman.New(fr), kr)
	if err != nil {
		t.Fatal(err)
	}
	if rep.YkmanVersion != "5.9.2" {
		t.Errorf("version %q", rep.YkmanVersion)
	}
	if len(rep.Keys) != 2 || len(rep.Unidentified) != 1 || len(rep.Missing) != 1 {
		t.Fatalf("keys=%d unidentified=%d missing=%d", len(rep.Keys), len(rep.Unidentified), len(rep.Missing))
	}
	k0, k1 := rep.Keys[0], rep.Keys[1]
	if k0.Known == nil || k0.Known.Label != "daily" || k0.FIDO.PINRetries != 8 || len(k0.Warnings()) != 0 {
		t.Errorf("k0 = %+v warnings=%v", k0, k0.Warnings())
	}
	if k1.Known != nil || len(k1.Errors) != 1 {
		t.Errorf("k1 = %+v", k1)
	}
	w := strings.Join(k1.Warnings(), "|")
	if !strings.Contains(w, "only 2 PIN attempt") || !strings.Contains(w, "not in keyring") {
		t.Errorf("k1 warnings = %s", w)
	}
	for _, c := range fr.calls {
		if _, err := ykman.Check(strings.Fields(c)); err != nil {
			t.Errorf("scan issued non-allowlisted call %q", c)
		}
	}
}
