package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yking/internal/plan"
)

func appliedPAM(t *testing.T, name string) (*plan.Applier, *plan.Manifest, string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "pam.d")
	os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, name)
	orig := "auth include system-auth\n"
	os.WriteFile(path, []byte(orig), 0o644)
	a := &plan.Applier{
		BackupRoot: filepath.Join(root, "backups"),
		Targets:    []plan.Target{{Dir: dir, Validate: func(string, []byte) error { return nil }}},
		Now:        time.Now,
	}
	p := plan.New("test", time.Now())
	p.WriteFile(path, []byte("auth sufficient pam_u2f.so\nauth include system-auth\n"), 0o644)
	m, err := a.Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	return a, m, path, orig
}

func stubSudo(t *testing.T, err error) *int {
	calls := 0
	old := testSudo
	testSudo = func() error { calls++; return err }
	t.Cleanup(func() { testSudo = old })
	return &calls
}

func TestDeadmanKeep(t *testing.T) {
	a, m, path, orig := appliedPAM(t, "kde")
	var out bytes.Buffer
	if err := deadman(a, m, strings.NewReader("x\n7\nk\n"), &out); err != nil { // other keys ignored
		t.Fatalf("keep: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) == orig {
		t.Error("change was rolled back despite keep")
	}
}

func TestDeadmanRollsBack(t *testing.T) {
	stubSudo(t, nil)
	for name, c := range map[string]struct{ svc, input string }{
		"r pressed":            {"kde", "r\n"},
		"other keys then eof":  {"kde", "yes\n123\n"},
		"input closed":         {"kde", ""},
		"sudo skipped, then r": {"sudo", "n\nr\n"},
		"r at sudo question":   {"sudo", "r\n"},
	} {
		a, m, path, orig := appliedPAM(t, c.svc)
		var out bytes.Buffer
		err := deadman(a, m, strings.NewReader(c.input), &out)
		if err == nil || !strings.Contains(err.Error(), "rolled back") {
			t.Errorf("%s: err = %v", name, err)
		}
		if b, _ := os.ReadFile(path); string(b) != orig {
			t.Errorf("%s: file not restored:\n%s", name, b)
		}
	}
}

// Regression: a PIN typed at the wrong moment was printed back in the
// rollback message. Input must never appear in output or errors.
func TestDeadmanNeverEchoesInput(t *testing.T) {
	calls := stubSudo(t, nil)
	// A PIN typed at the sudo question must not start the test.
	a0, m0, _, _ := appliedPAM(t, "sudo")
	deadman(a0, m0, strings.NewReader("834159\n"), new(bytes.Buffer))
	if *calls != 0 {
		t.Errorf("digits started the sudo test")
	}
	const secret = "834159"
	for _, input := range []string{secret + "\n", "\n" + secret + "\n", "n\n" + secret + "\nr\n"} {
		a, m, _, _ := appliedPAM(t, "sudo")
		var out bytes.Buffer
		err := deadman(a, m, strings.NewReader(input), &out)
		if strings.Contains(out.String(), secret) || (err != nil && strings.Contains(err.Error(), secret)) {
			t.Errorf("input leaked:\nout=%q\nerr=%v", out.String(), err)
		}
	}
}

// The sudo test must run only after the Y/n answer was read, and before
// anything else consumes input (it owns the terminal).
func TestDeadmanSudoTestOrder(t *testing.T) {
	calls := stubSudo(t, errors.New("auth failed"))
	a, m, path, orig := appliedPAM(t, "sudo")
	var out bytes.Buffer
	err := deadman(a, m, strings.NewReader("\n"), &out)
	if *calls != 1 || err == nil || !strings.Contains(out.String(), "sudo test FAILED") {
		t.Fatalf("calls=%d err=%v out=%q", *calls, err, out.String())
	}
	if b, _ := os.ReadFile(path); string(b) != orig {
		t.Error("failed sudo test did not roll back")
	}
}
