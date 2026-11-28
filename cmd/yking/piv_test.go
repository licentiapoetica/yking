package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/licentiapoetica/yking/internal/runner"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// fakePIV is a YubiKey whose PIV defaults flip when changed.
type fakePIV struct {
	pin, puk, mgmt bool // still default
	stdin          []string
}

func (f *fakePIV) Run(ctx context.Context, name string, args ...string) (runner.Result, error) {
	return f.RunStdin(ctx, nil, name, args...)
}

func (f *fakePIV) RunStdin(_ context.Context, stdin []byte, _ string, args ...string) (runner.Result, error) {
	a := strings.Join(args, " ")
	switch {
	case a == "list --serials":
		return runner.Result{Stdout: []byte("11111111\n")}, nil
	case strings.HasSuffix(a, "piv info"):
		out := "PIV version: 5.7.1\nPIN tries remaining: 3/3\nPUK tries remaining: 3/3\nManagement key algorithm: AES192\n"
		if f.pin {
			out += "WARNING: Using default PIN!\n"
		}
		if f.puk {
			out += "WARNING: Using default PUK!\n"
		}
		if f.mgmt {
			out += "WARNING: Using default Management key!\n"
		} else {
			out += "Management key is stored on the YubiKey, protected by PIN.\n"
		}
		return runner.Result{Stdout: []byte(out)}, nil
	case strings.HasSuffix(a, "change-pin"):
		f.pin = false
	case strings.HasSuffix(a, "change-puk"):
		f.puk = false
	case strings.HasSuffix(a, "--protect"):
		f.mgmt = false
	default:
		return runner.Result{}, errors.New("unexpected " + a)
	}
	f.stdin = append(f.stdin, string(stdin))
	return runner.Result{}, nil
}

func answers(a ...string) (func(string) (string, error), *[]string) {
	var asked []string
	return func(p string) (string, error) {
		asked = append(asked, p)
		if len(a) == 0 {
			return "", errors.New("cancelled")
		}
		v := a[0]
		a = a[1:]
		return v, nil
	}, &asked
}

func TestPIVDefaultsAll(t *testing.T) {
	f := &fakePIV{pin: true, puk: true, mgmt: true}
	ask, asked := answers("246813", "246813", "97531864", "97531864")
	if err := pivDefaults(context.Background(), ykman.New(f), "11111111", "offsite", ask, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 4 || !strings.HasPrefix((*asked)[0], "New PIV PIN") || !strings.HasPrefix((*asked)[2], "New PIV PUK") {
		t.Fatalf("asked %q", *asked)
	}
	want := []string{"123456\n246813\n", "12345678\n97531864\n", "\n246813\n"}
	if strings.Join(f.stdin, "|") != strings.Join(want, "|") {
		t.Fatalf("stdin %q", f.stdin)
	}
}

// A cancelled or bad answer changes nothing: all questions come first.
func TestPIVDefaultsNothingOnCancel(t *testing.T) {
	for _, a := range [][]string{
		{"246813", "246813"},             // PUK cancelled
		{"246813", "246814"},             // repeat differs
		{"246813", "246813", "246813"},   // PUK = PIN
		{"123456"},                       // default PIN again
		{"246813", "246813", "12345678"}, // default PUK again
	} {
		f := &fakePIV{pin: true, puk: true, mgmt: true}
		ask, _ := answers(a...)
		if err := pivDefaults(context.Background(), ykman.New(f), "11111111", "offsite", ask, func(string) {}); err == nil || len(f.stdin) != 0 {
			t.Errorf("%q: err %v, ran %q", a, err, f.stdin)
		}
	}
}

// PIN already changed: only the management key, with the user's PIN.
func TestPIVDefaultsMgmtOnly(t *testing.T) {
	f := &fakePIV{mgmt: true}
	ask, asked := answers("246813")
	if err := pivDefaults(context.Background(), ykman.New(f), "11111111", "offsite", ask, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 1 || !strings.HasPrefix((*asked)[0], "PIV PIN of offsite") || len(f.stdin) != 1 || f.stdin[0] != "\n246813\n" {
		t.Fatalf("asked %q stdin %q", *asked, f.stdin)
	}
}
