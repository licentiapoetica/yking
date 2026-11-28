package ykman

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParsePIVInfo(t *testing.T) {
	p := parsePIVInfo(fixture(t, "piv_info.txt"))
	if p.Version != "5.7.1" || p.PINTries != 2 || p.PUKTries != 3 || p.MgmtAlgo != "AES192" {
		t.Fatalf("%+v", p)
	}
	if p.DefaultPIN || !p.DefaultPUK || p.DefaultMgmt || !p.MgmtStored {
		t.Fatalf("defaults %+v", p)
	}
	if len(p.Slots) != 2 {
		t.Fatalf("slots %+v", p.Slots)
	}
	if s := p.Slots["9a"]; s.KeyType != "ECCP256" || s.Subject != "CN=alice" || !strings.HasPrefix(s.NotAfter, "2036-") {
		t.Fatalf("9a %+v", s)
	}
	if s := p.Slots["82"]; s.KeyType != "X25519" || s.Subject != "" {
		t.Fatalf("82 %+v", s)
	}
	d := parsePIVInfo(fixture(t, "piv_info_default.txt"))
	if !d.DefaultPIN || !d.DefaultPUK || !d.DefaultMgmt || len(d.Slots) != 0 || !d.AnyDefault() {
		t.Fatalf("%+v", d)
	}
	k := parsePIVKey(fixture(t, "piv_key_info.txt"))
	if k.Algorithm != "ECCP256" || !k.Generated || k.PIN != "ONCE" || k.Touch != "ALWAYS" {
		t.Fatalf("%+v", k)
	}
}

func TestPIVPINPrompt(t *testing.T) {
	for tries, want := range map[int]bool{-1: false, 0: false, 1: false, 2: true, 3: true} {
		if ok, _ := (PIVInfo{PINTries: tries}).PINPromptAllowed(); ok != want {
			t.Errorf("tries %d: %v", tries, ok)
		}
	}
}

func TestPIVPolicy(t *testing.T) {
	for _, args := range [][]string{
		{"--device", "11111111", "piv", "info"},
		{"--device", "11111111", "piv", "keys", "info", "9a"},
		{"--device", "11111111", "piv", "keys", "info", "95"},
	} {
		if k, err := Check(args); err != nil || k != ReadOnly {
			t.Errorf("Check(%v) = %v, %v", args, k, err)
		}
	}
	for _, args := range [][]string{
		{"--device", "11111111", "piv", "access", "change-pin"},
		{"--device", "11111111", "piv", "access", "change-puk"},
		{"--device", "11111111", "piv", "access", "change-management-key", "--protect"},
	} {
		if k, err := Check(args); err != nil || k != FromDefault {
			t.Errorf("Check(%v) = %v, %v", args, k, err)
		}
	}
	for _, args := range [][]string{
		{"--device", "11111111", "piv", "reset"},
		{"--device", "11111111", "piv", "reset", "-f"},
		{"--device", "11111111", "piv", "access", "change-pin", "-P", "123456", "-n", "654321"},
		{"--device", "11111111", "piv", "access", "change-puk", "-n", "87654321"},
		{"--device", "11111111", "piv", "access", "change-management-key"},
		{"--device", "11111111", "piv", "access", "change-management-key", "--protect", "-f"},
		{"--device", "11111111", "piv", "access", "unblock-pin"},
		{"--device", "11111111", "piv", "access", "set-retries", "5", "5"},
		{"--device", "11111111", "piv", "keys", "delete", "9a"},
		{"--device", "11111111", "piv", "keys", "info", "96"},
		{"--device", "11111111", "piv", "keys", "info", "9A"},
		{"piv", "access", "change-pin"},
		{"--device", "11111111", "fido", "access", "change-pin"},
	} {
		if _, err := Check(args); !errors.As(err, new(*PolicyError)) {
			t.Errorf("Check(%v) = %v, want PolicyError", args, err)
		}
	}
}

// Writes never go through the plain run path.
func TestRunRefusesWrites(t *testing.T) {
	fr := &fakeRunner{}
	if _, err := New(fr).run(context.Background(), "--device", "11111111", "piv", "access", "change-pin"); !errors.As(err, new(*PolicyError)) {
		t.Fatalf("got %v", err)
	}
	if _, err := New(fr).run(context.Background(), "--device", "11111111", "otp", "delete", "2"); !errors.As(err, new(*PolicyError)) {
		t.Fatalf("got %v", err)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("ran %v", fr.calls)
	}
}

func pivRunner(info string) *stdinRunner {
	return &stdinRunner{fakeRunner: fakeRunner{out: map[string][]byte{"--device 11111111 piv info": []byte(info)}}}
}

func TestPIVChangesOnlyFromDefault(t *testing.T) {
	ctx := context.Background()
	changed := "PIV version: 5.7.1\nPIN tries remaining: 3/3\nPUK tries remaining: 3/3\nManagement key algorithm: AES192\nManagement key is stored on the YubiKey, protected by PIN.\n"
	r := pivRunner(changed)
	c := New(r)
	for _, err := range []error{
		c.ChangePIVPIN(ctx, "11111111", "246813"),
		c.ChangePIVPUK(ctx, "11111111", "97531864"),
		c.ProtectPIVManagementKey(ctx, "11111111", "246813"),
	} {
		if !errors.Is(err, ErrNotDefault) {
			t.Errorf("got %v, want ErrNotDefault", err)
		}
	}
	if r.stdin != nil {
		t.Fatalf("stdin sent: %q", r.stdin)
	}

	def := string(fixture(t, "piv_info_default.txt"))
	for _, tc := range []struct {
		run   func(*Client) error
		call  string
		stdin string
	}{
		{func(c *Client) error { return c.ChangePIVPIN(ctx, "11111111", "246813") }, "piv access change-pin", "123456\n246813\n"},
		{func(c *Client) error { return c.ChangePIVPUK(ctx, "11111111", "97531864") }, "piv access change-puk", "12345678\n97531864\n"},
		{func(c *Client) error { return c.ProtectPIVManagementKey(ctx, "11111111", "246813") }, "piv access change-management-key --protect", "\n246813\n"},
	} {
		r := pivRunner(def)
		if err := tc.run(New(r)); err != nil {
			t.Fatal(err)
		}
		last := strings.Join(r.calls[len(r.calls)-1], " ")
		if last != "ykman --device 11111111 "+tc.call || string(r.stdin) != tc.stdin {
			t.Errorf("call %q stdin %q", last, r.stdin)
		}
	}

	for _, bad := range []string{"12345", "123456789", "123456", "12 3456", "pinä12"} {
		r := pivRunner(def)
		if err := New(r).ChangePIVPIN(ctx, "11111111", bad); err == nil || r.stdin != nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
