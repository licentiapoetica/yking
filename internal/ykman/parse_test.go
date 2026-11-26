package ykman

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/licentiapoetica/yking/internal/runner"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseList(t *testing.T) {
	got := parseList(fixture(t, "list.txt"))
	if len(got) != 3 {
		t.Fatalf("got %d devices, want 3", len(got))
	}
	if got[0].Serial != "12345678" || got[0].Description != "YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID]" {
		t.Errorf("device 0 = %+v", got[0])
	}
	if got[2].Serial != "" {
		t.Errorf("security key should have no serial, got %q", got[2].Serial)
	}
}

func TestParseSerials(t *testing.T) {
	got := parseSerials(fixture(t, "list_serials.txt"))
	if !slices.Equal(got, []string{"12345678", "23456789"}) {
		t.Errorf("got %v", got)
	}
}

func TestParseInfo(t *testing.T) {
	got := parseInfo(fixture(t, "info.txt"))
	if got.DeviceType != "YubiKey 5 NFC" || got.Serial != "12345678" || got.Firmware != "5.4.3" {
		t.Errorf("header = %+v", got)
	}
	if got.FormFactor != "Keychain (USB-A)" {
		t.Errorf("form factor = %q", got.FormFactor)
	}
	if st := got.Apps["FIDO2"]; st.USB != "Enabled" || st.NFC != "Enabled" {
		t.Errorf("FIDO2 = %+v", st)
	}
	if st := got.Apps["PIV"]; st.NFC != "Disabled" {
		t.Errorf("PIV = %+v", st)
	}
	if _, ok := got.Apps["YubiHSM Auth"]; !ok {
		t.Errorf("missing app with space in name: %v", got.Apps)
	}
}

func TestParseFIDOInfo(t *testing.T) {
	f := parseFIDOInfo(fixture(t, "fido_info.txt"))
	if !f.PINSet || f.PINRetries != 8 || f.MinPINLength != 4 || f.CredsRemaining != 21 || f.AlwaysUV != "Off" {
		t.Errorf("5.x format = %+v", f)
	}
	f = parseFIDOInfo(fixture(t, "fido_info_old.txt"))
	if !f.PINSet || f.PINRetries != 5 {
		t.Errorf("old format = %+v", f)
	}
	f = parseFIDOInfo(fixture(t, "fido_info_nopin.txt"))
	if f.PINSet || f.PINRetries != -1 {
		t.Errorf("no pin = %+v", f)
	}
	f = parseFIDOInfo([]byte("PIN:   Blocked\n"))
	if !f.PINBlocked || f.PINRetries != 0 {
		t.Errorf("blocked = %+v", f)
	}
}

func TestParseOTPInfo(t *testing.T) {
	o := parseOTPInfo(fixture(t, "otp_info.txt"))
	if o.Slot1 != SlotProgrammed || o.Slot2 != SlotEmpty {
		t.Errorf("got %+v", o)
	}
}

func TestPINPromptAllowed(t *testing.T) {
	cases := []struct {
		f    FIDOInfo
		want bool
	}{
		{FIDOInfo{PINSet: true, PINRetries: 8}, true},
		{FIDOInfo{PINSet: true, PINRetries: 4}, true},
		{FIDOInfo{PINSet: true, PINRetries: 3}, false},
		{FIDOInfo{PINSet: true, PINRetries: 0, PINBlocked: true}, false},
		{FIDOInfo{PINSet: true, PINRetries: -1}, false},
		{FIDOInfo{PINSet: false, PINRetries: -1}, false},
	}
	for _, c := range cases {
		if got, why := c.f.PINPromptAllowed(); got != c.want {
			t.Errorf("%+v: got %v (%s), want %v", c.f, got, why, c.want)
		}
	}
}

// fakeRunner serves fixtures keyed by the joined argv.
type fakeRunner struct {
	out   map[string][]byte
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (runner.Result, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if b, ok := f.out[strings.Join(args, " ")]; ok {
		return runner.Result{Stdout: b}, nil
	}
	return runner.Result{ExitCode: 2}, &runner.ExitError{Name: name, Code: 2}
}

func TestClientRefusesBeforeRunning(t *testing.T) {
	fr := &fakeRunner{}
	c := New(fr)
	if _, err := c.Info(context.Background(), "not-a-serial"); !errors.As(err, new(*PolicyError)) {
		t.Fatalf("got %v, want PolicyError", err)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("runner was called: %v", fr.calls)
	}
}

func TestClientInfo(t *testing.T) {
	fr := &fakeRunner{out: map[string][]byte{"--device 12345678 info": fixture(t, "info.txt")}}
	info, err := New(fr).Info(context.Background(), "12345678")
	if err != nil {
		t.Fatal(err)
	}
	if info.DeviceType != "YubiKey 5 NFC" {
		t.Errorf("got %+v", info)
	}
}
