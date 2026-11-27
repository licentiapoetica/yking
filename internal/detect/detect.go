// Package detect builds a read-only inventory of connected YubiKeys and
// matches them against the keyring. Nothing here writes to a key.
package detect

import (
	"context"
	"fmt"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// KeyReport is everything yking learned about one connected key.
type KeyReport struct {
	Serial string
	Info   ykman.DeviceInfo
	FIDO   *ykman.FIDOInfo // nil if unreadable / not available
	OTP    *ykman.OTPInfo  // nil if unreadable / not available
	Known  *keyring.Key    // nil if not in keyring
	// Errors are partial failures; the rest of the report is still valid.
	Errors []string
}

// Warnings are things the user should know before yking does anything with
// this key.
func (r KeyReport) Warnings() []string {
	var w []string
	if r.FIDO != nil {
		if ok, why := r.FIDO.PINPromptAllowed(); !ok {
			w = append(w, why)
		}
	}
	if r.OTP != nil && r.OTP.Slot2 == ykman.SlotProgrammed {
		w = append(w, "OTP slot 2 is in use; yking will not write HMAC challenge-response to this key")
	}
	if r.Known == nil {
		w = append(w, "not in keyring yet")
	}
	return w
}

// Report is a full scan.
type Report struct {
	YkmanVersion string
	Keys         []KeyReport
	// Unidentified counts connected YubiKeys without a readable serial
	// (e.g. FIDO-only Security Key models). yking cannot track those.
	Unidentified []string
	// Missing are keyring keys that are not connected right now.
	Missing []keyring.Key
}

// Progress is one step of a running scan, for a live display. A step is
// reported once when it starts (Done false) and once when it ends.
type Progress struct {
	Step string // stable id of the step
	Text string
	Done bool
}

// Scan inventories every connected key. It only uses read-only ykman
// commands (enforced by ykman's allowlist).
func Scan(ctx context.Context, c *ykman.Client, kr *keyring.Keyring) (*Report, error) {
	return ScanProgress(ctx, c, kr, nil)
}

// ScanProgress is Scan, reporting each step to progress (may be nil).
func ScanProgress(ctx context.Context, c *ykman.Client, kr *keyring.Keyring, progress func(Progress)) (*Report, error) {
	say := func(step, text string, done bool) {
		if progress != nil {
			progress(Progress{Step: step, Text: text, Done: done})
		}
	}
	rep := &Report{}
	say("version", "starting ykman", false)
	v, err := c.Version(ctx)
	if err != nil {
		return nil, fmt.Errorf("ykman not usable: %w", err)
	}
	rep.YkmanVersion = v
	say("version", "ykman "+v, true)

	say("list", "looking for YubiKeys on USB", false)
	devs, err := c.ListDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing keys: %w", err)
	}
	serials, err := c.ListSerials(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing serials: %w", err)
	}
	for _, d := range devs {
		if d.Serial == "" {
			rep.Unidentified = append(rep.Unidentified, d.Description)
		}
	}

	switch n := len(serials); n {
	case 0:
		say("list", "no YubiKey with a serial plugged in", true)
	case 1:
		say("list", "found 1 YubiKey", true)
	default:
		say("list", fmt.Sprintf("found %d YubiKeys", n), true)
	}

	connected := map[string]bool{}
	for _, s := range serials {
		connected[s] = true
		name := s
		if k := kr.Find(s); k != nil {
			name = fmt.Sprintf("%s (%s)", k.Label, s)
		}
		say("key:"+s, "reading "+name, false)
		r := inventory(ctx, c, kr, s)
		rep.Keys = append(rep.Keys, r)
		what := "read " + name
		if r.Known == nil {
			what += " — new key"
		}
		say("key:"+s, what, true)
	}
	for _, k := range kr.Keys {
		if !connected[k.Serial] {
			rep.Missing = append(rep.Missing, k)
		}
	}
	return rep, nil
}

func inventory(ctx context.Context, c *ykman.Client, kr *keyring.Keyring, serial string) KeyReport {
	r := KeyReport{Serial: serial, Known: kr.Find(serial)}
	info, err := c.Info(ctx, serial)
	if err != nil {
		r.Errors = append(r.Errors, "info: "+err.Error())
	}
	r.Info = info

	if appEnabled(info, "FIDO2") {
		if f, err := c.FIDOInfo(ctx, serial); err != nil {
			r.Errors = append(r.Errors, "fido info: "+err.Error())
		} else {
			r.FIDO = &f
		}
	}
	if appEnabled(info, "Yubico OTP") {
		if o, err := c.OTPInfo(ctx, serial); err != nil {
			r.Errors = append(r.Errors, "otp info: "+err.Error())
		} else {
			r.OTP = &o
		}
	}
	return r
}

// appEnabled is true when the app is enabled over USB, or when info could not
// be parsed (in which case we try and record any error).
func appEnabled(info ykman.DeviceInfo, app string) bool {
	if len(info.Apps) == 0 {
		return true
	}
	return info.Apps[app].USB == "Enabled"
}
