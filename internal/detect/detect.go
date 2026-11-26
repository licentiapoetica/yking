// Package detect builds a read-only inventory of connected YubiKeys and
// matches them against the keyring. Nothing here writes to a key.
package detect

import (
	"context"
	"fmt"

	"yking/internal/keyring"
	"yking/internal/ykman"
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

// Scan inventories every connected key. It only uses read-only ykman
// commands (enforced by ykman's allowlist).
func Scan(ctx context.Context, c *ykman.Client, kr *keyring.Keyring) (*Report, error) {
	rep := &Report{}
	v, err := c.Version(ctx)
	if err != nil {
		return nil, fmt.Errorf("ykman not usable: %w", err)
	}
	rep.YkmanVersion = v

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

	connected := map[string]bool{}
	for _, s := range serials {
		connected[s] = true
		rep.Keys = append(rep.Keys, inventory(ctx, c, kr, s))
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
