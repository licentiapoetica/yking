// Package enroll builds plans that register a YubiKey in the keyring.
// Enrollment is host-side only: nothing is written to the key.
package enroll

import (
	"fmt"
	"strings"
	"time"

	"yking/internal/detect"
	"yking/internal/keyring"
	"yking/internal/plan"
)

// Request is what the user chose in the enroll form.
type Request struct {
	Label     string
	Role      keyring.Role
	Protected bool
}

// Plan reads the keyring at krPath, adds the key and returns a plan writing
// the result. The plan's precondition is the exact keyring bytes it was
// computed from.
func Plan(krPath string, k detect.KeyReport, req Request, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	kr := keyring.New()
	if base.Exists {
		if kr, err = keyring.Parse(base.Data); err != nil {
			return nil, fmt.Errorf("%s: %w", krPath, err)
		}
	}

	label := strings.TrimSpace(req.Label)
	entry, err := kr.Add(k.Serial, label, req.Role, now)
	if err != nil {
		return nil, err
	}
	entry.Protected = req.Protected
	entry.Model = k.Info.DeviceType
	entry.Firmware = k.Info.Firmware

	content, err := kr.Encode()
	if err != nil {
		return nil, err
	}
	p := plan.New(fmt.Sprintf("register key %s as %q (%s)", k.Serial, label, req.Role), now)
	p.Replace(base, content, 0o644)
	return p, nil
}

// SuggestRole returns the first role not yet used in kr, or daily.
func SuggestRole(kr *keyring.Keyring) keyring.Role {
	used := map[keyring.Role]bool{}
	for _, k := range kr.Keys {
		used[k.Role] = true
	}
	for _, r := range keyring.Roles {
		if !used[r] {
			return r
		}
	}
	return keyring.RoleDaily
}

// SuggestLabel returns a unique label derived from role.
func SuggestLabel(kr *keyring.Keyring, role keyring.Role) string {
	taken := map[string]bool{}
	for _, k := range kr.Keys {
		taken[k.Label] = true
	}
	label := string(role)
	for i := 2; taken[label]; i++ {
		label = fmt.Sprintf("%s-%d", role, i)
	}
	return label
}
