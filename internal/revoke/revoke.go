// Package revoke plans the removal of everything tied to a lost, stolen or
// retired YubiKey. The key itself is usually not available, so nothing
// here talks to a key.
package revoke

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
)

// Cred is a credential position in the user's mapping line.
type Cred struct {
	Pos    int // 1-based
	Handle string
}

// SSHHost is one deployed SSH key on one host.
type SSHHost struct {
	Key  keyring.SSHKey
	Host string
}

// Analysis is everything tied to one key.
type Analysis struct {
	Key keyring.Key
	// Recorded are this key's credentials (per keyring) still in the mapping.
	Recorded []Cred
	// Unassigned are mapping credentials recorded on no registered key.
	Unassigned []Cred
	// UnassignedAreThisKeys is true when every OTHER registered key is
	// confirmed: then unassigned credentials cannot belong to them.
	UnassignedAreThisKeys bool
	Hosts                 []SSHHost
	Files                 []string // existing local SSH key files
	RemainingConfirmed    []string // labels of other keys that still work with PAM
	KeyServices           []string // PAM services that need a key (key only / password + key)
	Warnings              []string
}

// Analyze inspects the keyring, mapping and PAM services for serial.
func Analyze(kr *keyring.Keyring, m *pam.Mapping, user, serial string, services []pam.State) (*Analysis, error) {
	k := kr.Find(serial)
	if k == nil {
		return nil, fmt.Errorf("key %s is not registered", serial)
	}
	a := &Analysis{Key: *k}

	owner := map[string]string{}
	for _, other := range kr.Keys {
		for _, c := range other.U2F {
			if c.User == user {
				owner[c.KeyHandle] = other.Serial
			}
		}
	}
	if m != nil {
		for i, c := range m.Creds(user) {
			switch owner[c.KeyHandle] {
			case serial:
				a.Recorded = append(a.Recorded, Cred{i + 1, c.KeyHandle})
			case "":
				a.Unassigned = append(a.Unassigned, Cred{i + 1, c.KeyHandle})
			}
		}
	}
	cov := pam.Coverage(kr, m, user)
	a.UnassignedAreThisKeys = true
	for _, other := range kr.Keys {
		if other.Serial == serial {
			continue
		}
		if cov[other.Serial] {
			a.RemainingConfirmed = append(a.RemainingConfirmed, other.Label)
		} else {
			a.UnassignedAreThisKeys = false
		}
	}

	for _, s := range k.SSH {
		for _, h := range s.Hosts {
			a.Hosts = append(a.Hosts, SSHHost{Key: s, Host: h})
		}
		for _, f := range []string{s.Path, s.Path + ".pub"} {
			if s.Path == "" {
				continue
			}
			if fi, err := os.Lstat(f); err == nil && fi.Mode().IsRegular() {
				a.Files = append(a.Files, f)
			}
		}
	}

	for _, st := range services {
		if st.Current.Mode == pam.ModeOnly || st.Current.Mode == pam.ModeAnd {
			a.KeyServices = append(a.KeyServices, st.Service.Name)
		}
	}

	switch {
	case len(a.KeyServices) > 0 && len(a.RemainingConfirmed) == 0:
		a.Warnings = append(a.Warnings, fmt.Sprintf(
			"After this NO confirmed key opens %s. Only services that accept a password (e.g. the text console) will let you in. Check or add another key first if you can.",
			strings.Join(a.KeyServices, ", ")))
	case len(a.KeyServices) > 0 && len(a.RemainingConfirmed) < 2:
		a.Warnings = append(a.Warnings, fmt.Sprintf(
			"After this only %s opens %s. Register and check a replacement key soon.",
			strings.Join(a.RemainingConfirmed, ", "), strings.Join(a.KeyServices, ", ")))
	}
	if len(a.Recorded) == 0 && len(a.Unassigned) > 0 && !a.UnassignedAreThisKeys {
		a.Warnings = append(a.Warnings,
			"yking does not know which PAM credentials are this key's. Check your other keys first (main screen → c); then the leftover ones can only be this key's.")
	}
	return a, nil
}

// Choices are what the user ticked.
type Choices struct {
	RemoveRecorded   bool
	RemoveUnassigned bool
	ArchiveFiles     bool
	// HostsCleaned lists "fingerprint host" pairs confirmed gone.
	HostsCleaned map[string]bool
}

// HostKey identifies a host entry in Choices.HostsCleaned.
func HostKey(h SSHHost) string { return h.Key.Fingerprint + " " + h.Host }

// Handles returns the credentials to remove for the choices.
func (a *Analysis) Handles(ch Choices) []string {
	var out []string
	if ch.RemoveRecorded {
		for _, c := range a.Recorded {
			out = append(out, c.Handle)
		}
	}
	if ch.RemoveUnassigned && a.UnassignedAreThisKeys {
		for _, c := range a.Unassigned {
			out = append(out, c.Handle)
		}
	}
	return out
}

// UserPlan removes the chosen credentials from the mapping (nil if none).
func UserPlan(a *Analysis, ch Choices, user string, base plan.Base, now time.Time) (*plan.Plan, error) {
	handles := a.Handles(ch)
	if len(handles) == 0 {
		return nil, nil
	}
	m, err := pam.ParseMapping(string(base.Data))
	if err != nil {
		return nil, err
	}
	if n := m.Remove(user, handles); n != len(handles) {
		return nil, fmt.Errorf("mapping changed: expected to remove %d credential(s), found %d", len(handles), n)
	}
	p := plan.New(fmt.Sprintf("remove %d PAM credential(s) of revoked key %q", len(handles), a.Key.Label), now)
	mode := uint32(0o644)
	if fi, err := os.Stat(base.Path); err == nil {
		mode = uint32(fi.Mode().Perm())
	}
	p.Replace(base, []byte(m.String()), os.FileMode(mode))
	return p, nil
}

// RootPlan removes the key from the keyring and records it as revoked,
// with every deployed host that was not cleaned as a leftover.
func RootPlan(krPath string, a *Analysis, ch Choices, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	kr, err := keyring.Parse(base.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", krPath, err)
	}
	var left []keyring.Leftover
	for _, h := range a.Hosts {
		if !ch.HostsCleaned[HostKey(h)] {
			left = append(left, keyring.Leftover{Fingerprint: h.Key.Fingerprint, Comment: h.Key.Comment, Host: h.Host})
		}
	}
	if err := kr.Revoke(a.Key.Serial, left, now); err != nil {
		return nil, err
	}
	content, err := kr.Encode()
	if err != nil {
		return nil, err
	}
	desc := fmt.Sprintf("revoke key %q (%s)", a.Key.Label, a.Key.Serial)
	if len(left) > 0 {
		desc += fmt.Sprintf(", %d SSH host(s) still to clean", len(left))
	}
	p := plan.New(desc, now)
	p.Replace(base, content, 0o644)
	return p, nil
}

// ArchiveDir is where revoked key files are moved.
func ArchiveDir(sshDir string) string { return filepath.Join(sshDir, "yking-revoked") }

// Archive moves files into dir (0700), never overwriting. Returns the new
// paths. Moving back restores them.
func Archive(files []string, dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var moved []string
	for _, f := range files {
		dst := filepath.Join(dir, filepath.Base(f))
		if _, err := os.Lstat(dst); err == nil {
			dst += "." + time.Now().Format("20060102-150405")
		}
		if _, err := os.Lstat(dst); err == nil {
			return moved, errors.New(dst + " exists")
		}
		if err := os.Rename(f, dst); err != nil {
			return moved, err
		}
		moved = append(moved, dst)
	}
	return moved, nil
}
