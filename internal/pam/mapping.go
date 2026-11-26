package pam

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"yking/internal/keyring"
	"yking/internal/plan"
)

// Cred is one pam_u2f credential: "keyHandle,publicKey,coseType,options".
type Cred struct {
	KeyHandle string
	PublicKey string
	Type      string
	Options   string
	Raw       string
}

var credPartRe = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)

// ParseCred parses one credential field.
func ParseCred(s string) (Cred, error) {
	s = strings.TrimSpace(s)
	f := strings.Split(s, ",")
	if len(f) < 3 || len(f) > 4 {
		return Cred{}, fmt.Errorf("credential needs 3–4 comma-separated fields")
	}
	if !credPartRe.MatchString(f[0]) || !credPartRe.MatchString(f[1]) {
		return Cred{}, errors.New("credential key handle / public key not base64")
	}
	c := Cred{KeyHandle: f[0], PublicKey: f[1], Type: f[2], Raw: s}
	if len(f) == 4 {
		c.Options = f[3]
	}
	return c, nil
}

// Mapping is a parsed u2f_keys file.
type Mapping struct {
	lines []string
}

// ParseMapping parses "user:cred:cred…" lines, validating every credential.
func ParseMapping(content string) (*Mapping, error) {
	m := &Mapping{}
	seen := map[string]bool{}
	for i, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if content == "" {
			break
		}
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			m.lines = append(m.lines, l)
			continue
		}
		parts := strings.Split(t, ":")
		if len(parts) < 2 || parts[0] == "" {
			return nil, fmt.Errorf("line %d: expected user:credential…", i+1)
		}
		if seen[parts[0]] {
			return nil, fmt.Errorf("line %d: user %s appears twice", i+1, parts[0])
		}
		seen[parts[0]] = true
		for _, c := range parts[1:] {
			if _, err := ParseCred(c); err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
		}
		m.lines = append(m.lines, l)
	}
	return m, nil
}

// Creds returns user's credentials in file order.
func (m *Mapping) Creds(user string) []Cred {
	for _, l := range m.lines {
		parts := strings.Split(strings.TrimSpace(l), ":")
		if len(parts) > 1 && parts[0] == user {
			var out []Cred
			for _, p := range parts[1:] {
				if c, err := ParseCred(p); err == nil {
					out = append(out, c)
				}
			}
			return out
		}
	}
	return nil
}

// Append adds a credential for user (creating the user's line if needed).
// Refuses a duplicate key handle. Never removes or reorders anything.
func (m *Mapping) Append(user string, c Cred) error {
	for _, have := range m.Creds(user) {
		if have.KeyHandle == c.KeyHandle {
			return errors.New("credential already in the mapping")
		}
	}
	for i, l := range m.lines {
		parts := strings.Split(strings.TrimSpace(l), ":")
		if len(parts) > 1 && parts[0] == user {
			m.lines[i] = strings.TrimSpace(l) + ":" + c.Raw
			return nil
		}
	}
	m.lines = append(m.lines, user+":"+c.Raw)
	return nil
}

// Remove deletes the credentials with the given key handles for user and
// returns how many were removed. A user left with no credential loses the
// whole line (pam_u2f then refuses the key for that user).
func (m *Mapping) Remove(user string, handles []string) int {
	drop := map[string]bool{}
	for _, h := range handles {
		drop[h] = true
	}
	n := 0
	for i := 0; i < len(m.lines); i++ {
		parts := strings.Split(strings.TrimSpace(m.lines[i]), ":")
		if len(parts) < 2 || parts[0] != user {
			continue
		}
		keep := []string{parts[0]}
		for _, p := range parts[1:] {
			if c, err := ParseCred(p); err == nil && drop[c.KeyHandle] {
				n++
				continue
			}
			keep = append(keep, p)
		}
		if len(keep) == 1 {
			m.lines = append(m.lines[:i], m.lines[i+1:]...)
			i--
		} else {
			m.lines[i] = strings.Join(keep, ":")
		}
	}
	return n
}

// String renders the file.
func (m *Mapping) String() string {
	if len(m.lines) == 0 {
		return ""
	}
	return strings.Join(m.lines, "\n") + "\n"
}

// ValidateMapping is the plan validator for u2f_keys files.
func ValidateMapping(path string, content []byte) error {
	if !strings.HasSuffix(path, "/u2f_keys") {
		return fmt.Errorf("unexpected mapping file %s", path)
	}
	_, err := ParseMapping(string(content))
	return err
}

// Origin is pam_u2f's default relying party: pam://<hostname>.
func Origin() (string, error) {
	h, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return "pam://" + h, nil
}

// RegisterBinary is pam-u2f's registration tool. Only this package runs it.
const RegisterBinary = "pamu2fcfg"

// RegisterCommand creates a new NON-resident credential (nothing stored on
// the key; one touch). -P matches the existing PIN-only credentials (the
// PAM line's pinverification/userpresence options decide what is asked).
func RegisterCommand(origin string) *exec.Cmd {
	return exec.Command(RegisterBinary, RegisterArgs(origin)...)
}

// RegisterArgs are the fixed pamu2fcfg arguments.
func RegisterArgs(origin string) []string {
	return []string{"-n", "-P", "-o", origin, "-i", origin}
}

// ParseRegisterOutput extracts the credential from `pamu2fcfg -n` output
// (":keyHandle,publicKey,type,options").
func ParseRegisterOutput(out []byte) (Cred, error) {
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, ":") {
			return ParseCred(strings.TrimPrefix(l, ":"))
		}
	}
	return Cred{}, errors.New("no credential in pamu2fcfg output")
}

// RecordCredsPlan records that serial owns the given key handles (for
// user). A handle recorded on another key is moved, since the probe just
// proved where it lives. Returns plan.ErrNoChanges if nothing changes.
func RecordCredsPlan(krPath, serial, user string, handles []string, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	kr, err := keyring.Parse(base.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", krPath, err)
	}
	k := kr.Find(serial)
	if k == nil {
		return nil, fmt.Errorf("key %s is not registered", serial)
	}
	want := map[string]bool{}
	for _, h := range handles {
		want[h] = true
	}
	for i := range kr.Keys {
		other := &kr.Keys[i]
		if other.Serial == serial {
			continue
		}
		var keep []keyring.U2FCred
		for _, c := range other.U2F {
			if !(want[c.KeyHandle] && c.User == user) {
				keep = append(keep, c)
			}
		}
		other.U2F = keep
	}
	have := map[string]bool{}
	for _, c := range k.U2F {
		if c.User == user {
			have[c.KeyHandle] = true
		}
	}
	added := 0
	for _, h := range handles {
		if !have[h] {
			k.U2F = append(k.U2F, keyring.U2FCred{User: user, KeyHandle: h, CreatedAt: now.UTC().Truncate(time.Second)})
			added++
		}
	}
	content, err := kr.Encode()
	if err != nil {
		return nil, err
	}
	p := plan.New(fmt.Sprintf("record %d PAM credential(s) of %s on key %q", len(handles), user, k.Label), now)
	p.Replace(base, content, 0o644)
	if p.Empty() {
		return nil, plan.ErrNoChanges
	}
	return p, nil
}

// Coverage tells, per registered key, whether one of its recorded
// credentials is still in the mapping.
func Coverage(kr *keyring.Keyring, m *Mapping, user string) map[string]bool {
	inMap := map[string]bool{}
	if m != nil {
		for _, c := range m.Creds(user) {
			inMap[c.KeyHandle] = true
		}
	}
	out := map[string]bool{}
	for _, k := range kr.Keys {
		for _, c := range k.U2F {
			if c.User == user && inMap[c.KeyHandle] {
				out[k.Serial] = true
			}
		}
	}
	return out
}
