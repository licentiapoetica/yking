// Package chalresp puts one HMAC-SHA1 challenge-response secret into OTP
// slot 2 of several YubiKeys, so each of them opens the same KeePassXC
// database. The secret lives only in memory while yking runs.
package chalresp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
)

// SecretLen is the HMAC-SHA1 key size a YubiKey slot takes.
const SecretLen = 20

// NewSecret returns a fresh random secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, SecretLen)
	_, err := rand.Read(s)
	return s, err
}

// SetID names a secret without revealing it.
func SetID(secret []byte) string {
	h := sha256.Sum256(append([]byte("yking-hmac-set:"), secret...))
	return hex.EncodeToString(h[:6])
}

// Response is what a key holding secret answers to challenge.
func Response(secret, challenge []byte) []byte {
	m := hmac.New(sha1.New, secret)
	m.Write(challenge)
	return m.Sum(nil)
}

// Challenge returns a random test challenge.
func Challenge() ([]byte, error) {
	c := make([]byte, 32)
	_, err := rand.Read(c)
	return c, err
}

// Paper renders the secret for a written copy: groups of four hex digits.
func Paper(secret []byte) string {
	h := hex.EncodeToString(secret)
	var g []string
	for i := 0; i < len(h); i += 4 {
		g = append(g, h[i:min(i+4, len(h))])
	}
	return strings.Join(g, " ")
}

// ParsePaper reads a secret typed back from the paper copy.
func ParsePaper(s string) ([]byte, error) {
	s = strings.ToLower(strings.Join(strings.Fields(s), ""))
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != SecretLen {
		return nil, errors.New("expected 40 hex digits")
	}
	return b, nil
}

// Sets lists the secret sets recorded in the keyring: set → key labels.
func Sets(kr *keyring.Keyring) map[string][]string {
	out := map[string][]string{}
	for _, k := range kr.Keys {
		if k.HMAC != nil {
			out[k.HMAC.Set] = append(out[k.HMAC.Set], k.Label)
		}
	}
	return out
}

// RecordPlan records the programmed keys (serial → slot) in the keyring.
func RecordPlan(krPath string, slots map[string]keyring.HMACSlot, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	kr, err := keyring.Parse(base.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", krPath, err)
	}
	var labels []string
	for serial, s := range slots {
		k := kr.Find(serial)
		if k == nil {
			return nil, fmt.Errorf("key %s is not registered", serial)
		}
		s := s
		k.HMAC = &s
		labels = append(labels, k.Label)
	}
	content, err := kr.Encode()
	if err != nil {
		return nil, err
	}
	p := plan.New("record KeePassXC challenge-response on "+strings.Join(labels, ", "), now)
	p.Replace(base, content, 0o644)
	if p.Empty() {
		return nil, plan.ErrNoChanges
	}
	return p, nil
}

// RulePath gives the logged-in user the YubiKey OTP interface: ykman (and
// some KeePassXC builds) compute challenge-response over USB only there.
const RulePath = "/etc/udev/rules.d/69-yking-otp.rules"

// Rule is the udev rule at RulePath ("uaccess" before 73-seat-late).
const Rule = `# Managed by yking. YubiKey OTP interface for the logged-in user
# (challenge-response: KeePassXC, ykman otp calculate).
ACTION=="add|change", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"
`

// ValidateRule accepts only Rule at RulePath.
func ValidateRule(path string, content []byte) error {
	if path != RulePath || string(content) != Rule {
		return fmt.Errorf("yking only writes its own OTP rule, not %s", path)
	}
	return nil
}

// RulePlan installs the udev rule.
func RulePlan(now time.Time) (*plan.Plan, error) {
	p := plan.New("udev: YubiKey OTP interface for you (challenge-response)", now)
	if err := p.WriteFile(RulePath, []byte(Rule), 0o644); err != nil {
		return nil, err
	}
	if p.Empty() {
		return nil, plan.ErrNoChanges
	}
	return p, nil
}
