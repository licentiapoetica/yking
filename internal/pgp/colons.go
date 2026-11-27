// Package pgp drives GnuPG for yking: it lists the user's identities and
// copies their subkeys into a YubiKey's OpenPGP slots.
//
// Card writes never happen in the user's ~/.gnupg. The subkeys are copied
// into a throwaway GnuPG home in $XDG_RUNTIME_DIR (tmpfs), moved to the
// card from there, and the throwaway home is deleted. ~/.gnupg keeps its
// secret subkeys, so the same subkeys can go to every YubiKey in turn.
package pgp

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"time"
)

// Where is where a secret key lives.
type Where int

const (
	WhereNone Where = iota // public only, or a stub of an unknown card
	WhereDisk              // secret key in the agent's key store
	WhereCard              // on a smartcard (Card holds its serial)
)

// Subkey is one subkey of an identity.
type Subkey struct {
	Fingerprint string
	Keygrip     string
	Algo        string // "ed25519", "cv25519", "rsa4096", …
	Usage       string // lower-case capabilities: s, e, a
	Created     time.Time
	Expires     time.Time // zero = never
	Where       Where
	Card        string // card serial number as gpg reports it
	Invalid     bool   // revoked or expired
}

// Identity is a primary key with secret material somewhere.
type Identity struct {
	Fingerprint string
	Keygrip     string
	Algo        string
	UIDs        []string
	Created     time.Time
	Expires     time.Time
	Where       Where
	Invalid     bool
	Subkeys     []Subkey
}

// Name is the first user ID (or the fingerprint).
func (id Identity) Name() string {
	if len(id.UIDs) > 0 {
		return id.UIDs[0]
	}
	return id.Fingerprint
}

// ParseSecret parses `gpg -K --with-colons --with-keygrip --fixed-list-mode`.
func ParseSecret(b []byte) []Identity {
	var out []Identity
	var cur *Identity
	var sub *Subkey
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 2 {
			continue
		}
		get := func(i int) string {
			if i < len(f) {
				return f[i]
			}
			return ""
		}
		switch f[0] {
		case "sec":
			out = append(out, Identity{
				Algo:    algo(get(3), get(2), get(16)),
				Created: unix(get(5)),
				Expires: unix(get(6)),
				Invalid: invalid(get(1)),
			})
			cur, sub = &out[len(out)-1], nil
			cur.Where, _ = where(get(14))
		case "ssb":
			if cur == nil {
				continue
			}
			s := Subkey{
				Algo:    algo(get(3), get(2), get(16)),
				Usage:   strings.ToLower(get(11)),
				Created: unix(get(5)),
				Expires: unix(get(6)),
				Invalid: invalid(get(1)),
			}
			s.Where, s.Card = where(get(14))
			cur.Subkeys = append(cur.Subkeys, s)
			sub = &cur.Subkeys[len(cur.Subkeys)-1]
		case "fpr":
			switch {
			case sub != nil && sub.Fingerprint == "":
				sub.Fingerprint = get(9)
			case cur != nil && sub == nil && cur.Fingerprint == "":
				cur.Fingerprint = get(9)
			}
		case "grp":
			switch {
			case sub != nil && sub.Keygrip == "":
				sub.Keygrip = get(9)
			case cur != nil && sub == nil && cur.Keygrip == "":
				cur.Keygrip = get(9)
			}
		case "uid":
			if cur != nil && !invalid(get(1)) {
				cur.UIDs = append(cur.UIDs, unescape(get(9)))
			}
		}
	}
	return out
}

func where(field string) (Where, string) {
	switch field {
	case "+":
		return WhereDisk, ""
	case "", "#":
		return WhereNone, ""
	}
	return WhereCard, field
}

func invalid(validity string) bool { return validity == "r" || validity == "e" }

func unix(s string) time.Time {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func algo(id, bits, curve string) string {
	if curve != "" {
		return curve
	}
	switch id {
	case "1", "2", "3":
		return "rsa" + bits
	}
	return "algo" + id
}

// unescape decodes gpg's \xNN escapes in colon output.
func unescape(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Slots, in card order.
var Slots = []string{"sig", "dec", "aut"}

// SlotNumber is gpg's keytocard / uif number for a slot.
func SlotNumber(slot string) string {
	switch slot {
	case "sig":
		return "1"
	case "dec":
		return "2"
	case "aut":
		return "3"
	}
	return ""
}

// SlotUsage is the capability a slot needs.
func SlotUsage(slot string) string {
	switch slot {
	case "sig":
		return "s"
	case "dec":
		return "e"
	case "aut":
		return "a"
	}
	return ""
}

// ForSlot returns the newest valid subkey usable in slot, or nil.
func (id Identity) ForSlot(slot string) *Subkey {
	var best *Subkey
	for i := range id.Subkeys {
		s := &id.Subkeys[i]
		if s.Invalid || !strings.Contains(s.Usage, SlotUsage(slot)) {
			continue
		}
		if best == nil || s.Created.After(best.Created) {
			best = s
		}
	}
	return best
}

// SubkeyByFpr finds a subkey.
func (id Identity) SubkeyByFpr(fpr string) *Subkey {
	for i := range id.Subkeys {
		if id.Subkeys[i].Fingerprint == fpr {
			return &id.Subkeys[i]
		}
	}
	return nil
}

// Short renders a fingerprint as "ABCD…WXYZ".
func Short(fpr string) string {
	if len(fpr) < 8 {
		return fpr
	}
	return fpr[:4] + "…" + fpr[len(fpr)-4:]
}
