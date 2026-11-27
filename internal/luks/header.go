package luks

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"time"
)

// Slot is one LUKS2 keyslot.
type Slot struct {
	ID    int
	Token *Token // the token that unlocks it, if any
	KDF   string // argon2id, pbkdf2, …
}

// Token is a LUKS2 token (systemd-fido2, systemd-tpm2, …).
type Token struct {
	ID          int
	Type        string
	Keyslots    []int
	Credential  string // fido2-credential (base64), for matching a key
	RP          string // fido2-rp
	PINRequired bool
	UPRequired  bool
}

// Header is the parsed LUKS2 JSON metadata.
type Header struct {
	Slots  []Slot
	Tokens []Token
	Cipher string // data segment encryption, e.g. aes-xts-plain64
}

// PasswordSlots returns keyslots no token is bound to (passphrases or
// key files).
func (h Header) PasswordSlots() []int {
	var out []int
	for _, s := range h.Slots {
		if s.Token == nil {
			out = append(out, s.ID)
		}
	}
	return out
}

// HasRecovery reports a systemd recovery key slot (a passphrase too).
func (h Header) HasRecovery() bool {
	for _, t := range h.Tokens {
		if t.Type == "systemd-recovery" && len(t.Keyslots) > 0 {
			return true
		}
	}
	return false
}

// FIDO2 returns the systemd-fido2 tokens.
func (h Header) FIDO2() []Token {
	var out []Token
	for _, t := range h.Tokens {
		if t.Type == "systemd-fido2" {
			out = append(out, t)
		}
	}
	return out
}

// ParseHeader parses `cryptsetup luksDump --dump-json-metadata`.
func ParseHeader(b []byte) (Header, error) {
	var doc struct {
		Keyslots map[string]struct {
			KDF struct {
				Type string `json:"type"`
			} `json:"kdf"`
		} `json:"keyslots"`
		Segments map[string]struct {
			Encryption string `json:"encryption"`
		} `json:"segments"`
		Tokens map[string]struct {
			Type       string   `json:"type"`
			Keyslots   []string `json:"keyslots"`
			Credential string   `json:"fido2-credential"`
			RP         string   `json:"fido2-rp"`
			PIN        bool     `json:"fido2-clientPin-required"`
			UP         bool     `json:"fido2-up-required"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return Header{}, err
	}
	var h Header
	bySlot := map[int]*Token{}
	for id, t := range doc.Tokens {
		n, err := strconv.Atoi(id)
		if err != nil {
			return Header{}, fmt.Errorf("bad token id %q", id)
		}
		tok := Token{ID: n, Type: t.Type, Credential: t.Credential, RP: t.RP, PINRequired: t.PIN, UPRequired: t.UP}
		for _, k := range t.Keyslots {
			s, err := strconv.Atoi(k)
			if err != nil {
				return Header{}, fmt.Errorf("bad keyslot %q", k)
			}
			tok.Keyslots = append(tok.Keyslots, s)
		}
		h.Tokens = append(h.Tokens, tok)
	}
	sort.Slice(h.Tokens, func(i, j int) bool { return h.Tokens[i].ID < h.Tokens[j].ID })
	for i := range h.Tokens {
		for _, s := range h.Tokens[i].Keyslots {
			bySlot[s] = &h.Tokens[i]
		}
	}
	for id, ks := range doc.Keyslots {
		n, err := strconv.Atoi(id)
		if err != nil {
			return Header{}, fmt.Errorf("bad keyslot id %q", id)
		}
		h.Slots = append(h.Slots, Slot{ID: n, Token: bySlot[n], KDF: ks.KDF.Type})
	}
	if seg, ok := doc.Segments["0"]; ok {
		h.Cipher = seg.Encryption
	}
	sort.Slice(h.Slots, func(i, j int) bool { return h.Slots[i].ID < h.Slots[j].ID })
	return h, nil
}

// ReadHeader dumps and parses a LUKS2 header (root).
func ReadHeader(device string) (Header, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "cryptsetup", "luksDump", "--dump-json-metadata", device).Output()
	if err != nil {
		return Header{}, fmt.Errorf("cryptsetup luksDump %s: %w", device, err)
	}
	return ParseHeader(out)
}
