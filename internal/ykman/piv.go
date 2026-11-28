package ykman

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/licentiapoetica/yking/internal/runner"
)

// PIV factory defaults (public, printed in every YubiKey manual).
const (
	DefaultPIVPIN = "123456"
	DefaultPIVPUK = "12345678"
)

// PIVSlots are the key slots in display order: the four named ones, then
// the 20 retired key-management slots.
var PIVSlots = func() []string {
	s := []string{"9a", "9c", "9d", "9e"}
	for i := 0x82; i <= 0x95; i++ {
		s = append(s, strconv.FormatInt(int64(i), 16))
	}
	return s
}()

// IsPIVSlot reports whether s is a key slot id (lower case).
func IsPIVSlot(s string) bool {
	for _, x := range PIVSlots {
		if s == x {
			return true
		}
	}
	return false
}

// PIVSlotName is the slot's short role.
func PIVSlotName(slot string) string {
	switch slot {
	case "9a":
		return "auth"
	case "9c":
		return "sign"
	case "9d":
		return "decrypt"
	case "9e":
		return "card auth"
	}
	return "retired"
}

// PIVInfo is parsed `ykman piv info`.
type PIVInfo struct {
	Version     string
	PINTries    int // -1 = unknown
	PUKTries    int // -1 = unknown
	PUKBlocked  bool
	DefaultPIN  bool
	DefaultPUK  bool
	DefaultMgmt bool
	MgmtAlgo    string
	MgmtStored  bool // random key on the key, unlocked by the PIN
	MgmtDerived bool // old PIN-derived scheme
	Slots       map[string]PIVSlot
}

// PIVSlot is one used slot (key and/or certificate).
type PIVSlot struct {
	KeyType  string // "EMPTY" when only a certificate is there
	CertAlgo string
	Subject  string
	NotAfter string
}

// AnyDefault reports whether a factory credential is still in place.
func (p PIVInfo) AnyDefault() bool { return p.DefaultPIN || p.DefaultPUK || p.DefaultMgmt }

// MinPIVPINTriesToPrompt: three wrong PINs block PIV; then only the PUK
// helps. Ask only while a wrong answer still leaves a try.
const MinPIVPINTriesToPrompt = 2

// PINPromptAllowed reports whether yking may ask for the PIV PIN.
func (p PIVInfo) PINPromptAllowed() (bool, string) {
	switch {
	case p.PINTries < 0:
		return false, "could not read PIV PIN tries"
	case p.PINTries == 0:
		return false, "PIV PIN is blocked"
	case p.PINTries < MinPIVPINTriesToPrompt:
		return false, fmt.Sprintf("only %d PIV PIN try left; refusing to prompt", p.PINTries)
	}
	return true, ""
}

var slotHeadRe = regexp.MustCompile(`^Slot ([0-9A-Fa-f]{2}) \(`)

func parsePIVInfo(b []byte) PIVInfo {
	p := PIVInfo{PINTries: -1, PUKTries: -1, Slots: map[string]PIVSlot{}}
	tries := func(v string) int {
		v, _, _ = strings.Cut(v, "/")
		if strings.HasPrefix(v, "15 or more") {
			return 15
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return -1
		}
		return n
	}
	slot := ""
	for _, l := range lines(b) {
		t := strings.TrimSpace(l)
		if m := slotHeadRe.FindStringSubmatch(t); m != nil {
			slot = strings.ToLower(m[1])
			p.Slots[slot] = PIVSlot{}
			continue
		}
		switch t {
		case "WARNING: Using default PIN!":
			p.DefaultPIN = true
			continue
		case "WARNING: Using default PUK!":
			p.DefaultPUK = true
			continue
		case "WARNING: Using default Management key!":
			p.DefaultMgmt = true
			continue
		case "PUK is blocked":
			p.PUKBlocked = true
			continue
		case "Management key is stored on the YubiKey, protected by PIN.":
			p.MgmtStored = true
			continue
		case "Management key is derived from PIN.":
			p.MgmtDerived = true
			continue
		}
		k, v, ok := splitKV(t)
		if !ok {
			continue
		}
		if slot != "" && strings.HasPrefix(l, "  ") {
			s := p.Slots[slot]
			switch k {
			case "Private key type":
				s.KeyType = v
			case "Public key type":
				s.CertAlgo = v
			case "Subject DN":
				s.Subject = v
			case "Not after":
				s.NotAfter = v
			}
			p.Slots[slot] = s
			continue
		}
		switch k {
		case "PIV version":
			p.Version = v
		case "PIN tries remaining":
			p.PINTries = tries(v)
		case "PUK tries remaining":
			p.PUKTries = tries(v)
		case "Management key algorithm":
			p.MgmtAlgo = v
		}
	}
	if p.PUKBlocked {
		p.PUKTries = 0
	}
	return p
}

// PIVKey is parsed `ykman piv keys info`.
type PIVKey struct {
	Empty     bool
	Algorithm string
	Generated bool   // false: imported
	PIN       string // NEVER, ONCE, ALWAYS, MATCH_ONCE, MATCH_ALWAYS, DEFAULT
	Touch     string // NEVER, ALWAYS, CACHED, DEFAULT
}

func parsePIVKey(b []byte) PIVKey {
	var k PIVKey
	for _, l := range lines(b) {
		key, v, ok := splitKV(l)
		if !ok {
			continue
		}
		switch key {
		case "Algorithm":
			k.Algorithm = v
		case "Origin":
			k.Generated = v == "GENERATED"
		case "PIN required for use":
			k.PIN = v
		case "Touch required for use":
			k.Touch = v
		}
	}
	return k
}

// PIVInfo reads the PIV state. It verifies nothing, so it spends no tries.
func (c *Client) PIVInfo(ctx context.Context, serial string) (PIVInfo, error) {
	out, err := c.run(ctx, "--device", serial, "piv", "info")
	if err != nil {
		return PIVInfo{PINTries: -1, PUKTries: -1}, err
	}
	return parsePIVInfo(out), nil
}

// PIVKey reads one slot's key metadata.
func (c *Client) PIVKey(ctx context.Context, serial, slot string) (PIVKey, error) {
	out, err := c.run(ctx, "--device", serial, "piv", "keys", "info", slot)
	var ee *runner.ExitError
	if errors.As(err, &ee) && strings.Contains(ee.Stderr, "No key stored") {
		return PIVKey{Empty: true}, nil
	}
	if err != nil {
		return PIVKey{}, err
	}
	return parsePIVKey(out), nil
}

// ErrNotDefault: the credential was already changed; yking leaves it alone.
var ErrNotDefault = errors.New("not the factory default; left unchanged")

// ValidPIVSecret checks a new PIN or PUK: 6–8 printable ASCII characters.
func ValidPIVSecret(s string) error {
	if len(s) < 6 || len(s) > 8 {
		return errors.New("must be 6–8 characters")
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return errors.New("use letters, digits and symbols only")
		}
	}
	return nil
}

// fromDefaultRun re-reads the key, checks isDefault, then runs args with
// stdin (each prompt's answer on its own line).
func (c *Client) fromDefaultRun(ctx context.Context, serial string, isDefault func(PIVInfo) bool, stdin string, args ...string) error {
	sr, ok := c.r.(runner.StdinRunner)
	if !ok {
		return errors.New("runner cannot pass a secret on stdin")
	}
	info, err := c.PIVInfo(ctx, serial)
	if err != nil {
		return err
	}
	if !isDefault(info) {
		return ErrNotDefault
	}
	if k, err := Check(args); err != nil || k != FromDefault {
		return fmt.Errorf("refused: %v", err)
	}
	_, err = sr.RunStdin(ctx, []byte(stdin), Binary, args...)
	return err
}

// ChangePIVPIN replaces the default PIV PIN.
func (c *Client) ChangePIVPIN(ctx context.Context, serial, newPIN string) error {
	if err := ValidPIVSecret(newPIN); err != nil || newPIN == DefaultPIVPIN {
		return errors.New("invalid new PIN")
	}
	return c.fromDefaultRun(ctx, serial, func(p PIVInfo) bool { return p.DefaultPIN && p.PINTries > 0 },
		DefaultPIVPIN+"\n"+newPIN+"\n", "--device", serial, "piv", "access", "change-pin")
}

// ChangePIVPUK replaces the default PUK.
func (c *Client) ChangePIVPUK(ctx context.Context, serial, newPUK string) error {
	if err := ValidPIVSecret(newPUK); err != nil || newPUK == DefaultPIVPUK {
		return errors.New("invalid new PUK")
	}
	return c.fromDefaultRun(ctx, serial, func(p PIVInfo) bool { return p.DefaultPUK && !p.PUKBlocked && p.PUKTries != 0 },
		DefaultPIVPUK+"\n"+newPUK+"\n", "--device", serial, "piv", "access", "change-puk")
}

// ProtectPIVManagementKey replaces the default management key with a
// random one stored on the key, unlocked by the PIN. stdin answers ykman's
// two prompts: the current management key (blank = default), then the PIN.
func (c *Client) ProtectPIVManagementKey(ctx context.Context, serial, pin string) error {
	return c.fromDefaultRun(ctx, serial, func(p PIVInfo) bool { return p.DefaultMgmt && !p.MgmtStored && !p.MgmtDerived },
		"\n"+pin+"\n", "--device", serial, "piv", "access", "change-management-key", "--protect")
}
