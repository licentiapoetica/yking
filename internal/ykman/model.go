package ykman

import "fmt"

// Device is one line of `ykman list`.
type Device struct {
	Description string // e.g. "YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID]"
	Serial      string // empty if not readable
}

// AppState is the enabled state of one application per transport.
type AppState struct {
	USB string // "Enabled", "Disabled", "Not available"
	NFC string // empty when the key has no NFC
}

// DeviceInfo is parsed `ykman info`.
type DeviceInfo struct {
	DeviceType    string
	Serial        string
	Firmware      string
	FormFactor    string
	USBInterfaces string
	Apps          map[string]AppState
}

// FIDOInfo is parsed `ykman fido info`.
type FIDOInfo struct {
	PINSet         bool
	PINBlocked     bool
	PINRetries     int // -1 = unknown
	MinPINLength   int // 0 = unknown
	CredsRemaining int // -1 = unknown
	AlwaysUV       string
}

// SlotState is the state of one OTP slot.
type SlotState int

const (
	SlotUnknown SlotState = iota
	SlotEmpty
	SlotProgrammed
)

func (s SlotState) String() string {
	switch s {
	case SlotEmpty:
		return "empty"
	case SlotProgrammed:
		return "programmed"
	default:
		return "unknown"
	}
}

// MarshalText renders the state as a word in JSON output.
func (s SlotState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// OTPInfo is parsed `ykman otp info`.
type OTPInfo struct {
	Slot1, Slot2 SlotState
}

// MinPINRetriesToPrompt is the lowest remaining-retries count at which yking
// will still ask for the FIDO2 PIN. Eight wrong PINs block FIDO2, and the
// only way out is a reset, which would wipe every site registration. Stop well
// before that.
const MinPINRetriesToPrompt = 4

// PINPromptAllowed reports whether yking may ask the user for this key's
// FIDO2 PIN right now. Callers must show f.PINRetries in the prompt and must
// never retry automatically after a wrong PIN.
func (f FIDOInfo) PINPromptAllowed() (bool, string) {
	switch {
	case f.PINBlocked:
		return false, "FIDO2 PIN is blocked on this key"
	case !f.PINSet:
		return false, "no FIDO2 PIN set on this key (yking does not set PINs)"
	case f.PINRetries < 0:
		return false, "could not read remaining PIN retries"
	case f.PINRetries < MinPINRetriesToPrompt:
		return false, fmt.Sprintf("only %d PIN attempt(s) left; refusing to prompt (minimum %d)", f.PINRetries, MinPINRetriesToPrompt)
	default:
		return true, ""
	}
}
