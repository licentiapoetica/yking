package ykman

import (
	"fmt"
	"regexp"
	"strings"
)

// This file is the safety boundary between yking and the user's YubiKeys.
//
// HARD RULE: yking never resets, wipes or overwrites data on a key. The user's
// main key holds many site registrations; a FIDO reset or PIN lockout would
// destroy them. Therefore:
//
//   - Every ykman invocation must exactly match a rule in the allowlist below.
//   - No rule may contain a destructive verb (see forbiddenTokens). A unit
//     test enforces this, so adding such a rule fails the build's tests.
//   - Add-only rules (programming an EMPTY OTP slot) run only through a
//     client method that re-reads the key right before and refuses unless
//     the target is empty (ProgramChalResp).
//   - The ONE exception to "never delete" is clearOTPSlot2 below: OTP slot
//     2 only, offered by the TUI only for a key whose slot just failed the
//     challenge-response test, after the user typed the key's label.

// Kind classifies what a rule does to the key.
type Kind int

const (
	// ReadOnly rules never change key state.
	ReadOnly Kind = iota
	// AddOnly rules write into an empty slot; their client method checks
	// that it is empty first.
	AddOnly
)

func (k Kind) String() string {
	switch k {
	case ReadOnly:
		return "read-only"
	case AddOnly:
		return "add-only"
	case Clear:
		return "clear OTP slot 2"
	default:
		return "unknown"
	}
}

// placeholder tokens in rule patterns.
const (
	serialArg  = "<serial>"
	pgpSlotArg = "<pgp-slot>" // sig, dec or aut
	hexArg     = "<hex>"      // a challenge (not a secret), 2–128 hex digits
)

var (
	serialRe = regexp.MustCompile(`^[0-9]{1,10}$`)
	hexRe    = regexp.MustCompile(`^([0-9a-f]{2}){1,64}$`)
)

type rule struct {
	name    string
	kind    Kind
	pattern []string
}

var allowlist = []rule{
	{"version", ReadOnly, []string{"--version"}},
	{"list", ReadOnly, []string{"list"}},
	{"list-serials", ReadOnly, []string{"list", "--serials"}},
	{"info", ReadOnly, []string{"--device", serialArg, "info"}},
	{"fido-info", ReadOnly, []string{"--device", serialArg, "fido", "info"}},
	{"otp-info", ReadOnly, []string{"--device", serialArg, "otp", "info"}},
	{"openpgp-info", ReadOnly, []string{"--device", serialArg, "openpgp", "info"}},
	{"openpgp-key-info", ReadOnly, []string{"--device", serialArg, "openpgp", "keys", "info", pgpSlotArg}},
	{"otp-calculate", ReadOnly, []string{"--device", serialArg, "otp", "calculate", "2", hexArg}},
	// The secret is read from stdin, never passed here.
	{"otp-chalresp", AddOnly, []string{"--device", serialArg, "otp", "chalresp", "2"}},
	{"otp-chalresp-touch", AddOnly, []string{"--device", serialArg, "otp", "chalresp", "--touch", "2"}},
}

// clearOTPSlot2 is the only deleting invocation yking may run
// (ClearChalResp). It is matched exactly, before the forbidden-token scan.
var clearOTPSlot2 = []string{"--device", serialArg, "otp", "delete", "2"}

// Clear marks the single deleting rule.
const Clear Kind = 100

// forbiddenTokens may never appear in any ykman invocation, no matter what
// the allowlist says. Defense in depth against a bad rule edit.
var forbiddenTokens = map[string]bool{
	"reset":                 true,
	"delete":                true,
	"set-pin":               true,
	"change-pin":            true,
	"change-puk":            true,
	"change-management-key": true,
	"unblock-pin":           true,
	"set-pin-retries":       true,
	"set-password":          true,
	"change-password":       true,
	"forget":                true,
	"disable":               true,
	"enable":                true,
	"mode":                  true,
	"set-lock-code":         true,
	"swap":                  true,
	"--force":               true,
	"-f":                    true,
}

// PolicyError means an invocation was refused before it ran.
type PolicyError struct {
	Args   []string
	Reason string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("refused ykman %s: %s", strings.Join(e.Args, " "), e.Reason)
}

// Check returns the matching rule's kind, or a *PolicyError if args are not
// allowed.
func Check(args []string) (Kind, error) {
	if matches(clearOTPSlot2, args) {
		return Clear, nil
	}
	for _, a := range args {
		if forbiddenTokens[strings.ToLower(a)] {
			return 0, &PolicyError{args, fmt.Sprintf("forbidden token %q", a)}
		}
	}
	for _, r := range allowlist {
		if matches(r.pattern, args) {
			return r.kind, nil
		}
	}
	return 0, &PolicyError{args, "not in allowlist"}
}

func matches(pattern, args []string) bool {
	if len(pattern) != len(args) {
		return false
	}
	for i, p := range pattern {
		switch p {
		case serialArg:
			if !serialRe.MatchString(args[i]) {
				return false
			}
		case hexArg:
			if !hexRe.MatchString(args[i]) {
				return false
			}
		case pgpSlotArg:
			if args[i] != "sig" && args[i] != "dec" && args[i] != "aut" {
				return false
			}
		default:
			if p != args[i] {
				return false
			}
		}
	}
	return true
}
