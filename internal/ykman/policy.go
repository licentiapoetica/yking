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
//   - Only read-only rules exist in M1. Add-only rules (e.g. programming an
//     EMPTY OTP slot) arrive in later milestones and must carry a
//     precondition check run against a fresh inventory of the key.

// Kind classifies what a rule does to the key.
type Kind int

const (
	// ReadOnly rules never change key state.
	ReadOnly Kind = iota
)

func (k Kind) String() string {
	switch k {
	case ReadOnly:
		return "read-only"
	default:
		return "unknown"
	}
}

// placeholder tokens in rule patterns.
const serialArg = "<serial>"

var serialRe = regexp.MustCompile(`^[0-9]{1,10}$`)

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
}

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
		default:
			if p != args[i] {
				return false
			}
		}
	}
	return true
}
