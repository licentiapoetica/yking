package pam

import (
	"fmt"
	"slices"
	"strings"
)

// Mode is how a service uses the key.
type Mode int

const (
	ModeOff  Mode = iota // no pam_u2f
	ModeOr               // key OR password (sufficient, before password)
	ModeAnd              // password AND key (required, after password)
	ModeOnly             // key only, password never asked
)

// Modes in display order.
var Modes = []Mode{ModeOff, ModeOr, ModeAnd, ModeOnly}

func (m Mode) String() string {
	switch m {
	case ModeOr:
		return "key or password"
	case ModeAnd:
		return "password + key"
	case ModeOnly:
		return "key only"
	default:
		return "off"
	}
}

func (m Mode) tag() string {
	return [...]string{"off", "or", "and", "only"}[m]
}

// NeedsPassword reports whether the password still works on its own.
func (m Mode) PasswordWorks() bool { return m == ModeOff || m == ModeOr }

// Unlock is what the key itself requires.
type Unlock int

const (
	UnlockPINTouch Unlock = iota
	UnlockPIN
	UnlockTouch
)

// Unlocks in display order.
var Unlocks = []Unlock{UnlockPINTouch, UnlockPIN, UnlockTouch}

func (u Unlock) String() string {
	return [...]string{"PIN + touch", "PIN only", "touch only"}[u]
}

func (u Unlock) tag() string { return [...]string{"pin+touch", "pin", "touch"}[u] }

func (u Unlock) args() []string {
	switch u {
	case UnlockPIN:
		return []string{"pinverification=1", "userpresence=0"}
	case UnlockTouch:
		return []string{"pinverification=0", "userpresence=1"}
	default:
		return []string{"pinverification=1", "userpresence=1"}
	}
}

// Config is the desired pam_u2f setup for one service.
type Config struct {
	Mode   Mode
	Unlock Unlock
	// Interactive makes pam_u2f prompt "Insert your FIDO authenticator,
	// then press ENTER." and wait, instead of failing when no key is there.
	Interactive bool
	// Extra are pam_u2f arguments yking does not interpret (kept verbatim
	// when taking over a hand-written line), e.g. authfile=…
	Extra []string
}

func (c Config) String() string {
	if c.Mode == ModeOff {
		return "off"
	}
	return c.Mode.String() + " · " + c.Unlock.String()
}

// Marker is the comment yking puts above its line.
const markerPrefix = "# yking: managed pam_u2f line below"

func (c Config) lines() []Line {
	if c.Mode == ModeOff {
		return nil
	}
	control := map[Mode]string{ModeOr: "sufficient", ModeAnd: "required", ModeOnly: "[success=done default=die]"}[c.Mode]
	args := append(c.Unlock.args(), "cue")
	if c.Interactive {
		args = append(args, "interactive")
	}
	args = append(args, c.Extra...)
	rule := fmt.Sprintf("auth %s pam_u2f.so %s", control, strings.Join(args, " "))
	extraTag := ""
	if c.Interactive {
		extraTag = " interactive"
	}
	marker := fmt.Sprintf("%s (mode=%s unlock=%s%s) — change it with yking", markerPrefix, c.Mode.tag(), c.Unlock.tag(), extraTag)
	l, _ := parseRule(rule)
	l.Raw = rule
	return []Line{{Raw: marker, Comment: true}, l}
}

// Classify infers the current Config from a file's lines. ok=false means
// the pam_u2f setup is something yking does not understand (it then leaves
// the service alone).
func Classify(lines []Line) (cfg Config, ok bool, why string) {
	var u2f []int
	firstAuth, passwordIdx := -1, -1
	for i, l := range lines {
		if l.IsU2F() {
			u2f = append(u2f, i)
			continue
		}
		if l.IsAuth() {
			if firstAuth < 0 {
				firstAuth = i
			}
			if passwordIdx < 0 && (l.IsInclude() || l.Module == "pam_unix.so") {
				passwordIdx = i
			}
		}
	}
	if len(u2f) == 0 {
		return Config{Mode: ModeOff}, true, ""
	}
	if len(u2f) > 1 {
		return cfg, false, "more than one pam_u2f line"
	}
	l := lines[u2f[0]]
	if l.Type != "auth" || l.Optional {
		return cfg, false, "pam_u2f line is not a plain auth rule"
	}
	cfg.Unlock, cfg.Interactive, cfg.Extra = classifyArgs(l.Args)
	before := firstAuth < 0 || u2f[0] < firstAuth
	switch l.Control {
	case "sufficient":
		if passwordIdx < 0 {
			// Nothing to fall back to: effectively key only.
			cfg.Mode = ModeOnly
		} else if before {
			cfg.Mode = ModeOr
		} else {
			return cfg, false, "sufficient pam_u2f after other auth rules"
		}
	case "required", "requisite":
		if passwordIdx < 0 {
			cfg.Mode = ModeOnly
		} else {
			cfg.Mode = ModeAnd
		}
	case "[success=done default=die]":
		if !before {
			return cfg, false, "key-only rule after other auth rules"
		}
		cfg.Mode = ModeOnly
	default:
		return cfg, false, "unrecognised control " + l.Control
	}
	return cfg, true, ""
}

func classifyArgs(args []string) (Unlock, bool, []string) {
	pin, presence, interactive := false, true, false // pam_u2f defaults: no PIN, presence required
	var extra []string
	for _, a := range args {
		switch a {
		case "pinverification=1":
			pin = true
		case "pinverification=0":
			pin = false
		case "userpresence=1":
			presence = true
		case "userpresence=0":
			presence = false
		case "interactive":
			interactive = true
		case "cue":
		default:
			extra = append(extra, a)
		}
	}
	switch {
	case pin && !presence:
		return UnlockPIN, interactive, extra
	case pin:
		return UnlockPINTouch, interactive, extra
	default:
		return UnlockTouch, interactive, extra
	}
}

// Base returns the lines with every pam_u2f line and yking marker removed.
func Base(lines []Line) []Line {
	var out []Line
	for _, l := range lines {
		if l.IsU2F() || (l.Comment && strings.HasPrefix(strings.TrimSpace(l.Raw), markerPrefix)) {
			continue
		}
		out = append(out, l)
	}
	return out
}

// HasRules reports whether lines contain any non-comment rule.
func HasRules(lines []Line) bool {
	return slices.ContainsFunc(lines, func(l Line) bool { return !l.Comment })
}

// Apply renders base with cfg's pam_u2f line in the right place.
func Apply(base []Line, cfg Config) ([]Line, error) {
	add := cfg.lines()
	if add == nil {
		return slices.Clone(base), nil
	}
	firstAuth, passwordIdx := -1, -1
	for i, l := range base {
		if l.IsAuth() {
			if firstAuth < 0 {
				firstAuth = i
			}
			if passwordIdx < 0 && (l.IsInclude() || l.Module == "pam_unix.so") {
				passwordIdx = i
			}
		}
	}
	var at int
	switch cfg.Mode {
	case ModeOr, ModeOnly:
		if cfg.Mode == ModeOr && passwordIdx < 0 {
			return nil, fmt.Errorf("no password rule to fall back to; \"key or password\" impossible")
		}
		at = firstAuth
		if at < 0 { // no auth rules: after the header comments
			at = 0
			for at < len(base) && base[at].Comment {
				at++
			}
		}
	case ModeAnd:
		if passwordIdx < 0 {
			return nil, fmt.Errorf("no password rule found; \"password + key\" impossible")
		}
		at = passwordIdx + 1
	}
	out := slices.Clone(base[:at])
	out = append(out, add...)
	return append(out, base[at:]...), nil
}

// Tag is the stable text form of a Mode ("off", "or", "and", "only").
func (m Mode) Tag() string { return m.tag() }

// Tag is the stable text form of an Unlock ("pin+touch", "pin", "touch").
func (u Unlock) Tag() string { return u.tag() }

// ParseMode parses Mode.Tag.
func ParseMode(s string) (Mode, error) {
	for _, m := range Modes {
		if m.tag() == s {
			return m, nil
		}
	}
	return 0, fmt.Errorf("unknown PAM mode %q", s)
}

// ParseUnlock parses Unlock.Tag.
func ParseUnlock(s string) (Unlock, error) {
	for _, u := range Unlocks {
		if u.tag() == s {
			return u, nil
		}
	}
	return 0, fmt.Errorf("unknown unlock %q", s)
}
