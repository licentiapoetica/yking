// Package events reacts to YubiKeys being plugged in or pulled out.
//
// udev (90-yking.rules) → systemctl start yking-event@add|remove.service →
// `/usr/local/bin/yking event add|remove` as root, headless.
//
// It never unlocks anything: plugging a key in only wakes a locked screen
// so the normal unlock prompt (with the key) appears.
package events

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// Installed file locations.
const (
	BinaryPath = "/usr/local/bin/yking"
	ConfigPath = "/etc/yking/events.toml"
	RulePath   = "/etc/udev/rules.d/90-yking.rules"
	UnitPath   = "/etc/systemd/system/yking-event@.service"
	StateDir   = "/run/yking"
)

// Config is /etc/yking/events.toml.
type Config struct {
	Version int      `toml:"version"`
	Users   []string `toml:"users"` // whose sessions / sudo cache are affected
	// Triggers are the serials whose removal locks. Empty = every
	// registered key.
	Triggers []string `toml:"triggers"`
	OnRemove Remove   `toml:"on_remove"`
	OnInsert Insert   `toml:"on_insert"`
}

// Remove actions.
type Remove struct {
	Lock      bool `toml:"lock"`       // lock the users' graphical sessions
	SudoReset bool `toml:"sudo_reset"` // forget cached sudo authentication
}

// Insert actions.
type Insert struct {
	Wake bool `toml:"wake"` // wake a LOCKED screen so the unlock prompt shows
}

var (
	userRe   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	serialRe = regexp.MustCompile(`^[0-9]{1,10}$`)
)

// Parse decodes and validates the config.
func Parse(b []byte) (*Config, error) {
	var c Config
	md, err := toml.Decode(string(b), &c)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("unknown keys %v", und)
	}
	return &c, c.Validate()
}

// Validate checks the config.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported events config version %d", c.Version)
	}
	if len(c.Users) == 0 {
		return errors.New("no users configured")
	}
	for _, u := range c.Users {
		if !userRe.MatchString(u) || u == "root" {
			return fmt.Errorf("invalid user %q", u)
		}
	}
	for _, s := range c.Triggers {
		if !serialRe.MatchString(s) {
			return fmt.Errorf("invalid trigger serial %q", s)
		}
	}
	return nil
}

// Encode renders the config.
func (c *Config) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("# Managed by yking (YubiKey plug/unplug actions). Edit with yking.\n")
	enc := toml.NewEncoder(&b)
	enc.Indent = ""
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// IsTrigger reports whether removing serial should run the remove actions.
func (c *Config) IsTrigger(serial string, registered []string) bool {
	if len(c.Triggers) == 0 {
		return slices.Contains(registered, serial)
	}
	return slices.Contains(c.Triggers, serial)
}

// Rule is the exact udev rule yking installs. It matches Yubico USB
// devices (vendor 1050) by the kernel's PRODUCT variable, which is present
// on both add and remove, and only starts the systemd unit; all work
// happens there.
const Rule = `# Managed by yking. YubiKey plugged in / pulled out → yking-event@ACTION.service
ACTION=="add|remove", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ENV{PRODUCT}=="1050/*", RUN+="/usr/bin/systemctl --no-block start yking-event@$env{ACTION}.service"
`

// Unit is the exact systemd template unit yking installs.
const Unit = `# Managed by yking.
[Unit]
Description=yking: YubiKey %i event

[Service]
Type=oneshot
ExecStart=` + BinaryPath + ` event %i
TimeoutStartSec=30
# Hardening: it only needs ykman, loginctl, busctl and /run (incl. the
# user's session bus under /run/user, so no ProtectHome).
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run
PrivateTmp=yes
`

// ValidateRule accepts only yking's own rule, byte for byte.
func ValidateRule(path string, content []byte) error {
	if path != RulePath && !strings.HasSuffix(path, "/90-yking.rules") {
		return fmt.Errorf("yking only writes its own udev rule, not %s", path)
	}
	if string(content) != Rule {
		return errors.New("udev rule differs from the one yking generates")
	}
	return nil
}

// ValidateUnit accepts only yking's own unit, byte for byte.
func ValidateUnit(path string, content []byte) error {
	if !strings.HasSuffix(path, "/yking-event@.service") {
		return fmt.Errorf("yking only writes its own unit, not %s", path)
	}
	if string(content) != Unit {
		return errors.New("systemd unit differs from the one yking generates")
	}
	return nil
}

// ValidateBinary accepts only an ELF file named yking.
func ValidateBinary(path string, content []byte) error {
	if !strings.HasSuffix(path, "/yking") {
		return fmt.Errorf("only the yking binary may be installed, not %s", path)
	}
	if !bytes.HasPrefix(content, []byte("\x7fELF")) {
		return errors.New("not an ELF executable")
	}
	return nil
}
