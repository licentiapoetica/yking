// Package keyring is yking's registry of known YubiKeys. It stores no
// secrets: only serials, labels, roles and public identifiers (credential
// handles, SSH fingerprints, deployed hosts).
package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/licentiapoetica/yking/internal/fsutil"
)

// DefaultPath is where the system keyring lives.
const DefaultPath = "/etc/yking/keyring.toml"

// SchemaVersion is the current file format version.
const SchemaVersion = 1

// Role is a key's job in the set.
type Role string

const (
	RoleDaily      Role = "daily"
	RoleHomeBackup Role = "home-backup"
	RoleOffsite    Role = "offsite"
)

// Roles lists valid roles in display order.
var Roles = []Role{RoleDaily, RoleHomeBackup, RoleOffsite}

func (r Role) Valid() bool {
	for _, v := range Roles {
		if r == v {
			return true
		}
	}
	return false
}

// Keyring is the whole registry file.
type Keyring struct {
	Version int          `toml:"version"`
	Keys    []Key        `toml:"key"`
	Revoked []RevokedKey `toml:"revoked,omitempty"`
}

// RevokedKey remembers a key that was revoked, and what could not be
// cleaned up (e.g. a server that was unreachable).
type RevokedKey struct {
	Serial    string     `toml:"serial"`
	Label     string     `toml:"label"`
	Role      Role       `toml:"role"`
	RevokedAt time.Time  `toml:"revoked_at"`
	Leftovers []Leftover `toml:"leftover,omitempty"`
}

// Leftover is an SSH public key still deployed on a host after revoke.
type Leftover struct {
	Fingerprint string `toml:"fingerprint"`
	Comment     string `toml:"comment,omitempty"`
	Host        string `toml:"host"`
}

// Key is one registered YubiKey.
type Key struct {
	Serial string `toml:"serial"`
	Label  string `toml:"label"`
	Role   Role   `toml:"role"`
	// Protected keys require typing the label to confirm any write.
	Protected bool   `toml:"protected"`
	Model     string `toml:"model,omitempty"`
	Firmware  string `toml:"firmware,omitempty"`

	AddedAt    time.Time `toml:"added_at"`
	LastSeen   time.Time `toml:"last_seen,omitempty"`
	LastTested time.Time `toml:"last_tested,omitempty"`

	U2F  []U2FCred  `toml:"u2f,omitempty"`
	SSH  []SSHKey   `toml:"ssh,omitempty"`
	LUKS []LUKSSlot `toml:"luks,omitempty"`
}

// LUKSSlot records a FIDO2 keyslot this key unlocks.
type LUKSSlot struct {
	DeviceUUID  string    `toml:"device_uuid"`
	Mapper      string    `toml:"mapper,omitempty"`
	Keyslot     int       `toml:"keyslot"`
	Token       int       `toml:"token"`
	PINRequired bool      `toml:"pin_required"`
	UPRequired  bool      `toml:"up_required"`
	EnrolledAt  time.Time `toml:"enrolled_at"`
}

// U2FCred records a pam_u2f mapping created by yking (public data only).
type U2FCred struct {
	User      string    `toml:"user"`
	KeyHandle string    `toml:"key_handle"` // as written to u2f_keys
	CreatedAt time.Time `toml:"created_at"`
}

// SSHKey records an SSH security-key credential created with this key.
type SSHKey struct {
	Fingerprint     string    `toml:"fingerprint"` // SHA256:...
	Type            string    `toml:"type"`        // sk-ssh-ed25519@openssh.com etc.
	Resident        bool      `toml:"resident"`
	VerifyRequired  bool      `toml:"verify_required,omitempty"`   // PIN on every use
	NoTouchRequired bool      `toml:"no_touch_required,omitempty"` // PIN without touch; authorized_keys needs "no-touch-required"
	Application     string    `toml:"application,omitempty"`       // e.g. ssh:yking
	User            string    `toml:"user,omitempty"`              // local account owning the key file
	Path            string    `toml:"path,omitempty"`              // private key handle file
	Comment         string    `toml:"comment,omitempty"`
	PublicKey       string    `toml:"public_key,omitempty"` // the .pub line (public); needed to remove it from servers
	Hosts           []string  `toml:"hosts,omitempty"`      // user@host where the pubkey was deployed
	CreatedAt       time.Time `toml:"created_at"`
}

var serialRe = regexp.MustCompile(`^[0-9]{1,10}$`)

// New returns an empty keyring.
func New() *Keyring { return &Keyring{Version: SchemaVersion} }

// Load reads path. A missing file yields an empty keyring, not an error.
func Load(path string) (*Keyring, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, err
	}
	k, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// Parse decodes and validates keyring TOML.
func Parse(b []byte) (*Keyring, error) {
	var k Keyring
	md, err := toml.Decode(string(b), &k)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("unknown keys %v", und)
	}
	if k.Version > SchemaVersion {
		return nil, fmt.Errorf("schema version %d is newer than this yking supports (%d)", k.Version, SchemaVersion)
	}
	if k.Version < 1 {
		return nil, fmt.Errorf("missing or invalid schema version")
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return &k, nil
}

// Encode renders the keyring as TOML.
func (k *Keyring) Encode() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("# Managed by yking. Contains no secrets.\n")
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(k); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Save writes the keyring atomically. Normally only the elevated apply step
// writes the system keyring; this is for tests and tooling.
func (k *Keyring) Save(path string) error {
	b, err := k.Encode()
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(path, b, 0o644)
}

// Validate checks structural invariants.
func (k *Keyring) Validate() error {
	seenSerial := map[string]bool{}
	seenLabel := map[string]bool{}
	for i, key := range k.Keys {
		if !serialRe.MatchString(key.Serial) {
			return fmt.Errorf("key %d: invalid serial %q", i, key.Serial)
		}
		if seenSerial[key.Serial] {
			return fmt.Errorf("key %d: duplicate serial %s", i, key.Serial)
		}
		seenSerial[key.Serial] = true
		if key.Label == "" {
			return fmt.Errorf("key %s: empty label", key.Serial)
		}
		if seenLabel[key.Label] {
			return fmt.Errorf("key %s: duplicate label %q", key.Serial, key.Label)
		}
		seenLabel[key.Label] = true
		if !key.Role.Valid() {
			return fmt.Errorf("key %s: invalid role %q", key.Serial, key.Role)
		}
	}
	return nil
}

// Find returns the key with serial, or nil.
func (k *Keyring) Find(serial string) *Key {
	for i := range k.Keys {
		if k.Keys[i].Serial == serial {
			return &k.Keys[i]
		}
	}
	return nil
}

// Add registers a new key. New keys start Protected; the user can relax that
// explicitly. The returned pointer points into k.Keys and is only valid
// until the next Add (use Find afterwards).
func (k *Keyring) Add(serial, label string, role Role, now time.Time) (*Key, error) {
	if k.Find(serial) != nil {
		return nil, fmt.Errorf("key %s already registered", serial)
	}
	k.Keys = append(k.Keys, Key{
		Serial:    serial,
		Label:     label,
		Role:      role,
		Protected: true,
		AddedAt:   now.UTC().Truncate(time.Second),
	})
	if err := k.Validate(); err != nil {
		k.Keys = k.Keys[:len(k.Keys)-1]
		return nil, err
	}
	return &k.Keys[len(k.Keys)-1], nil
}

// Revoke removes the key and records it under Revoked with leftovers.
func (k *Keyring) Revoke(serial string, leftovers []Leftover, now time.Time) error {
	for i, key := range k.Keys {
		if key.Serial == serial {
			k.Keys = append(k.Keys[:i:i], k.Keys[i+1:]...)
			k.Revoked = append(k.Revoked, RevokedKey{
				Serial: key.Serial, Label: key.Label, Role: key.Role,
				RevokedAt: now.UTC().Truncate(time.Second), Leftovers: leftovers,
			})
			return nil
		}
	}
	return fmt.Errorf("key %s is not registered", serial)
}

// MeetsMinimumKeys reports whether at least two keys are registered, which
// every feature that can lock the user out (key-only PAM, LUKS) requires.
func (k *Keyring) MeetsMinimumKeys() bool { return len(k.Keys) >= 2 }
