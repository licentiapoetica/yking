// Package transfer exports yking's setup from one machine and imports it on
// another. Machine-specific parts (PAM credentials, which are bound to the
// hostname, and LUKS slots, which belong to a disk) are not copied; the
// import guides through recreating them with the same keys.
//
// The export contains NO secrets (no PIN, no passphrase) but does contain the
// SSH key handle files (~/.ssh/yk-main-0X): treat it like a key file.
package transfer

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/fsutil"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// Version of the export format.
const Version = 1

// Export is the whole file.
type Export struct {
	Version int       `toml:"version"`
	Created time.Time `toml:"created"`
	// Keys: serial, label, role, protected, model, SSH keys (with servers).
	// U2F records are dropped (hostname-bound). LUKS records are kept only
	// as information which keys were enrolled.
	Keys     []keyring.Key         `toml:"key"`
	PAM      map[string]PAMSetting `toml:"pam,omitempty"`
	Events   *events.Config        `toml:"events,omitempty"`
	SSHFiles []SSHFile             `toml:"ssh_file,omitempty"`
}

// PAMSetting is the desired mode of one PAM service.
type PAMSetting struct {
	Mode        string `toml:"mode"`
	Unlock      string `toml:"unlock"`
	Interactive bool   `toml:"interactive,omitempty"`
}

// SSHFile is one SSH key handle file pair.
type SSHFile struct {
	Name    string `toml:"name"`    // file name in ~/.ssh
	Private string `toml:"private"` // base64 of the handle file
	Public  string `toml:"public"`  // the .pub line
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Options for Build.
type Options struct {
	Keyring  *keyring.Keyring
	PAM      []pam.State
	Events   *events.Config
	User     string
	SSHFiles bool // include the handle files
	Now      time.Time
}

// Build assembles an export from the current machine.
func Build(o Options) (*Export, error) {
	if o.Keyring == nil || len(o.Keyring.Keys) == 0 {
		return nil, errors.New("no registered keys to export")
	}
	e := &Export{Version: Version, Created: o.Now.UTC().Truncate(time.Second), PAM: map[string]PAMSetting{}, Events: o.Events}
	for _, k := range o.Keyring.Keys {
		k.U2F = nil
		k.LastSeen, k.LastTested = time.Time{}, time.Time{}
		for i := range k.SSH {
			s := &k.SSH[i]
			s.User = ""
			if o.SSHFiles && s.Path != "" {
				priv, err := os.ReadFile(s.Path)
				if err != nil {
					return nil, fmt.Errorf("SSH key %s: %w", s.Path, err)
				}
				pub := s.PublicKey
				if pub == "" {
					b, err := os.ReadFile(s.Path + ".pub")
					if err != nil {
						return nil, err
					}
					pub = strings.TrimSpace(string(b))
				}
				e.SSHFiles = append(e.SSHFiles, SSHFile{Name: filepath.Base(s.Path), Private: base64.StdEncoding.EncodeToString(priv), Public: pub})
			}
			s.Path = filepath.Base(s.Path) // re-rooted to ~/.ssh on import
		}
		e.Keys = append(e.Keys, k)
	}
	for _, st := range o.PAM {
		if st.Custom != "" || st.Current.Mode == pam.ModeOff {
			continue
		}
		e.PAM[st.Service.Name] = PAMSetting{Mode: st.Current.Mode.Tag(), Unlock: st.Current.Unlock.Tag(), Interactive: st.Current.Interactive}
	}
	if o.Events != nil {
		c := *o.Events
		c.Users = nil // re-filled with the importing user
		e.Events = &c
	}
	return e, e.Validate()
}

// Encode renders the export.
func (e *Export) Encode() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("# yking export. Contains SSH key handles (useless without the YubiKey, but private):\n# keep it like a key file, never commit or publish it.\n")
	enc := toml.NewEncoder(&b)
	enc.Indent = ""
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Parse reads and validates an export.
func Parse(b []byte) (*Export, error) {
	var e Export
	md, err := toml.Decode(string(b), &e)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("unknown keys %v", und)
	}
	return &e, e.Validate()
}

// Validate checks structure and that every SSH file matches its key.
func (e *Export) Validate() error {
	if e.Version != Version {
		return fmt.Errorf("unsupported export version %d", e.Version)
	}
	kr := &keyring.Keyring{Version: keyring.SchemaVersion, Keys: e.Keys}
	if err := kr.Validate(); err != nil {
		return err
	}
	for name, s := range e.PAM {
		known := false
		for _, svc := range pam.Known {
			if svc.Name == name {
				known = true
			}
		}
		if !known {
			return fmt.Errorf("unknown PAM service %q", name)
		}
		if _, err := pam.ParseMode(s.Mode); err != nil {
			return err
		}
		if _, err := pam.ParseUnlock(s.Unlock); err != nil {
			return err
		}
	}
	if e.Events != nil {
		c := *e.Events
		c.Users = []string{"placeholder"}
		if err := c.Validate(); err != nil {
			return fmt.Errorf("events: %w", err)
		}
	}
	fps := map[string]string{} // file name → fingerprint from the keyring
	for _, k := range e.Keys {
		for _, s := range k.SSH {
			if !nameRe.MatchString(s.Path) {
				return fmt.Errorf("bad SSH file name %q", s.Path)
			}
			fps[s.Path] = s.Fingerprint
		}
	}
	for _, f := range e.SSHFiles {
		if !nameRe.MatchString(f.Name) || strings.HasSuffix(f.Name, ".pub") {
			return fmt.Errorf("bad SSH file name %q", f.Name)
		}
		pk, err := sshkey.ParsePub(f.Public)
		if err != nil || !pk.IsSK() {
			return fmt.Errorf("%s: not a security-key public key", f.Name)
		}
		if fps[f.Name] != pk.Fingerprint {
			return fmt.Errorf("%s: public key does not match the recorded fingerprint", f.Name)
		}
		priv, err := base64.StdEncoding.DecodeString(f.Private)
		if err != nil || !bytes.Contains(priv, []byte("OPENSSH PRIVATE KEY")) {
			return fmt.Errorf("%s: not an OpenSSH key file", f.Name)
		}
	}
	return nil
}

// DesiredPAM returns the PAM settings as configs.
func (e *Export) DesiredPAM() map[string]pam.Config {
	out := map[string]pam.Config{}
	for name, s := range e.PAM {
		m, _ := pam.ParseMode(s.Mode)
		u, _ := pam.ParseUnlock(s.Unlock)
		out[name] = pam.Config{Mode: m, Unlock: u, Interactive: s.Interactive}
	}
	return out
}

// DesiredEvents returns the events config for user (nil if none).
func (e *Export) DesiredEvents(user string) *events.Config {
	if e.Events == nil {
		return nil
	}
	c := *e.Events
	c.Users = []string{user}
	return &c
}

// LUKSKeys lists labels of keys that had a LUKS slot on the old machine.
func (e *Export) LUKSKeys() []string {
	var out []string
	for _, k := range e.Keys {
		if len(k.LUKS) > 0 {
			out = append(out, k.Label)
		}
	}
	return out
}

// WriteSSHFiles puts the handle files into sshDir. Existing files are never
// overwritten: identical ones are fine, different ones are an error.
func WriteSSHFiles(e *Export, sshDir string) (written []string, err error) {
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return nil, err
	}
	for _, f := range e.SSHFiles {
		priv, _ := base64.StdEncoding.DecodeString(f.Private)
		for _, w := range []struct {
			path string
			data []byte
			mode os.FileMode
		}{
			{filepath.Join(sshDir, f.Name), priv, 0o600},
			{filepath.Join(sshDir, f.Name+".pub"), []byte(strings.TrimSpace(f.Public) + "\n"), 0o644},
		} {
			cur, err := os.ReadFile(w.path)
			switch {
			case err == nil && bytes.Equal(bytes.TrimSpace(cur), bytes.TrimSpace(w.data)):
				continue
			case err == nil:
				return written, fmt.Errorf("%s exists with different content; yking never overwrites key files", w.path)
			case !errors.Is(err, fs.ErrNotExist):
				return written, err
			}
			if err := fsutil.WriteAtomic(w.path, w.data, w.mode); err != nil {
				return written, err
			}
			written = append(written, w.path)
		}
	}
	return written, nil
}

// KeyringPlan merges the exported keys into the local keyring: missing keys
// are added (SSH paths re-rooted to sshDir, owner user; no U2F/LUKS records,
// those are recreated on this machine). Existing serials are left alone.
func KeyringPlan(krPath string, e *Export, user, sshDir string, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	kr := keyring.New()
	if base.Exists {
		if kr, err = keyring.Parse(base.Data); err != nil {
			return nil, err
		}
	}
	added := 0
	for _, k := range e.Keys {
		if kr.Find(k.Serial) != nil {
			continue
		}
		k.U2F, k.LUKS = nil, nil
		k.AddedAt = now.UTC().Truncate(time.Second)
		for i := range k.SSH {
			k.SSH[i].Path = filepath.Join(sshDir, k.SSH[i].Path)
			k.SSH[i].User = user
		}
		kr.Keys = append(kr.Keys, k)
		added++
	}
	if added == 0 {
		return nil, plan.ErrNoChanges
	}
	content, err := kr.Encode()
	if err != nil {
		return nil, err
	}
	p := plan.New(fmt.Sprintf("import: register %d key(s) with their SSH keys", added), now)
	p.Replace(base, content, 0o644)
	return p, nil
}

// PendingPath is where an import waits until all steps are done.
func PendingPath(home string) string {
	return filepath.Join(home, ".local", "state", "yking", "import.toml")
}

// SavePending stores the export for the import checklist (mode 600).
func SavePending(home string, e *Export) error {
	b, err := e.Encode()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(PendingPath(home)), 0o700); err != nil {
		return err
	}
	return fsutil.WriteAtomic(PendingPath(home), b, 0o600)
}

// LoadPending returns the pending import, or nil if there is none.
func LoadPending(home string) (*Export, error) {
	b, err := os.ReadFile(PendingPath(home))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(b)
}
