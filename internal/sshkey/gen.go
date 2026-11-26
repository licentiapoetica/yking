package sshkey

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// KeygenBinary is the ssh-keygen executable. Only this package runs it.
const KeygenBinary = "ssh-keygen"

// GenRequest describes one SSH key to create with one YubiKey.
//
// Keys are always NON-resident: nothing is stored on the YubiKey, so no
// existing credential can be overwritten. The private key file in ~/.ssh is
// only a handle that is useless without the physical key. Touch is always
// set by Use.
type GenRequest struct {
	Serial   string
	Label    string
	Firmware string
	Dir      string // ~/.ssh
	Name     string // private key file name inside Dir
	Comment  string
	Use      Use
}

// Use is what every SSH login with the key requires.
type Use int

const (
	UsePINTouch Use = iota // PIN + touch (default)
	UsePIN                 // PIN, no touch
	UseTouch               // touch, no PIN
)

// Uses lists the choices in display order.
var Uses = []Use{UsePINTouch, UsePIN, UseTouch}

func (u Use) String() string {
	switch u {
	case UsePINTouch:
		return "PIN + touch"
	case UsePIN:
		return "PIN only"
	default:
		return "touch only"
	}
}

// Explain describes the choice for the user.
func (u Use) Explain() string {
	switch u {
	case UsePINTouch:
		return "every login: type the FIDO2 PIN and touch the key"
	case UsePIN:
		return "every login: type the PIN, no touch. Servers need \"no-touch-required\"\nin front of this key in authorized_keys (yking's deploy step adds it)"
	default:
		return "every login: touch the key, no PIN"
	}
}

// NeedsPIN reports whether logins (and therefore creation) use the PIN.
func (u Use) NeedsPIN() bool { return u == UsePINTouch || u == UsePIN }

// NoTouch reports whether logins skip the touch.
func (u Use) NoTouch() bool { return u == UsePIN }

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// NamePrefix is the user's naming scheme for key files: yk-main-01, -02, …
const NamePrefix = "yk-main-"

var numberedRe = regexp.MustCompile(`^` + regexp.QuoteMeta(NamePrefix) + `([0-9]+)(\.pub)?$`)

// NextName returns the next free yk-main-NN name in dir (two digits
// minimum), counting both private and .pub files.
func NextName(dir string) string {
	highest := 0
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if m := numberedRe.FindStringSubmatch(e.Name()); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil && n > highest {
					highest = n
				}
			}
		}
	}
	return fmt.Sprintf("%s%02d", NamePrefix, highest+1)
}

// DefaultComment is the key comment for a file name: the name itself
// (yk-main-02 → "yk-main-02").
func DefaultComment(name string) string { return name }

// KeyType picks ed25519-sk when the firmware supports it (5.2.3+), else
// ecdsa-sk.
func (r GenRequest) KeyType() string {
	if FirmwareAtLeast(r.Firmware, 5, 2, 3) {
		return "ed25519-sk"
	}
	return "ecdsa-sk"
}

// Paths returns the private and public key paths.
func (r GenRequest) Paths() (priv, pub string) {
	priv = filepath.Join(r.Dir, r.Name)
	return priv, priv + ".pub"
}

// Args returns the ssh-keygen arguments. -N "" because the file holds only
// a key handle; the YubiKey (touch, optionally PIN) is the protection.
func (r GenRequest) Args() []string {
	priv, _ := r.Paths()
	args := []string{"-t", r.KeyType(), "-N", "", "-C", r.Comment, "-f", priv}
	// no-touch-required is only ever combined with verify-required: a key
	// that needs neither PIN nor touch would sign for anything on the
	// machine while plugged in.
	if r.Use.NeedsPIN() {
		args = append(args, "-O", "verify-required")
	}
	if r.Use.NoTouch() {
		args = append(args, "-O", "no-touch-required")
	}
	return args
}

// Command builds the ssh-keygen command. env carries the askpass guard.
func (r GenRequest) Command(env []string) *exec.Cmd {
	cmd := exec.Command(KeygenBinary, r.Args()...)
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

// State is what Preflight needs to know about the machine right now.
type State struct {
	Key         detect.KeyReport
	Serials     []string // ykman list --serials
	YubiKeys    int      // ykman list (incl. keys without serial)
	FIDODevices int      // all FIDO HID devices, any vendor
}

// Preflight returns every reason the request must not run. Empty = go.
func Preflight(r GenRequest, s State) []string {
	var p []string
	if s.Key.Known == nil {
		p = append(p, "key is not registered in the keyring; register it first (e)")
	}
	if len(s.Serials) != 1 || s.Serials[0] != r.Serial || s.YubiKeys != 1 || s.FIDODevices != 1 {
		p = append(p, fmt.Sprintf("exactly one FIDO key must be connected, and it must be %s (now: %d FIDO device(s), serials %v); unplug the others", r.Serial, s.FIDODevices, s.Serials))
	}
	if s.Key.Info.Apps != nil && s.Key.Info.Apps["FIDO2"].USB != "Enabled" {
		p = append(p, "FIDO2 is not enabled over USB on this key (yking will not change that)")
	}
	if f := s.Key.FIDO; f != nil {
		if f.PINBlocked {
			p = append(p, "FIDO2 PIN is blocked")
		} else if f.PINSet && f.PINRetries >= 0 && f.PINRetries < ykman.MinPINRetriesToPrompt {
			p = append(p, fmt.Sprintf("only %d PIN attempts left; refusing anything that could ask for the PIN", f.PINRetries))
		}
		if r.Use.NeedsPIN() {
			if ok, why := f.PINPromptAllowed(); !ok {
				p = append(p, r.Use.String()+" needs the PIN: "+why)
			}
		}
	} else {
		p = append(p, "could not read FIDO2 state of this key")
	}
	if !nameRe.MatchString(r.Name) || strings.HasSuffix(r.Name, ".pub") {
		p = append(p, fmt.Sprintf("invalid file name %q (letters, digits, . _ - only)", r.Name))
	} else {
		priv, pub := r.Paths()
		for _, path := range []string{priv, pub} {
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				p = append(p, path+" already exists; yking never overwrites key files")
			}
		}
	}
	if strings.ContainsAny(r.Comment, "\n\r") {
		p = append(p, "comment must be a single line")
	}
	return p
}

// FirmwareAtLeast compares a dotted firmware version.
func FirmwareAtLeast(v string, want ...int) bool {
	parts := strings.Split(strings.TrimSpace(v), ".")
	for i, w := range want {
		if i >= len(parts) {
			return false
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return false
		}
		if n != w {
			return n > w
		}
	}
	return true
}

// RecordPlan builds a plan adding a created SSH key to serial's keyring
// entry. Refuses a fingerprint already recorded on any key.
func RecordPlan(krPath, serial string, entry keyring.SSHKey, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	if !base.Exists {
		return nil, fmt.Errorf("%s does not exist; register the key first", krPath)
	}
	kr, err := keyring.Parse(base.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", krPath, err)
	}
	for _, k := range kr.Keys {
		for _, s := range k.SSH {
			if s.Fingerprint == entry.Fingerprint {
				return nil, fmt.Errorf("SSH key %s is already recorded on key %s", entry.Fingerprint, k.Label)
			}
		}
	}
	k := kr.Find(serial)
	if k == nil {
		return nil, fmt.Errorf("key %s is not registered", serial)
	}
	k.SSH = append(k.SSH, entry)
	content, err := kr.Encode()
	if err != nil {
		return nil, err
	}
	p := plan.New(fmt.Sprintf("record SSH key %s on key %q", filepath.Base(entry.Path), k.Label), now)
	p.Replace(base, content, 0o644)
	return p, nil
}

// SignTestNamespace is the signature namespace of yking's ownership test.
const SignTestNamespace = "yking-link-test"

// SignTestCommand signs a throwaway file with privPath to prove which
// YubiKey holds it (needs touch and, for verify-required keys, the PIN;
// env carries the askpass PIN guard). Nothing is stored anywhere.
func SignTestCommand(privPath, dataFile string, env []string) *exec.Cmd {
	cmd := exec.Command(KeygenBinary, SignTestArgs(privPath, dataFile)...)
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

// SignTestArgs are the fixed arguments of the ownership test.
func SignTestArgs(privPath, dataFile string) []string {
	return []string{"-Y", "sign", "-f", privPath, "-n", SignTestNamespace, dataFile}
}

// LinkEntry builds the keyring record for an SSH key made outside yking.
func LinkEntry(pub PubKey, priv string, h SKHandle, user string, hosts []string, now time.Time) keyring.SSHKey {
	line := strings.TrimSpace(string(must(os.ReadFile(pub.Path))))
	return keyring.SSHKey{
		Fingerprint:     pub.Fingerprint,
		Type:            pub.Type,
		Resident:        h.Resident(),
		VerifyRequired:  h.PINRequired(),
		NoTouchRequired: !h.TouchRequired(),
		Application:     h.Application,
		User:            user,
		Path:            priv,
		Comment:         pub.Comment,
		PublicKey:       line,
		Hosts:           hosts,
		CreatedAt:       now.UTC().Truncate(time.Second),
	}
}

func must(b []byte, _ error) []byte { return b }
