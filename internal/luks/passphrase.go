package luks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
)

// Removing the passphrase leaves the FIDO2 keys (and, by default, a
// recovery key) as the only ways into the volume. RemovalBlocked lists
// every reason not to do it yet.

// RemovalState is what RemovalBlocked looks at.
type RemovalState struct {
	Volume  Volume
	Header  Header
	Boot    Boot
	Pending string // an interrupted boot change
	Keys    []keyring.Key
}

// KeysOn returns the labels of registered keys whose recorded FIDO2 slot is
// present on the volume.
func (st RemovalState) KeysOn() []string {
	present := map[int]bool{}
	for _, t := range st.Header.FIDO2() {
		for _, s := range t.Keyslots {
			present[s] = true
		}
	}
	var out []string
	for _, k := range st.Keys {
		for _, s := range k.LUKS {
			if s.DeviceUUID == st.Volume.UUID && present[s.Keyslot] {
				out = append(out, k.Label)
				break
			}
		}
	}
	return out
}

// RemovalBlocked returns why the passphrase may not be removed ("" = ok).
func RemovalBlocked(st RemovalState) string {
	switch {
	case !st.Volume.Root:
		return "only the root volume: other volumes are opened by the desktop, which cannot use FIDO2"
	case st.Volume.Version != 2:
		return "needs LUKS2"
	case st.Pending != "":
		return "a boot change was interrupted; run `yking luks repair` first"
	case st.Boot.Method != "sd-encrypt":
		return "boot does not unlock with FIDO2 yet (`yking luks migrate`)"
	case len(st.Boot.Problems) > 0:
		return "boot has problems: " + st.Boot.Problems[0]
	case len(st.Header.PasswordSlots()) == 0:
		return "no passphrase slot left"
	case len(st.KeysOn()) < 2:
		return fmt.Sprintf("needs at least 2 registered keys enrolled on the volume (now: %d)", len(st.KeysOn()))
	}
	return ""
}

// TestToken checks that a FIDO2 token unlocks device, the way boot does
// (cryptsetup's systemd-fido2 plugin; PIN and touch on the terminal). One
// PIN attempt only.
func TestToken(device string, tty *os.File) error {
	if !devRe.MatchString(device) {
		return errors.New("bad device")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cryptsetup", "open", "--test-passphrase", "--token-only",
		"--token-type", "systemd-fido2", "--tries", "1", device)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	if err := cmd.Run(); err != nil {
		return errors.New("the plugged-in key did not unlock " + device)
	}
	return nil
}

// TestTokenPIN is TestToken without a terminal: the PIN goes to
// cryptsetup on stdin (read up to the newline), messages to out.
func TestTokenPIN(device string, pin []byte, out io.Writer) error {
	if !devRe.MatchString(device) {
		return errors.New("bad device")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cryptsetup", "open", "--test-passphrase", "--token-only",
		"--token-type", "systemd-fido2", "--tries", "1", device)
	in := append(bytes.Clone(pin), '\n')
	defer Wipe(in)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(in), out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Run(); err != nil {
		return errors.New("the plugged-in key did not unlock " + device)
	}
	return nil
}

// recoveryRe matches a systemd recovery key: 8 groups of 8 modhex letters.
var recoveryRe = regexp.MustCompile(`[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}`)

// ParseRecoveryKey finds the recovery key in systemd-cryptenroll's output.
func ParseRecoveryKey(out []byte) ([]byte, error) {
	all := recoveryRe.FindAll(out, -1)
	if len(all) != 1 {
		return nil, fmt.Errorf("expected one recovery key in the output, found %d", len(all))
	}
	return all[0], nil
}

// EnrollRecovery adds a systemd recovery key, unlocking with pass, and
// returns it.
func EnrollRecovery(device string, pass []byte) ([]byte, error) {
	if !devRe.MatchString(device) {
		return nil, errors.New("bad device")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemd-cryptenroll", "--recovery-key", device)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "PASSWORD=" + string(pass)}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // no terminal: no QR code, no prompts
	err := cmd.Run()
	defer Wipe(out.Bytes())
	if err != nil {
		return nil, fmt.Errorf("systemd-cryptenroll --recovery-key failed: %w: %s", err, bytes.TrimSpace(errb.Bytes()))
	}
	key, err := ParseRecoveryKey(append(out.Bytes(), errb.Bytes()...))
	if err != nil {
		return nil, err
	}
	return bytes.Clone(key), nil
}

// VerifyHeaderBackup checks that path is a LUKS header of the volume uuid.
func VerifyHeaderBackup(path, uuid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "cryptsetup", "luksUUID", path).Output()
	if err != nil {
		return fmt.Errorf("%s is not a readable LUKS header: %w", path, err)
	}
	if got := string(bytes.TrimSpace(out)); got != uuid {
		return fmt.Errorf("%s belongs to %s, not %s", path, got, uuid)
	}
	return nil
}

// CopyHeaderBackup copies a header backup into dir (0600, owned by uid/gid
// when >= 0) and returns the new path. An existing file is never replaced.
func CopyHeaderBackup(src, dir string, uid, gid int) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", errors.New("folder must be an absolute path")
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%s is not a folder", dir)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	dst := filepath.Join(dir, filepath.Base(src))
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if uid >= 0 {
		os.Chown(dst, uid, gid)
	}
	return dst, nil
}

// SameFilesystem reports whether a and b live on the same filesystem.
func SameFilesystem(a, b string) bool {
	var sa, sb syscall.Stat_t
	return syscall.Stat(a, &sa) == nil && syscall.Stat(b, &sb) == nil && sa.Dev == sb.Dev
}
