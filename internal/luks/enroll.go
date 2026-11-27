package luks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
)

// HeaderBackupDir keeps LUKS header backups (root only).
const HeaderBackupDir = "/var/lib/yking/luks"

// Unlock is what unlocking with the key requires at boot.
type Unlock int

const (
	UnlockPINTouch Unlock = iota
	UnlockPIN
	UnlockTouch
)

func (u Unlock) String() string { return [...]string{"PIN + touch", "PIN only", "touch only"}[u] }

// ParseUnlock accepts "pin+touch" or "touch". "PIN only" is refused: a
// YubiKey always demands a touch for the hmac-secret disk unlocking uses
// (systemd-cryptenroll silently re-enables it).
func ParseUnlock(s string) (Unlock, error) {
	switch s {
	case "pin+touch", "":
		return UnlockPINTouch, nil
	case "touch":
		return UnlockTouch, nil
	case "pin":
		return 0, errors.New("\"PIN only\" is not possible for disk unlocking: the YubiKey always requires a touch there; use pin+touch")
	}
	return 0, fmt.Errorf("unlock must be pin+touch or touch (got %q)", s)
}

// PIN reports whether the PIN is part of unlocking.
func (u Unlock) PIN() bool { return u != UnlockTouch }

// Touch reports whether a touch is part of unlocking.
func (u Unlock) Touch() bool { return u != UnlockPIN }

var devRe = regexp.MustCompile(`^/dev/[A-Za-z0-9/_-]+$`)

// EnrollArgs are the fixed systemd-cryptenroll arguments. The existing
// passphrase and the PIN come from $PASSWORD / $PIN, never the command line.
func EnrollArgs(device, hidraw string, u Unlock) ([]string, error) {
	if !devRe.MatchString(device) || !regexp.MustCompile(`^/dev/hidraw[0-9]+$`).MatchString(hidraw) {
		return nil, errors.New("bad device path")
	}
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	return []string{
		"--fido2-device=" + hidraw,
		"--fido2-with-client-pin=" + yn(u.PIN()),
		"--fido2-with-user-presence=" + yn(u.Touch()),
		"--fido2-with-user-verification=no",
		device,
	}, nil
}

// BackupHeader stores a LUKS header backup and returns its path.
func BackupHeader(device, uuid string, now time.Time) (string, error) {
	if err := os.MkdirAll(HeaderBackupDir, 0o700); err != nil {
		return "", err
	}
	if !regexp.MustCompile(`^[0-9a-f-]+$`).MatchString(uuid) {
		return "", fmt.Errorf("bad uuid %q", uuid)
	}
	path := filepath.Join(HeaderBackupDir, uuid+"-"+now.UTC().Format("20060102-150405")+".img")
	cmd := exec.Command("cryptsetup", "luksHeaderBackup", device, "--header-backup-file", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("luksHeaderBackup: %v %s", err, bytes.TrimSpace(out))
	}
	os.Chmod(path, 0o600)
	return path, nil
}

// TestPassphrase checks the existing passphrase without opening anything.
func TestPassphrase(device string, pass []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cryptsetup", "open", "--test-passphrase", "--key-file=-", device)
	cmd.Stdin = bytes.NewReader(pass)
	if err := cmd.Run(); err != nil {
		return errors.New("the passphrase does not unlock " + device)
	}
	return nil
}

// RunEnroll runs systemd-cryptenroll without a controlling terminal. The
// existing passphrase comes from $PASSWORD; the FIDO2 PIN (which
// systemd-cryptenroll asks for through the ask-password agent protocol when
// creating a credential) is answered by AnswerPINOnce — once. Output goes
// to out.
func RunEnroll(args []string, pass, pin []byte, out *os.File) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemd-cryptenroll", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "PASSWORD=" + string(pass)}
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	agentCtx, stopAgent := context.WithCancel(ctx)
	agentErr := make(chan error, 1)
	go func() {
		if pin == nil {
			// No PIN expected: any request at all is unexpected.
			agentErr <- AnswerPINOnce(agentCtx, cmd.Process.Pid, nil, func() { cmd.Process.Kill() }, true)
			return
		}
		agentErr <- AnswerPINOnce(agentCtx, cmd.Process.Pid, pin, func() { cmd.Process.Kill() }, false)
	}()
	err := cmd.Wait()
	stopAgent()
	if aerr := <-agentErr; aerr != nil {
		cleanupAsks(cmd.Process.Pid)
		return aerr
	}
	cleanupAsks(cmd.Process.Pid)
	if err != nil {
		if ctx.Err() != nil {
			return errors.New("systemd-cryptenroll timed out (was the key touched?)")
		}
		return fmt.Errorf("systemd-cryptenroll failed: %w", err)
	}
	return nil
}

// cleanupAsks removes request files a killed process left behind.
func cleanupAsks(pid int) {
	files, _ := filepath.Glob(filepath.Join(AskDir, "ask.*"))
	for _, f := range files {
		if r, err := readAsk(f); err == nil && r.PID == pid {
			os.Remove(f)
			if filepath.Dir(filepath.Clean(r.Socket)) == filepath.Clean(AskDir) {
				os.Remove(r.Socket)
			}
		}
	}
}

// NewFIDO2Token returns the FIDO2 token in after that is not in before.
func NewFIDO2Token(before, after Header) (Token, error) {
	seen := map[int]bool{}
	for _, t := range before.FIDO2() {
		seen[t.ID] = true
	}
	var found []Token
	for _, t := range after.FIDO2() {
		if !seen[t.ID] {
			found = append(found, t)
		}
	}
	if len(found) != 1 || len(found[0].Keyslots) != 1 {
		return Token{}, fmt.Errorf("expected exactly one new FIDO2 token, found %d", len(found))
	}
	return found[0], nil
}

// RecordPlan records the new slot on serial's keyring entry.
func RecordPlan(krPath, serial string, slot keyring.LUKSSlot, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	kr, err := keyring.Parse(base.Data)
	if err != nil {
		return nil, err
	}
	k := kr.Find(serial)
	if k == nil {
		return nil, fmt.Errorf("key %s is not registered", serial)
	}
	var keep []keyring.LUKSSlot
	for _, s := range k.LUKS { // a slot number reused after a wipe replaces the old record
		if !(s.DeviceUUID == slot.DeviceUUID && s.Keyslot == slot.Keyslot) {
			keep = append(keep, s)
		}
	}
	k.LUKS = append(keep, slot)
	content, err := kr.Encode()
	if err != nil {
		return nil, err
	}
	p := plan.New(fmt.Sprintf("record LUKS keyslot %d (%s) on key %q", slot.Keyslot, slot.Mapper, k.Label), now)
	p.Replace(base, content, 0o644)
	return p, nil
}

// Wipe overwrites a byte slice (best effort for secrets).
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
