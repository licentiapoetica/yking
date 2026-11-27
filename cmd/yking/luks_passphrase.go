package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/luks"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// passUI is where luks passphrase remove talks to the user: the terminal,
// or the TUI over its askpass socket (--tui).
type passUI interface {
	say(format string, a ...any)
	// choose returns the key of the picked option ("" = cancelled).
	choose(prompt string, opts []askpass.Option) string
	secret(prompt string) ([]byte, error)
	phase(title string)
	// testToken lets the plugged-in key unlock device (PIN, then touch).
	testToken(device, label string) error
	// showKey shows the recovery key once and waits until it is written down.
	showKey(key []byte) error
	out() io.Writer // where tool output goes
}

type ttyUI struct {
	tty *os.File
	in  *bufio.Reader
}

func (u ttyUI) say(f string, a ...any) { fmt.Fprintf(u.tty, f+"\n", a...) }
func (u ttyUI) phase(t string)         { fmt.Fprintf(u.tty, "\n— %s\n", t) }
func (u ttyUI) secret(p string) ([]byte, error) {
	return readSecret(u.tty, p+": ")
}
func (u ttyUI) choose(prompt string, opts []askpass.Option) string {
	fmt.Fprintln(u.tty, prompt)
	for _, o := range opts {
		fmt.Fprintf(u.tty, "  %-6s %s\n", o.Key, o.Label)
	}
	fmt.Fprint(u.tty, "Choice: ")
	l, _ := u.in.ReadString('\n')
	l = strings.TrimSpace(l)
	for _, o := range opts {
		if l == o.Key || (l == "" && o.Key == "enter") {
			return o.Key
		}
	}
	return ""
}
func (u ttyUI) testToken(device, label string) error {
	u.say("Testing %q the way boot does: enter its FIDO2 PIN, then touch it.", label)
	return luks.TestToken(device, u.tty)
}
func (u ttyUI) showKey(key []byte) error {
	u.say("\nRecovery key — write it down now, it is shown only once:\n\n    %s\n", key)
	fmt.Fprint(u.tty, "Press Enter when it is written down. ")
	u.in.ReadString('\n')
	return nil
}

type sockUI struct{ sock string }

func (u sockUI) say(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
func (u sockUI) phase(t string)         { askpass.Phase(u.sock, t) }
func (u sockUI) secret(p string) ([]byte, error) {
	a, ok, err := askpass.Ask(u.sock, askpass.KindAsk, p)
	if err == nil && !ok {
		err = errors.New("cancelled")
	}
	return []byte(a), err
}
func (u sockUI) choose(prompt string, opts []askpass.Option) string {
	k, err := askpass.Choose(u.sock, prompt, opts, time.Time{})
	if err != nil {
		return ""
	}
	return k
}
func (u sockUI) testToken(device, label string) error {
	u.phase("test " + label + " the way boot does")
	pin, err := u.secret("FIDO2 PIN of " + label)
	if err != nil {
		return err
	}
	defer luks.Wipe(pin)
	u.say("Touch %s when it blinks.", label)
	return luks.TestTokenPIN(device, pin, os.Stderr)
}
func (u sockUI) showKey(key []byte) error {
	if u.choose("Recovery key — write it down now, it is shown only once:\n\n    "+string(key),
		[]askpass.Option{{Key: "enter", Label: "written down"}}) == "" {
		return errors.New("cancelled")
	}
	return nil
}

// luksPassphraseRemove removes the passphrase slot(s) of the root volume,
// replacing them with a recovery key (default) or nothing (key-only). It
// runs only when boot unlocks with FIDO2, two registered keys are enrolled
// and the plugged-in key just unlocked the volume the way boot does.
func luksPassphraseRemove(c *ykman.Client, krPath, sock string) error {
	ctx := context.Background()
	v, err := rootVolume("")
	if err != nil {
		return err
	}
	h, err := luks.ReadHeader(v.Device)
	if err != nil {
		return err
	}
	kr, err := keyring.Load(krPath)
	if err != nil {
		return err
	}
	st := luks.RemovalState{Volume: v, Header: h, Boot: luks.DiscoverBoot(), Pending: luks.Pending(), Keys: kr.Keys}
	if why := luks.RemovalBlocked(st); why != "" {
		return errors.New("not removing the passphrase: " + why)
	}
	pwSlots := h.PasswordSlots()

	// The plugged-in key: registered, enrolled here, PIN tries left.
	devs, err := fido.Devices(fido.DefaultSysRoot)
	if err != nil {
		return err
	}
	serials, err := c.ListSerials(ctx)
	if err != nil {
		return err
	}
	if len(devs) != 1 || len(serials) != 1 {
		return fmt.Errorf("plug in exactly one enrolled key (now: %d FIDO device(s), serials %v)", len(devs), serials)
	}
	k := kr.Find(serials[0])
	if k == nil || !slices.Contains(st.KeysOn(), k.Label) {
		return fmt.Errorf("key %s is not enrolled on %s", serials[0], v.Device)
	}
	if f, err := c.FIDOInfo(ctx, serials[0]); err != nil {
		return err
	} else if ok, why := f.PINPromptAllowed(); !ok {
		return errors.New(why)
	}

	ui, closeUI, err := newUI(sock)
	if err != nil {
		return err
	}
	defer closeUI()

	keyOnly := false
	switch ui.choose(fmt.Sprintf("Remove passphrase slot(s) %v of %s (%s).\nKeys that unlock it: %s.",
		pwSlots, v.Device, v.Mapper, strings.Join(st.KeysOn(), ", ")),
		[]askpass.Option{{Key: "enter", Label: "replace it with a recovery key"}, {Key: "k", Label: "key-only"}, {Key: "n", Label: "cancel"}}) {
	case "enter":
	case "k":
		keyOnly = true
		if ui.choose("! Key-only: if every key is lost or broken, or boot cannot use them, the data is gone.\n"+
			"! The GRUB fallback entry cannot unlock the disk any more.\n"+
			"! Adding a key then needs an enrolled key plugged in next to the new one.",
			[]askpass.Option{{Key: "K", Label: "key-only, I understand"}, {Key: "n", Label: "cancel"}}) != "K" {
			return errors.New("cancelled; nothing changed")
		}
	default:
		return errors.New("cancelled; nothing changed")
	}

	if err := ui.testToken(v.Device, k.Label); err != nil {
		return fmt.Errorf("%w; nothing changed", err)
	}
	ui.say("✓ %s unlocks the volume", k.Label)

	backup, err := luks.BackupHeader(v.Device, v.UUID, time.Now())
	if err != nil {
		return err
	}
	ui.say("LUKS header backed up to %s", backup)
	ui.phase("current passphrase")
	pass, err := ui.secret("Current LUKS passphrase of " + v.Device)
	if err != nil || len(pass) == 0 {
		return errors.New("no passphrase entered; nothing changed")
	}
	defer luks.Wipe(pass)
	if err := luks.TestPassphrase(v.Device, pass); err != nil {
		return fmt.Errorf("%w; nothing changed", err)
	}

	var rk []byte
	if !keyOnly {
		ui.phase("recovery key")
		rk, err = luks.EnrollRecovery(v.Device, pass)
		if err != nil {
			return fmt.Errorf("%w; the passphrase was not removed", err)
		}
		defer luks.Wipe(rk)
		if err := ui.showKey(rk); err != nil {
			return errors.New("recovery key not confirmed; the passphrase stays (the recovery key slot was added and also works)")
		}
		ok := false
		for range 3 {
			typed, err := ui.secret("Type the recovery key back")
			if err != nil {
				break
			}
			if strings.ReplaceAll(strings.ToLower(string(typed)), " ", "") == string(rk) {
				ok = true
				break
			}
			ui.say("does not match")
		}
		if !ok {
			return errors.New("recovery key not confirmed; the passphrase stays (the recovery key slot was added and also works)")
		}
		if err := luks.TestPassphrase(v.Device, rk); err != nil {
			return fmt.Errorf("the new recovery key does not unlock the volume; the passphrase stays: %w", err)
		}
		if tu, ok := ui.(ttyUI); ok {
			fmt.Fprint(tu.tty, "\033[H\033[2J\033[3J") // the key off the screen and out of the scrollback
		}
		ui.say("✓ recovery key confirmed and tested")
	}

	auth := pass // the wipe unlocks with a slot that stays, when there is one
	if rk != nil {
		auth = rk
	}
	if err := luks.RunWipe(v.Device, pwSlots, auth, ui.out()); err != nil {
		return fmt.Errorf("%w (header backup: %s)", err, backup)
	}
	after, err := luks.ReadHeader(v.Device)
	if err != nil {
		return err
	}
	if left := after.PasswordSlots(); len(left) > 0 {
		return fmt.Errorf("passphrase slot(s) %v still there; header backup: %s", left, backup)
	}
	if len(after.FIDO2()) != len(h.FIDO2()) {
		return fmt.Errorf("FIDO2 slots changed (%d → %d); header backup: %s", len(h.FIDO2()), len(after.FIDO2()), backup)
	}
	if rk != nil {
		if err := luks.TestPassphrase(v.Device, rk); err != nil {
			return fmt.Errorf("recovery key no longer unlocks; header backup: %s", backup)
		}
	}

	ui.say("Passphrase removed.")
	if rk != nil {
		ui.say("Without a key: type the recovery key where the passphrase was asked (also in the GRUB fallback entry and when enrolling a key).")
	}
	ui.say("Header backup %s still holds the old passphrase slot; delete it if anyone else knows that passphrase.", backup)
	return nil
}
