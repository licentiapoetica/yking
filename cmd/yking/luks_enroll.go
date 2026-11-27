package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/luks"
	"github.com/licentiapoetica/yking/internal/targets"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// newUI returns the TUI's prompts (sock) or the terminal's.
func newUI(sock string) (passUI, func(), error) {
	if sock != "" {
		return sockUI{sock}, func() {}, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, errors.New("needs a terminal")
	}
	return ttyUI{tty, bufio.NewReader(tty)}, func() { tty.Close() }, nil
}

func (u ttyUI) out() io.Writer  { return u.tty }
func (u sockUI) out() io.Writer { return os.Stderr }

// enrolledDevice finds, among the plugged FIDO devices, the one holding a
// FIDO2 slot of the volume — asked silently (no PIN, no touch, no attempt).
func enrolledDevice(ctx context.Context, devs []string, h luks.Header) (string, luks.Token, error) {
	found, tok := "", luks.Token{}
	for _, d := range devs {
		for _, t := range h.FIDO2() {
			if t.Credential == "" || t.RP == "" || len(t.Keyslots) != 1 {
				continue
			}
			if fido.Probe(ctx, d, t.RP, t.Credential) == nil {
				if found != "" && found != d {
					return "", tok, errors.New("both plugged-in keys are enrolled already")
				}
				found, tok = d, t
			}
		}
	}
	if found == "" {
		return "", tok, errors.New("none of the plugged-in keys answered for a slot of this disk")
	}
	return found, tok, nil
}

// ownerOf is the registered key recorded for a keyslot of the volume.
func ownerOf(kr *keyring.Keyring, uuid string, keyslot int) *keyring.Key {
	for i := range kr.Keys {
		for _, s := range kr.Keys[i].LUKS {
			if s.DeviceUUID == uuid && s.Keyslot == keyslot {
				return &kr.Keys[i]
			}
		}
	}
	return nil
}

func luksEnroll(c *ykman.Client, krPath string, args []string) error {
	fs := flag.NewFlagSet("luks enroll", flag.ExitOnError)
	device := fs.String("device", "", "LUKS device (default: the one holding /)")
	unlockS := fs.String("unlock", "pin+touch", "what unlocking needs: pin+touch or touch")
	sock := fs.String("tui", "", "started by the TUI: ask over this askpass socket")
	fs.Parse(args)
	unlock, err := luks.ParseUnlock(*unlockS)
	if err != nil {
		return err
	}
	ctx := context.Background()

	v, err := rootVolume(*device)
	if err != nil {
		return err
	}
	if v.Version != 2 {
		return fmt.Errorf("%s is LUKS%d; FIDO2 needs LUKS2", v.Device, v.Version)
	}
	before, err := luks.ReadHeader(v.Device)
	if err != nil {
		return err
	}
	kr, err := keyring.Load(krPath)
	if err != nil {
		return err
	}
	devs, err := fido.Devices(fido.DefaultSysRoot)
	if err != nil {
		return err
	}
	serials, err := c.ListSerials(ctx)
	if err != nil {
		return err
	}
	hasSecret := len(before.PasswordSlots()) > 0 || before.HasRecovery()

	// One key: the passphrase (or recovery key) unlocks. Two keys: the
	// enrolled one unlocks, the other is the new one.
	var newDev, authDev string
	var authKey *keyring.Key
	var authTok luks.Token
	switch {
	case len(devs) == 1 && len(serials) == 1:
		if !hasSecret {
			return errors.New("this disk has no passphrase: plug in an enrolled key next to the new one")
		}
		newDev = devs[0]
	case len(devs) == 2 && len(serials) == 2:
		authDev, authTok, err = enrolledDevice(ctx, devs, before)
		if err != nil {
			return err
		}
		authKey = ownerOf(kr, v.UUID, authTok.Keyslots[0])
		if authKey == nil || !slices.Contains(serials, authKey.Serial) {
			return fmt.Errorf("the enrolled key (slot %d) is not a registered key here; run yking luks identify --record with it", authTok.Keyslots[0])
		}
		newDev = devs[0]
		if newDev == authDev {
			newDev = devs[1]
		}
		serials = slices.DeleteFunc(slices.Clone(serials), func(s string) bool { return s == authKey.Serial })
	default:
		return fmt.Errorf("plug in the new key alone, or next to one enrolled key (now: %d FIDO device(s), serials %v)", len(devs), serials)
	}

	k := kr.Find(serials[0])
	if k == nil {
		return fmt.Errorf("key %s is not registered in %s", serials[0], krPath)
	}
	for _, s := range k.LUKS {
		if s.DeviceUUID == v.UUID {
			for _, slot := range before.Slots {
				if slot.ID == s.Keyslot && slot.Token != nil {
					return fmt.Errorf("%q is already enrolled on %s (keyslot %d)", k.Label, v.Device, s.Keyslot)
				}
			}
		}
	}
	f, err := c.FIDOInfo(ctx, k.Serial)
	if err != nil {
		return err
	}
	if unlock.PIN() {
		if ok, why := f.PINPromptAllowed(); !ok {
			return errors.New(k.Label + ": " + why)
		}
	}
	if authKey != nil && authTok.PINRequired {
		af, err := c.FIDOInfo(ctx, authKey.Serial)
		if err != nil {
			return err
		}
		if ok, why := af.PINPromptAllowed(); !ok {
			return errors.New(authKey.Label + ": " + why)
		}
	}

	ui, closeUI, err := newUI(*sock)
	if err != nil {
		return err
	}
	defer closeUI()
	if authKey != nil {
		ui.say("Enrolling %q (%s) into %s (%s), unlocked by %q — unlock at boot: %s.", k.Label, k.Serial, v.Device, v.Mapper, authKey.Label, unlock)
	} else {
		ui.say("Enrolling %q (%s) into %s (%s) — unlock at boot: %s.", k.Label, k.Serial, v.Device, v.Mapper, unlock)
	}

	backup, err := luks.BackupHeader(v.Device, v.UUID, time.Now())
	if err != nil {
		return err
	}
	ui.say("LUKS header backed up to %s", backup)

	var pass []byte
	if authKey == nil {
		ui.phase("current passphrase")
		pass, err = ui.secret("Current LUKS passphrase or recovery key of " + v.Device)
		if err != nil || len(pass) == 0 {
			return errors.New("no passphrase entered")
		}
		defer luks.Wipe(pass)
		if err := luks.TestPassphrase(v.Device, pass); err != nil {
			return err // no PIN attempt used
		}
	}

	// PINs, each asked once: the unlocking key's (if its slot needs one),
	// then the new key's.
	askPIN := func(label string, tries int) ([]byte, error) {
		ui.phase("PIN of " + label)
		pin, err := ui.secret(fmt.Sprintf("FIDO2 PIN of %s (%d tries left, asked once)", label, tries))
		if err != nil {
			return nil, err
		}
		if len([]rune(string(pin))) < max(f.MinPINLength, 4) {
			luks.Wipe(pin)
			return nil, errors.New("PIN too short; not sent (no attempt used)")
		}
		return pin, nil
	}
	var pins [][]byte
	defer func() {
		for _, p := range pins {
			luks.Wipe(p)
		}
	}()
	needAuth, needNew := authKey != nil && authTok.PINRequired, unlock.PIN()
	switch {
	case needAuth && needNew:
		same := ui.choose(fmt.Sprintf("Do %s and %s have the same FIDO2 PIN?", authKey.Label, k.Label),
			[]askpass.Option{{Key: "enter", Label: "yes, ask once"}, {Key: "d", Label: "different PINs"}, {Key: "n", Label: "cancel"}})
		switch same {
		case "enter":
			p, err := askPIN(authKey.Label+" and "+k.Label, f.PINRetries)
			if err != nil {
				return err
			}
			pins = append(pins, p, p)
		case "d":
			af, _ := c.FIDOInfo(ctx, authKey.Serial)
			p1, err := askPIN(authKey.Label, af.PINRetries)
			if err != nil {
				return err
			}
			pins = append(pins, p1)
			p2, err := askPIN(k.Label, f.PINRetries)
			if err != nil {
				return err
			}
			pins = append(pins, p2)
		default:
			return errors.New("cancelled; nothing changed")
		}
	case needAuth:
		af, _ := c.FIDOInfo(ctx, authKey.Serial)
		p, err := askPIN(authKey.Label, af.PINRetries)
		if err != nil {
			return err
		}
		pins = append(pins, p)
	case needNew:
		p, err := askPIN(k.Label, f.PINRetries)
		if err != nil {
			return err
		}
		pins = append(pins, p)
	}

	if authKey != nil {
		ui.say("Touch %s when it blinks, then %s.", authKey.Label, k.Label)
		eargs, err := luks.EnrollWithKeyArgs(v.Device, authDev, newDev, unlock)
		if err != nil {
			return err
		}
		if err := luks.RunEnrollWithKey(eargs, pins, ui.out()); err != nil {
			return fmt.Errorf("%w (if a PIN was wrong, one attempt was used; header backup: %s)", err, backup)
		}
	} else {
		ui.say("Touch %s when it blinks (creating the credential always needs one touch).", k.Label)
		eargs, err := luks.EnrollArgs(v.Device, newDev, unlock)
		if err != nil {
			return err
		}
		var pin []byte
		if len(pins) > 0 {
			pin = pins[0]
		}
		if err := luks.RunEnroll(eargs, pass, pin, ui.out()); err != nil {
			return fmt.Errorf("%w (if the PIN was wrong, one attempt was used; header backup: %s)", err, backup)
		}
	}

	after, err := luks.ReadHeader(v.Device)
	if err != nil {
		return err
	}
	tok, err := luks.NewFIDO2Token(before, after)
	if err != nil {
		return err
	}
	ui.say("Enrolled: keyslot %d (token %d).", tok.Keyslots[0], tok.ID)

	slot := keyring.LUKSSlot{DeviceUUID: v.UUID, Mapper: v.Mapper, Keyslot: tok.Keyslots[0], Token: tok.ID,
		PINRequired: tok.PINRequired, UPRequired: tok.UPRequired, EnrolledAt: time.Now().UTC().Truncate(time.Second)}
	p, err := luks.RecordPlan(krPath, k.Serial, slot, time.Now())
	if err != nil {
		return fmt.Errorf("enrolled, but recording failed: %w", err)
	}
	m, err := targets.Applier().Apply(p)
	if err != nil {
		return fmt.Errorf("enrolled, but recording failed: %w", err)
	}
	ui.say("Recorded in the keyring (%s).", m.ID)
	if b := luks.DiscoverBoot(); b.Method == "encrypt" {
		ui.say("Boot still uses the old \"encrypt\" hook, which ignores FIDO2; switch it with yking luks migrate.")
	}
	return nil
}
