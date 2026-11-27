package pgp

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Card is what the copy needs to know about the target YubiKey.
type Card struct {
	Serial string
	// Slot returns a slot's current fingerprint ("" = empty).
	Slot func(ctx context.Context, slot string) (fpr, touch string, err error)
	// Connected lists the serials of all plugged-in YubiKeys.
	Connected func(ctx context.Context) ([]string, error)
}

// CopyRequest copies an identity's subkeys to one card.
type CopyRequest struct {
	Primary string
	Writes  []SlotWrite
	Touch   bool
	// Source: armored secret subkeys from a backup file (nil = export
	// them from the user's GnuPG home).
	Source []byte
}

// CopyResult says what ended up on the card.
type CopyResult struct {
	Written []SlotWrite // newly written
	Present []SlotWrite // already there, untouched
	Touch   []string    // slots whose touch policy is now on
}

// Copy runs the whole copy. askPass returns the key passphrase (only asked
// if the keys have one); askPIN the card's Admin PIN. log reports steps.
func Copy(ctx context.Context, user GPG, card Card, req CopyRequest, askPass func() (string, error), askPIN AskPIN, log func(string)) (CopyResult, error) {
	var res CopyResult
	if len(req.Writes) == 0 {
		return res, errors.New("nothing to copy")
	}
	check := func() error {
		serials, err := card.Connected(ctx)
		if err != nil {
			return err
		}
		if len(serials) != 1 || serials[0] != card.Serial {
			return fmt.Errorf("plug in only YubiKey %s (connected: %s)", card.Serial, strings.Join(serials, ", "))
		}
		return nil
	}
	if err := check(); err != nil {
		return res, err
	}

	// Never overwrite: every slot must be empty or hold this very subkey.
	var todo []SlotWrite
	for _, w := range req.Writes {
		fpr, _, err := card.Slot(ctx, w.Slot)
		if err != nil {
			return res, fmt.Errorf("reading %s slot: %w", w.Slot, err)
		}
		switch fpr {
		case "":
			todo = append(todo, w)
		case w.Fingerprint:
			res.Present = append(res.Present, w)
		default:
			return res, fmt.Errorf("%s slot holds another key (%s); nothing written", w.Slot, Short(fpr))
		}
	}

	id, err := user.Find(ctx, req.Primary)
	if err != nil {
		return res, err
	}
	var subs []string
	for _, w := range todo {
		s := id.SubkeyByFpr(w.Fingerprint)
		if s == nil {
			return res, fmt.Errorf("subkey %s is not part of %s", Short(w.Fingerprint), id.Name())
		}
		if req.Source == nil && s.Where != WhereDisk {
			return res, fmt.Errorf("subkey %s is not on disk (card-only already?); use a backup file", Short(w.Fingerprint))
		}
		subs = append(subs, w.Fingerprint)
	}

	pass := ""
	if len(todo) > 0 {
		protected := true
		if req.Source == nil {
			protected = false
			for _, f := range subs {
				p, err := user.Protected(ctx, id.SubkeyByFpr(f).Keygrip)
				if err != nil {
					return res, err
				}
				protected = protected || p
			}
		}
		if protected {
			if pass, err = askPass(); err != nil {
				return res, err
			}
		}
		secret := req.Source
		if secret == nil {
			log("Exporting subkeys")
			if secret, err = user.ExportSecretSubkeys(ctx, pass, subs); err != nil {
				return res, err
			}
		}
		pub, err := user.ExportPublic(ctx, req.Primary)
		if err != nil {
			return res, err
		}

		tmp, cleanup, err := RuntimeHome()
		if err != nil {
			return res, err
		}
		defer cleanup()
		log("Preparing a temporary GnuPG home")
		if err := tmp.Import(ctx, "", pub); err != nil {
			return res, err
		}
		if err := tmp.Import(ctx, pass, secret); err != nil {
			return res, err
		}
		tid, err := tmp.Find(ctx, req.Primary)
		if err != nil {
			return res, err
		}
		for _, w := range todo {
			s := tid.SubkeyByFpr(w.Fingerprint)
			if s == nil || s.Where != WhereDisk {
				return res, fmt.Errorf("subkey %s missing in the export", Short(w.Fingerprint))
			}
			if pass != "" {
				if err := tmp.Preset(ctx, s.Keygrip, pass); err != nil {
					return res, err
				}
			}
		}
		pass = ""

		user.Kill("scdaemon") // free the card
		if err := check(); err != nil {
			return res, err
		}
		log("Writing to the card")
		kc := &keytocard{cardDialog: cardDialog{serial: card.Serial, ask: askPIN}, writes: todo}
		derr := tmp.dialog(ctx, kc.status, kc.answer, "--edit-key", req.Primary)
		for _, slot := range kc.done {
			for _, w := range todo {
				if w.Slot == slot {
					res.Written = append(res.Written, w)
				}
			}
		}
		if kc.err != nil {
			return res, kc.err
		}
		if derr != nil {
			return res, derr
		}
		if len(kc.done) != len(todo) {
			return res, errors.New("gpg stopped before all slots were written")
		}

		if req.Touch {
			log("Setting touch")
			u := &uif{cardDialog: kc.cardDialog, slots: nil}
			for _, w := range append(append([]SlotWrite{}, res.Present...), res.Written...) {
				u.slots = append(u.slots, w.Slot)
			}
			u.cardOK = false
			if err := tmp.dialog(ctx, u.status, u.answer, "--card-edit"); err != nil && u.err == nil {
				u.err = err
			}
			if u.err != nil {
				return res, u.err
			}
		}
	}

	// Verify against the card itself.
	for _, w := range append(append([]SlotWrite{}, res.Present...), res.Written...) {
		fpr, touch, err := card.Slot(ctx, w.Slot)
		if err != nil {
			return res, fmt.Errorf("verifying %s: %w", w.Slot, err)
		}
		if fpr != w.Fingerprint {
			return res, fmt.Errorf("%s slot holds %s, expected %s", w.Slot, Short(fpr), Short(w.Fingerprint))
		}
		if strings.EqualFold(touch, "on") {
			res.Touch = append(res.Touch, w.Slot)
		}
	}
	return res, nil
}
