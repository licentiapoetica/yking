package pgp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// gpg is driven through its status/command protocol (--status-fd,
// --command-fd): it prints "[GNUPG:] GET_LINE keyedit.prompt" and reads one
// answer line. The dialogs below answer only what they expect; anything
// else is cancelled.

// AskPIN returns the Admin PIN. It is called at most once per dialog run.
type AskPIN func() (string, error)

// cardDialog is the PIN policy shared by keytocard and uif: the Admin PIN
// is sent only to the card with the expected serial, and asked again only
// after it was proven right (an operation succeeded since).
type cardDialog struct {
	serial  string // the YubiKey's serial (decimal)
	ask     AskPIN
	pin     string
	pinSent bool
	proven  bool   // an admin operation succeeded after the PIN was sent
	cardOK  bool   // CARDCTRL named the expected card
	failed  string // SC_OP_FAILURE / error seen
	err     error  // why yking stopped
}

func (c *cardDialog) status(kw string, args []string) {
	switch kw {
	case "CARDCTRL":
		// "CARDCTRL 3 D2760001240100000006123456780000": the AID carries the
		// serial as decimal digits right before the last four.
		c.cardOK = len(args) >= 2 && aidSerial(args[1]) == c.serial
	case "SC_OP_FAILURE":
		c.failed = "card operation failed"
		if len(args) > 0 && args[0] == "2" {
			c.failed = "Admin PIN not accepted"
		}
	case "SC_OP_SUCCESS":
		if c.pinSent {
			c.proven = true
		}
	}
}

// hidden answers GET_HIDDEN (the Admin PIN). An empty answer cancels
// without using a PIN try.
func (c *cardDialog) hidden() string {
	if c.err != nil || c.failed != "" {
		return ""
	}
	if !c.cardOK {
		c.err = errors.New("PIN asked for an unexpected card; cancelled")
		return ""
	}
	if c.pinSent && !c.proven {
		c.err = errors.New("Admin PIN asked again; cancelled so no try is used")
		return ""
	}
	if !c.pinSent {
		pin, err := c.ask()
		if err != nil {
			c.err = err
			return ""
		}
		c.pin = pin
	}
	c.pinSent, c.proven = true, false
	return c.pin
}

// aidSerial extracts the serial from an OpenPGP card AID
// (D276000124 01 vvvv mmmm ssssssss 0000).
func aidSerial(aid string) string {
	if len(aid) != 32 || !strings.HasPrefix(strings.ToUpper(aid), "D2760001240") {
		return ""
	}
	s := strings.TrimLeft(aid[20:28], "0")
	if s == "" {
		s = "0"
	}
	return s
}

// handler answers one GET_* request; ok=false means "not mine".
type handler func(kind, keyword string) (answer string)

// drive runs the protocol: status lines from st, answers to cmd.
func drive(st io.Reader, cmd io.Writer, onStatus func(kw string, args []string), answer handler) error {
	sc := bufio.NewScanner(st)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "[GNUPG:] ") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "[GNUPG:] "))
		if len(f) == 0 {
			continue
		}
		kw, args := f[0], f[1:]
		if strings.HasPrefix(kw, "GET_") {
			key := ""
			if len(args) > 0 {
				key = args[0]
			}
			if _, err := io.WriteString(cmd, answer(kw, key)+"\n"); err != nil {
				return err
			}
			continue
		}
		onStatus(kw, args)
	}
	return sc.Err()
}

// SlotWrite is one subkey to move into a slot.
type SlotWrite struct {
	Slot        string // sig, dec, aut
	Fingerprint string
}

// keytocard is the --edit-key dialog moving subkeys to the card.
type keytocard struct {
	cardDialog
	writes []SlotWrite
	i      int
	step   int // 0 select, 1 keytocard, 2 check+deselect
	done   []string
	quit   bool
}

func (k *keytocard) answer(kind, kw string) string {
	switch {
	case kind == "GET_LINE" && kw == "keyedit.prompt":
		if k.quit || k.err != nil || k.i >= len(k.writes) {
			return "quit"
		}
		w := k.writes[k.i]
		switch k.step {
		case 0:
			k.step = 1
			return "key " + w.Fingerprint
		case 1:
			k.step = 2
			k.failed = ""
			return "keytocard"
		default:
			if k.failed != "" {
				k.err = fmt.Errorf("%s slot: %s", w.Slot, k.failed)
				return "quit"
			}
			if k.pinSent {
				k.proven = true // keytocard returned to the prompt without failure
			}
			k.done = append(k.done, w.Slot)
			k.i, k.step = k.i+1, 0
			return "key " + w.Fingerprint // deselect
		}
	case kind == "GET_LINE" && kw == "cardedit.genkeys.storekeytype":
		if k.step != 2 {
			k.err = errors.New("unexpected slot question")
			return ""
		}
		return SlotNumber(k.writes[k.i].Slot)
	case kind == "GET_BOOL" && strings.HasPrefix(kw, "cardedit.genkeys.replace_key"):
		k.err = fmt.Errorf("%s slot is not empty; nothing overwritten", k.writes[k.i].Slot)
		return "n"
	case kind == "GET_BOOL" && kw == "keyedit.save.okay":
		return "n" // the throwaway home is deleted anyway
	case kind == "GET_HIDDEN":
		return k.hidden()
	}
	if k.err == nil {
		k.err = fmt.Errorf("unexpected gpg question %s %s; cancelled", kind, kw)
	}
	if kind == "GET_BOOL" {
		return "n"
	}
	if kind == "GET_LINE" && kw == "keyedit.prompt" {
		return "quit"
	}
	return ""
}

// uif is the --card-edit dialog setting touch policies.
type uif struct {
	cardDialog
	slots []string
	i     int
	admin bool
	done  []string
}

func (u *uif) answer(kind, kw string) string {
	switch {
	case kind == "GET_LINE" && kw == "cardedit.prompt":
		if u.err != nil {
			return "quit"
		}
		if !u.admin {
			u.admin = true
			return "admin"
		}
		if u.i > 0 && u.failed != "" {
			u.err = fmt.Errorf("touch for %s: %s", u.slots[u.i-1], u.failed)
			return "quit"
		}
		if u.i > 0 {
			if u.pinSent {
				u.proven = true
			}
			u.done = append(u.done, u.slots[u.i-1])
		}
		if u.i >= len(u.slots) {
			return "quit"
		}
		u.failed = ""
		u.i++
		return "uif " + SlotNumber(u.slots[u.i-1]) + " on"
	case kind == "GET_HIDDEN":
		return u.hidden()
	}
	if u.err == nil {
		u.err = fmt.Errorf("unexpected gpg question %s %s; cancelled", kind, kw)
	}
	if kind == "GET_BOOL" {
		return "n"
	}
	if kind == "GET_LINE" && kw == "cardedit.prompt" {
		return "quit"
	}
	return ""
}
