package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/pgp"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// Result lines on stdout, read by the TUI.
const pgpMark = "YKING-PGP"

// cmdPGP: the TUI runs these as children; prompts go to the TUI over the
// askpass socket. yking pgp tocard|new|add-sign|backup|card-only|learn
func cmdPGP(c *ykman.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: yking pgp tocard|new|add-sign|backup|card-only|learn")
	}
	sock := os.Getenv(askpass.EnvSock)
	if sock == "" {
		return errors.New("yking pgp runs from the TUI (g)")
	}
	ask := func(prompt string) (string, error) {
		a, ok, err := askpass.Ask(sock, askpass.KindAsk, prompt)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("cancelled")
		}
		return a, nil
	}
	log := func(s string) { fmt.Fprintln(os.Stderr, s) }
	ctx := context.Background()
	user := pgp.GPG{}
	fs := flag.NewFlagSet("pgp "+args[0], flag.ContinueOnError)
	primary := fs.String("primary", "", "primary key fingerprint")
	var subs multiFlag
	fs.Var(&subs, "sub", "subkey fingerprint (repeatable)")

	switch args[0] {
	case "tocard":
		serial := fs.String("serial", "", "YubiKey serial")
		label := fs.String("label", "", "YubiKey label")
		var writes multiFlag
		fs.Var(&writes, "write", "slot=fingerprint (repeatable)")
		touch := fs.Bool("touch", false, "require touch for each use")
		from := fs.String("from", "", "backup file with the secret subkeys")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		req := pgp.CopyRequest{Primary: *primary, Touch: *touch}
		for _, w := range writes {
			slot, fpr, ok := strings.Cut(w, "=")
			if !ok || pgp.SlotNumber(slot) == "" {
				return fmt.Errorf("bad --write %q", w)
			}
			req.Writes = append(req.Writes, pgp.SlotWrite{Slot: slot, Fingerprint: fpr})
		}
		if *from != "" {
			b, err := os.ReadFile(*from)
			if err != nil {
				return err
			}
			req.Source = b
		}
		card := pgp.Card{
			Serial: *serial,
			Slot: func(ctx context.Context, slot string) (string, string, error) {
				s, err := c.PGPSlot(ctx, *serial, slot)
				return s.Fingerprint, s.Touch, err
			},
			Connected: c.ListSerials,
		}
		askPIN := func() (string, error) {
			info, err := c.OpenPGPInfo(ctx, *serial)
			if err != nil {
				return "", err
			}
			if ok, why := info.AdminPromptAllowed(); !ok {
				return "", errors.New(why)
			}
			return ask(fmt.Sprintf("OpenPGP Admin PIN of %s (%s), %d tries left", *label, *serial, info.AdminPINTries))
		}
		res, err := pgp.Copy(ctx, user, card, req, func() (string, error) {
			return ask("PGP passphrase for " + pgp.Short(*primary))
		}, askPIN, log)
		for _, w := range res.Written {
			fmt.Printf("%s written %s %s\n", pgpMark, w.Slot, w.Fingerprint)
		}
		for _, w := range res.Present {
			fmt.Printf("%s present %s %s\n", pgpMark, w.Slot, w.Fingerprint)
		}
		for _, s := range res.Touch {
			fmt.Printf("%s touch %s\n", pgpMark, s)
		}
		return err

	case "new":
		uid := fs.String("uid", "", "Name <email>")
		expire := fs.String("expire", "3y", "expiry")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		pass, err := ask("New PGP passphrase")
		if err != nil {
			return err
		}
		again, err := ask("Repeat PGP passphrase")
		if err != nil {
			return err
		}
		if pass != again {
			return errors.New("passphrases differ")
		}
		if len(pass) < 8 {
			return errors.New("passphrase shorter than 8 characters")
		}
		log("Generating " + *uid)
		fpr, err := user.Generate(ctx, pass, *uid, *expire)
		if fpr != "" {
			fmt.Printf("%s new %s\n", pgpMark, fpr)
		}
		return err

	case "add-sign":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		id, err := user.Find(ctx, *primary)
		if err != nil {
			return err
		}
		if id.Where != pgp.WhereDisk {
			return errors.New("the primary key is not on this computer")
		}
		expire := "never"
		if !id.Expires.IsZero() {
			expire = id.Expires.Format(time.DateOnly)
		}
		pass, err := ask("PGP passphrase for " + pgp.Short(*primary))
		if err != nil {
			return err
		}
		log("Adding a signing subkey")
		return user.AddSubkey(ctx, pass, *primary, "ed25519", "sign", expire)

	case "backup":
		out := fs.String("out", "", "file to write")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if len(subs) == 0 || *out == "" {
			return errors.New("need --sub and --out")
		}
		pass, err := ask("PGP passphrase for " + pgp.Short(*primary))
		if err != nil {
			return err
		}
		b, err := user.ExportSecretSubkeys(ctx, pass, subs)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(b); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("%s backup %s\n", pgpMark, *out)
		return nil

	case "card-only":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if len(subs) == 0 {
			return errors.New("need --sub")
		}
		user.Kill("scdaemon")
		st, err := user.CardStatus(ctx)
		if err != nil {
			return fmt.Errorf("card not readable by gpg, nothing removed: %w", err)
		}
		on := pgp.CardFingerprints(st)
		for _, s := range subs {
			if !on[s] {
				return fmt.Errorf("subkey %s is not on the plugged card; nothing removed", pgp.Short(s))
			}
		}
		log("Removing the subkeys from disk")
		if err := user.DeleteSecretSubkeys(ctx, subs); err != nil {
			return err
		}
		if _, err := user.CardStatus(ctx); err != nil { // stubs pointing at the card
			return err
		}
		return nil

	case "learn":
		user.Kill("scdaemon")
		_, err := user.CardStatus(ctx)
		return err
	}
	return fmt.Errorf("unknown pgp command %q", args[0])
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
