package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// Result lines on stdout, read by the TUI.
const pivMark = "YKING-PIV"

// cmdPIV: run by the TUI; prompts go to it over the askpass socket.
// yking piv defaults --serial S --label L
func cmdPIV(c *ykman.Client, args []string) error {
	if len(args) == 0 || args[0] != "defaults" {
		return errors.New("usage: yking piv defaults --serial S --label L")
	}
	sock := os.Getenv(askpass.EnvSock)
	if sock == "" {
		return errors.New("yking piv runs from the TUI (P)")
	}
	fs := flag.NewFlagSet("piv defaults", flag.ContinueOnError)
	serial := fs.String("serial", "", "YubiKey serial")
	label := fs.String("label", "", "YubiKey label")
	if err := fs.Parse(args[1:]); err != nil {
		return err
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
	ctx := context.Background()
	return pivDefaults(ctx, c, *serial, *label, ask, func(s string) { fmt.Fprintln(os.Stderr, s) })
}

// pivDefaults asks for everything first, then replaces each factory
// credential still in place: PIN, PUK, management key (random, stored on
// the key behind the PIN).
func pivDefaults(ctx context.Context, c *ykman.Client, serial, label string, ask func(string) (string, error), log func(string)) error {
	serials, err := c.ListSerials(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(serials, serial) {
		return fmt.Errorf("YubiKey %s is not plugged in", serial)
	}
	info, err := c.PIVInfo(ctx, serial)
	if err != nil {
		return err
	}
	if !info.AnyDefault() {
		return errors.New("no factory default left")
	}
	if info.PINTries == 0 {
		return errors.New("PIV PIN is blocked")
	}

	newSecret := func(what, def string, other string) (string, error) {
		v, err := ask(fmt.Sprintf("New PIV %s for %s (6–8 characters)", what, label))
		if err != nil {
			return "", err
		}
		if err := ykman.ValidPIVSecret(v); err != nil {
			return "", fmt.Errorf("%s %v", what, err)
		}
		if v == def {
			return "", fmt.Errorf("%s is the factory default", what)
		}
		if other != "" && v == other {
			return "", errors.New("PUK must differ from the PIN")
		}
		again, err := ask(fmt.Sprintf("Repeat new PIV %s", what))
		if err != nil {
			return "", err
		}
		if again != v {
			return "", fmt.Errorf("%ss differ", what)
		}
		return v, nil
	}

	pin, puk := "", ""
	if info.DefaultPIN {
		if pin, err = newSecret("PIN", ykman.DefaultPIVPIN, ""); err != nil {
			return err
		}
	} else if info.DefaultMgmt {
		if ok, why := info.PINPromptAllowed(); !ok {
			return errors.New(why)
		}
		if pin, err = ask(fmt.Sprintf("PIV PIN of %s (%s), %d tries left", label, serial, info.PINTries)); err != nil {
			return err
		}
	}
	if info.DefaultPUK && !info.PUKBlocked {
		if puk, err = newSecret("PUK", ykman.DefaultPIVPUK, pin); err != nil {
			return err
		}
	}

	if info.DefaultPIN {
		log("Setting the PIN")
		if err := c.ChangePIVPIN(ctx, serial, pin); err != nil {
			return err
		}
		fmt.Println(pivMark, "pin")
	}
	if puk != "" {
		log("Setting the PUK")
		if err := c.ChangePIVPUK(ctx, serial, puk); err != nil {
			return err
		}
		fmt.Println(pivMark, "puk")
	}
	if info.DefaultMgmt {
		log("Setting a random management key")
		if err := c.ProtectPIVManagementKey(ctx, serial, pin); err != nil {
			return err
		}
		fmt.Println(pivMark, "mgmt")
	}
	pin, puk = "", ""

	after, err := c.PIVInfo(ctx, serial)
	if err != nil {
		return err
	}
	if after.DefaultPIN || after.DefaultMgmt || (after.DefaultPUK && !after.PUKBlocked) {
		return errors.New("a factory default is still set")
	}
	return nil
}
