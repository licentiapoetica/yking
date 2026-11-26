// Command yking sets up YubiKeys on Linux: SSH, PAM, udev events, LUKS and
// remote unlock. It runs as the user; only an explicit apply step elevates.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"yking/internal/askpass"
	"yking/internal/detect"
	"yking/internal/keyring"
	"yking/internal/runner"
	"yking/internal/tui"
	"yking/internal/ykman"
)

var version = "0.1.0-dev"

const usage = `yking — YubiKey setup for Linux

Usage:
  yking [flags]               start the interactive TUI
  yking detect [--json]       read-only inventory of connected keys
  yking apply [--yes] PLAN    apply a reviewed plan (elevates via sudo/pkexec)
  yking rollback [ID]         undo an applied plan (default: the latest)
  yking history               list applied plans
  yking event add|remove      udev event handler (run by yking-event@.service)
  yking event status          show the plug/unplug configuration and state
  yking version

Flags:
`

func main() {
	// ssh-keygen runs yking as SSH_ASKPASS for the one-shot PIN guard.
	if os.Getenv(askpass.EnvState) != "" {
		os.Exit(askpass.Main(os.Args[1:]))
	}
	fs := flag.NewFlagSet("yking", flag.ExitOnError)
	keyringPath := fs.String("keyring", keyring.DefaultPath, "path to keyring.toml")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	client := ykman.New(runner.Exec{})
	args := fs.Args()
	cmd := ""
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	var err error
	switch cmd {
	case "":
		err = tui.Run(tui.Config{Client: client, KeyringPath: *keyringPath})
	case "detect":
		err = cmdDetect(os.Stdout, client, *keyringPath, args)
	case "apply":
		err = cmdApply(args)
	case "rollback":
		err = cmdRollback(args)
	case "history":
		err = cmdHistory()
	case "event":
		err = cmdEvent(client, *keyringPath, args)
	case "version":
		fmt.Println("yking", version)
	case "help", "-h", "--help":
		fs.Usage()
	default:
		fs.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yking:", err)
		os.Exit(1)
	}
}

func cmdDetect(w io.Writer, c *ykman.Client, krPath string, args []string) error {
	fs := flag.NewFlagSet("detect", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	fs.Parse(args)

	kr, err := keyring.Load(krPath)
	if err != nil {
		return err
	}
	rep, err := detect.Scan(context.Background(), c, kr)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	fmt.Fprintf(w, "ykman %s · keyring %s (%d registered)\n\n", rep.YkmanVersion, krPath, len(kr.Keys))
	if len(rep.Keys) == 0 {
		fmt.Fprintln(w, "No YubiKey with a readable serial connected.")
	}
	for _, k := range rep.Keys {
		name := "(not in keyring)"
		if k.Known != nil {
			name = fmt.Sprintf("%s [%s]", k.Known.Label, k.Known.Role)
		}
		fmt.Fprintf(w, "%s  %s  fw %s  %s\n", k.Serial, k.Info.DeviceType, k.Info.Firmware, name)
		if f := k.FIDO; f != nil {
			pin := "not set"
			switch {
			case f.PINBlocked:
				pin = "BLOCKED"
			case f.PINSet && f.PINRetries >= 0:
				pin = fmt.Sprintf("set, %d tries left", f.PINRetries)
			case f.PINSet:
				pin = "set"
			}
			fmt.Fprintf(w, "    FIDO2 PIN: %s", pin)
			if f.CredsRemaining >= 0 {
				fmt.Fprintf(w, " · resident slots free: %d", f.CredsRemaining)
			}
			fmt.Fprintln(w)
		}
		if o := k.OTP; o != nil {
			fmt.Fprintf(w, "    OTP: slot 1 %s · slot 2 %s\n", o.Slot1, o.Slot2)
		}
		for _, s := range k.Warnings() {
			fmt.Fprintf(w, "    ! %s\n", s)
		}
		for _, e := range k.Errors {
			fmt.Fprintf(w, "    ✗ %s\n", e)
		}
	}
	for _, k := range rep.Missing {
		fmt.Fprintf(w, "%s  %s [%s]  not connected\n", k.Serial, k.Label, k.Role)
	}
	if len(rep.Unidentified) > 0 {
		fmt.Fprintf(w, "\n%d key(s) without readable serial (cannot be tracked): %s\n",
			len(rep.Unidentified), strings.Join(rep.Unidentified, "; "))
	}
	return nil
}
