package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/licentiapoetica/yking/internal/elevate"
	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/luks"
	"github.com/licentiapoetica/yking/internal/targets"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// cmdLUKS: yking luks status|enroll
func cmdLUKS(c *ykman.Client, krPath string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: yking luks status | enroll [--device DEV] [--unlock pin+touch|touch] | migrate [--dry-run] | repair")
	}
	if !elevate.IsRoot() {
		return elevate.Reexec(append([]string{"--keyring", krPath, "luks"}, args...)...)
	}
	switch args[0] {
	case "status":
		return luksStatus(krPath)
	case "enroll":
		return luksEnroll(c, krPath, args[1:])
	case "repair":
		return luksRepair()
	case "migrate":
		return luksMigrate(len(args) > 1 && args[1] == "--dry-run")
	}
	return fmt.Errorf("unknown luks command %q", args[0])
}

func rootVolume(device string) (luks.Volume, error) {
	vols, err := luks.Volumes()
	if err != nil {
		return luks.Volume{}, err
	}
	for _, v := range vols {
		if (device == "" && v.Root) || v.Device == device {
			return v, nil
		}
	}
	if device == "" {
		return luks.Volume{}, errors.New("no LUKS volume holds the root filesystem; pass --device")
	}
	return luks.Volume{}, fmt.Errorf("%s is not a LUKS volume", device)
}

func luksStatus(krPath string) error {
	vols, err := luks.Volumes()
	if err != nil {
		return err
	}
	kr, _ := keyring.Load(krPath)
	owner := map[string]string{} // uuid/slot → label
	if kr != nil {
		for _, k := range kr.Keys {
			for _, s := range k.LUKS {
				owner[fmt.Sprintf("%s/%d", s.DeviceUUID, s.Keyslot)] = k.Label
			}
		}
	}
	for _, v := range vols {
		root := ""
		if v.Root {
			root = " (root)"
		}
		fmt.Printf("%s  LUKS%d  %s  %s%s\n", v.Device, v.Version, v.UUID, v.Mapper, root)
		if v.Version != 2 {
			fmt.Println("   LUKS1: FIDO2 unlocking needs LUKS2 (not handled yet)")
			continue
		}
		h, err := luks.ReadHeader(v.Device)
		if err != nil {
			fmt.Println("   ", err)
			continue
		}
		for _, s := range h.Slots {
			switch {
			case s.Token == nil:
				fmt.Printf("   slot %d: passphrase / key file\n", s.ID)
			case s.Token.Type == "systemd-fido2":
				who := owner[fmt.Sprintf("%s/%d", v.UUID, s.ID)]
				if who == "" {
					who = "unknown key"
				}
				fmt.Printf("   slot %d: FIDO2 (%s; PIN %v, touch %v)\n", s.ID, who, s.Token.PINRequired, s.Token.UPRequired)
			default:
				fmt.Printf("   slot %d: %s\n", s.ID, s.Token.Type)
			}
		}
	}
	if id := luks.Pending(); id != "" {
		fmt.Printf("\n!!! The boot change %s was interrupted before rebuild/verification finished.\n    Run `yking luks repair` BEFORE rebooting.\n", id)
	}
	b := luks.DiscoverBoot()
	fmt.Printf("\nboot: initramfs unlock hook %q, GRUB %v\n", b.Method, b.GRUB)
	for _, p := range b.Problems {
		fmt.Println("  !", p)
	}
	return nil
}

func readSecret(tty *os.File, prompt string) ([]byte, error) {
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return b, err
}

func luksEnroll(c *ykman.Client, krPath string, args []string) error {
	fs := flag.NewFlagSet("luks enroll", flag.ExitOnError)
	device := fs.String("device", "", "LUKS device (default: the one holding /)")
	unlockS := fs.String("unlock", "pin+touch", "what unlocking needs: pin+touch or touch")
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
	if len(before.PasswordSlots()) == 0 {
		return errors.New("no passphrase slot on " + v.Device + "; yking only adds FIDO2 next to a passphrase")
	}

	devs, err := fido.Devices(fido.DefaultSysRoot)
	if err != nil {
		return err
	}
	serials, err := c.ListSerials(ctx)
	if err != nil {
		return err
	}
	if len(devs) != 1 || len(serials) != 1 {
		return fmt.Errorf("plug in exactly one key (now: %d FIDO device(s), serials %v)", len(devs), serials)
	}
	kr, err := keyring.Load(krPath)
	if err != nil {
		return err
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
	f, err := c.FIDOInfo(ctx, serials[0])
	if err != nil {
		return err
	}
	if unlock.PIN() {
		if ok, why := f.PINPromptAllowed(); !ok {
			return errors.New(why)
		}
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("needs a terminal for the passphrase and PIN prompts")
	}
	defer tty.Close()
	fmt.Fprintf(tty, "Enrolling key %q (%s) into %s (%s) — unlock: %s.\n", k.Label, k.Serial, v.Device, v.Mapper, unlock)
	fmt.Fprintf(tty, "The passphrase slot stays. Nothing is stored on the key (non-resident credential).\n\n")

	backup, err := luks.BackupHeader(v.Device, v.UUID, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(tty, "LUKS header backed up to %s\n\n", backup)

	pass, err := readSecret(tty, "Current LUKS passphrase of "+v.Device+": ")
	if err != nil || len(pass) == 0 {
		return errors.New("no passphrase entered")
	}
	defer luks.Wipe(pass)
	fmt.Fprintln(tty, "Checking the passphrase…")
	if err := luks.TestPassphrase(v.Device, pass); err != nil {
		return err // no PIN attempt used
	}

	var pin []byte
	if unlock.PIN() {
		fmt.Fprintf(tty, "FIDO2 PIN of %q — %d tries left. Asked ONCE; a wrong PIN stops here.\n", k.Label, f.PINRetries)
		pin, err = readSecret(tty, "PIN: ")
		if err != nil {
			return err
		}
		defer luks.Wipe(pin)
		if len([]rune(string(pin))) < max(f.MinPINLength, 4) {
			return errors.New("PIN too short; not sent (no attempt used)")
		}
	}

	eargs, err := luks.EnrollArgs(v.Device, devs[0], unlock)
	if err != nil {
		return err
	}
	fmt.Fprintln(tty, "\n>>> Touch the key when it blinks (creating the credential always needs one touch). <<<")
	if err := luks.RunEnroll(eargs, pass, pin, tty); err != nil {
		return fmt.Errorf("%w (if the PIN was wrong, one attempt was used; the LUKS header is unchanged or backed up at %s)", err, backup)
	}
	after, err := luks.ReadHeader(v.Device)
	if err != nil {
		return err
	}
	tok, err := luks.NewFIDO2Token(before, after)
	if err != nil {
		return err
	}
	fmt.Fprintf(tty, "\nEnrolled: keyslot %d (token %d). Passphrase slot(s) %v kept.\n", tok.Keyslots[0], tok.ID, after.PasswordSlots())

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
	fmt.Fprintf(tty, "Recorded in the keyring (%s).\n", m.ID)
	fmt.Fprint(tty, "\n"+bootInstructions)
	if b := luks.DiscoverBoot(); b.Method == "encrypt" {
		fmt.Fprintln(tty, "\nNote: boot still uses the old \"encrypt\" hook, which ignores FIDO2 — the passphrase keeps working as before.")
		fmt.Fprintln(tty, "To unlock with the key at boot, switch the initramfs next (yking luks migrate).")
	}
	return nil
}

// luksMigrate switches boot to the systemd initramfs so enrolled FIDO2 keys
// unlock the root volume. Shows the diff and asks before applying.
func luksMigrate(dryRun bool) error {
	v, err := rootVolume("")
	if err != nil {
		return err
	}
	h, err := luks.ReadHeader(v.Device)
	if err != nil {
		return err
	}
	if len(h.FIDO2()) == 0 && !dryRun {
		return errors.New("no FIDO2 key is enrolled on the root volume yet — run `yking luks enroll` first")
	}
	if len(h.PasswordSlots()) == 0 {
		return errors.New("no passphrase slot left; refusing")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return err
	}
	p, err := luks.MigratePlan(v, luks.DiscoverBoot(), string(cmdline), time.Now())
	if err != nil {
		return err
	}
	if dryRun {
		d, err := p.Diff()
		if err != nil {
			return err
		}
		fmt.Print(p.Summary(), "\n", d)
		if err := targets.Applier().Check(p); err != nil {
			return fmt.Errorf("elevated check would refuse: %w", err)
		}
		fmt.Println("\n(dry run: the elevated check accepts this plan; nothing was changed)")
		return nil
	}
	dir, err := os.MkdirTemp("", "yking-migrate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := dir + "/plan.json"
	if err := p.Save(path); err != nil {
		return err
	}
	fmt.Printf("%d FIDO2 key(s) enrolled on %s; passphrase slot(s) %v stay.\n", len(h.FIDO2()), v.Device, h.PasswordSlots())
	fmt.Println("After applying, yking rebuilds the initramfs images and the GRUB menu and checks them;")
	fmt.Println("if anything is wrong it restores the old files and rebuilds again.")
	fmt.Println()
	if err := applyAsRoot(path, false); err != nil {
		return err
	}
	fmt.Println()
	fmt.Print(bootInstructions)
	return nil
}

const bootInstructions = `At boot (after "yking luks migrate"):
  1. Enter the FIDO2 PIN when asked.
  2. The key then BLINKS — touch it within ~30 s. (With "quiet" on the kernel
     command line there is no message asking for the touch.)
  If unlocking with the key fails, systemd does NOT fall back to the passphrase
  while the key is plugged in. Then: unplug the key and reboot — after ~30 s the
  passphrase prompt appears — or pick "yking fallback" in the GRUB menu.
`

// luksRepair rebuilds every boot image and the GRUB menu from the files on
// disk and verifies them — after an interrupted boot change.
func luksRepair() error {
	signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Reset(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	fmt.Println("yking: rebuilding boot images and the GRUB menu from the current files (cannot be interrupted)…")
	if err := runReloads(luks.BootPaths); err != nil {
		return fmt.Errorf("rebuild failed: %w — do not reboot; the fallback entry or `yking rollback` may help", err)
	}
	syscall.Sync()
	if err := luks.VerifyBoot(luks.BootPaths); err != nil {
		return fmt.Errorf("verification failed: %w — do not reboot", err)
	}
	luks.ClearPending()
	syscall.Sync()
	fmt.Println("yking: boot images and GRUB menu rebuilt and verified.")
	return nil
}
