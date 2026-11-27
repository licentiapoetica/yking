package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/licentiapoetica/yking/internal/askpass"
	"github.com/licentiapoetica/yking/internal/elevate"
	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/luks"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/targets"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// cmdLUKS: yking luks status|enroll
func cmdLUKS(c *ykman.Client, krPath string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: yking luks status | enroll [--device DEV] [--unlock pin+touch|touch] | migrate [--dry-run] | repair | identify [--record] | wipe --slot N[,M…] [--device DEV] | passphrase remove | backup [--device DEV] [--out DIR]")
	}
	if !elevate.IsRoot() {
		return elevate.Reexec(append([]string{"--keyring", krPath, "luks"}, args...)...)
	}
	// Whatever happened, leave the current slot lists for the TUI.
	defer func() {
		if vols, err := luks.Volumes(); err == nil {
			luks.TakeSnapshot(vols, time.Now())
		}
	}()
	switch args[0] {
	case "status":
		return luksStatus(krPath)
	case "enroll":
		return luksEnroll(c, krPath, args[1:])
	case "repair":
		return luksRepair()
	case "wipe":
		return luksWipe(c, krPath, args[1:])
	case "identify":
		return luksIdentify(c, krPath, len(args) > 1 && args[1] == "--record")
	case "migrate":
		switch {
		case len(args) == 3 && args[1] == "--tui":
			return luksMigrate(false, args[2])
		case len(args) == 1 || (len(args) == 2 && args[1] == "--dry-run"):
			return luksMigrate(len(args) == 2, "")
		}
		return errors.New("usage: yking luks migrate [--dry-run]")
	case "backup":
		return luksBackup(args[1:])
	case "passphrase":
		switch {
		case len(args) == 2 && args[1] == "remove":
			return luksPassphraseRemove(c, krPath, "")
		case len(args) == 4 && args[1] == "remove" && args[2] == "--tui":
			return luksPassphraseRemove(c, krPath, args[3])
		}
		return errors.New("usage: yking luks passphrase remove")
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
			case s.Token.Type == "systemd-recovery":
				fmt.Printf("   slot %d: recovery key\n", s.ID)
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

// luksMigrate switches boot to the systemd initramfs so enrolled FIDO2 keys
// unlock the root volume. Shows the diff and asks before applying (in the
// TUI when sock is set).
func luksMigrate(dryRun bool, sock string) error {
	if sock != "" {
		// The TUI shows stderr lines live; a closed TUI must not kill a
		// half-done apply (SIGPIPE).
		os.Stdout = os.Stderr
		signal.Ignore(syscall.SIGPIPE)
	}
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
	b := luks.DiscoverBoot()
	var p *plan.Plan
	if b.UKI != "" {
		p, err = luks.MigratePlanUKI(v, b, time.Now())
	} else {
		p, err = luks.MigratePlan(v, b, string(cmdline), time.Now())
	}
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
	if sock != "" {
		d, err := p.Diff()
		if err != nil {
			return err
		}
		if k, err := askpass.Choose(sock, p.Summary()+"\n"+d, []askpass.Option{{Key: "a", Label: "apply"}, {Key: "n", Label: "cancel"}}, time.Time{}); err != nil || k != "a" {
			return errors.New("cancelled; nothing changed")
		}
		if err := applyAsRoot(path, true, sock); err != nil {
			return err
		}
	} else if err := applyAsRoot(path, false, ""); err != nil {
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

// luksIdentify asks the single plugged-in key, silently (no PIN, no touch,
// no attempt used), which FIDO2 slots on the LUKS2 volumes are its own.
func luksIdentify(c *ykman.Client, krPath string, record bool) error {
	ctx := context.Background()
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
	name := serials[0]
	if k != nil {
		name = k.Label
	}
	vols, err := luks.Volumes()
	if err != nil {
		return err
	}
	var found []keyring.LUKSSlot
	probed, silentFail := 0, 0
	for _, v := range vols {
		if v.Version != 2 {
			continue
		}
		h, err := luks.ReadHeader(v.Device)
		if err != nil {
			fmt.Println(v.Device+":", err)
			continue
		}
		for _, t := range h.FIDO2() {
			if t.Credential == "" || t.RP == "" || len(t.Keyslots) != 1 {
				continue
			}
			probed++
			err := fido.Probe(ctx, devs[0], t.RP, t.Credential)
			switch {
			case err == nil:
				fmt.Printf("%s slot %d (token %d): belongs to %q\n", v.Device, t.Keyslots[0], t.ID, name)
				found = append(found, keyring.LUKSSlot{DeviceUUID: v.UUID, Mapper: v.Mapper, Keyslot: t.Keyslots[0], Token: t.ID,
					PINRequired: t.PINRequired, UPRequired: t.UPRequired, EnrolledAt: time.Now().UTC().Truncate(time.Second)})
			case errors.Is(err, fido.ErrNotThisKey):
				silentFail++
				fmt.Printf("%s slot %d (token %d): not this key\n", v.Device, t.Keyslots[0], t.ID)
			default:
				fmt.Printf("%s slot %d (token %d): check failed: %v\n", v.Device, t.Keyslots[0], t.ID, err)
			}
		}
	}
	if probed == 0 {
		fmt.Println("No FIDO2 slots found.")
		return nil
	}
	if len(found) == 0 {
		fmt.Printf("\nNo slot answered for %q. If you know this key IS enrolled, its credential is protected against silent\n"+
			"checks; then test a slot with: cryptsetup open --test-passphrase --token-only --token-id N DEVICE (PIN + touch).\n", name)
		return nil
	}
	if len(found) > 1 {
		fmt.Printf("\n%q owns %d slots on the same key — one is enough; the extra slot can be removed later.\n", name, len(found))
	}
	if !record {
		fmt.Println("\n(add --record to store this in yking's keyring)")
		return nil
	}
	if k == nil {
		return fmt.Errorf("key %s is not registered; register it first", serials[0])
	}
	for _, slot := range found {
		p, err := luks.RecordPlan(krPath, k.Serial, slot, time.Now())
		if err != nil {
			return err
		}
		if p.Empty() {
			continue
		}
		if _, err := targets.Applier().Apply(p); err != nil {
			return err
		}
	}
	fmt.Printf("Recorded %d slot(s) for %q in the keyring.\n", len(found), name)
	return nil
}

// luksWipe removes FIDO2 keyslots that are no longer needed. It never
// touches a passphrase slot, refuses slots recorded for a registered key
// (unless --recorded-too), and keeps at least one FIDO2 slot and one
// passphrase slot. The header is backed up first.
func luksWipe(c *ykman.Client, krPath string, args []string) error {
	fs := flag.NewFlagSet("luks wipe", flag.ExitOnError)
	device := fs.String("device", "", "LUKS device (default: the one holding /)")
	slotsS := fs.String("slot", "", "comma-separated keyslots to remove")
	recordedToo := fs.Bool("recorded-too", false, "also allow slots yking recorded for a registered key")
	fs.Parse(args)
	v, err := rootVolume(*device)
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
	owner := map[int]string{}
	for _, k := range kr.Keys {
		for _, s := range k.LUKS {
			if s.DeviceUUID == v.UUID {
				owner[s.Keyslot] = k.Label
			}
		}
	}
	if len(h.PasswordSlots()) == 0 && !h.HasRecovery() {
		return luksWipeWithKey(c, v, h, owner, *slotsS, *recordedToo)
	}
	wipe, err := luks.WipeSelection(h, *slotsS, owner, *recordedToo)
	if err != nil {
		return err
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("needs a terminal for the passphrase prompt")
	}
	defer tty.Close()
	fmt.Fprintf(tty, "Removing FIDO2 keyslot(s) %v from %s (%s). Passphrase slot(s) %v stay.\n", wipe, v.Device, v.Mapper, h.PasswordSlots())
	backup, err := luks.BackupHeader(v.Device, v.UUID, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(tty, "LUKS header backed up to %s\n", backup)
	pass, err := readSecret(tty, "Current LUKS passphrase or recovery key of "+v.Device+": ")
	if err != nil || len(pass) == 0 {
		return errors.New("no passphrase entered")
	}
	defer luks.Wipe(pass)
	if err := luks.TestPassphrase(v.Device, pass); err != nil {
		return err
	}
	if err := luks.RunWipe(v.Device, wipe, pass, tty); err != nil {
		return fmt.Errorf("%w (header backup: %s)", err, backup)
	}
	after, err := luks.ReadHeader(v.Device)
	if err != nil {
		return err
	}
	for _, sl := range after.Slots {
		for _, w := range wipe {
			if sl.ID == w {
				return fmt.Errorf("slot %d is still there; header backup: %s", w, backup)
			}
		}
	}
	fmt.Fprintf(tty, "Removed. Remaining: passphrase %v, FIDO2 slots %d.\n", after.PasswordSlots(), len(after.FIDO2()))
	return nil
}

// luksBackup saves the LUKS header (keyslots and metadata, no data) in
// yking's folder and, with --out, also in a folder off this disk: a damaged
// header can only be restored from a copy the locked disk does not hold.
func luksBackup(args []string) error {
	fs := flag.NewFlagSet("luks backup", flag.ExitOnError)
	device := fs.String("device", "", "LUKS device (default: the one holding /)")
	out := fs.String("out", "", "also copy it into this folder (e.g. on a USB stick)")
	fs.Parse(args)
	v, err := rootVolume(*device)
	if err != nil {
		return err
	}
	path, err := luks.BackupHeader(v.Device, v.UUID, time.Now())
	if err != nil {
		return err
	}
	if err := luks.VerifyHeaderBackup(path, v.UUID); err != nil {
		return err
	}
	fmt.Printf("Header of %s saved: %s\n", v.Device, path)
	if *out == "" {
		if luks.SameFilesystem(path, "/") && v.Root {
			fmt.Println("! This copy is on the encrypted disk itself; keep one elsewhere too (--out).")
		}
		return nil
	}
	uid, gid := -1, -1 // the copy belongs to the user who ran sudo
	if n, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil {
		uid = n
	}
	if n, err := strconv.Atoi(os.Getenv("SUDO_GID")); err == nil {
		gid = n
	}
	dst, err := luks.CopyHeaderBackup(path, *out, uid, gid)
	if err != nil {
		return err
	}
	if err := luks.VerifyHeaderBackup(dst, v.UUID); err != nil {
		return err
	}
	fmt.Printf("Copied and verified: %s\n", dst)
	if luks.SameFilesystem(dst, "/") && v.Root {
		fmt.Println("! That folder is on the encrypted disk itself; put a copy on another medium too.")
	}
	return nil
}

// luksWipeWithKey removes FIDO2 slots from a disk without passphrase: the
// one plugged-in enrolled key opens it (its PIN asked once).
func luksWipeWithKey(c *ykman.Client, v luks.Volume, h luks.Header, owner map[int]string, list string, recordedToo bool) error {
	ctx := context.Background()
	devs, err := fido.Devices(fido.DefaultSysRoot)
	if err != nil {
		return err
	}
	serials, err := c.ListSerials(ctx)
	if err != nil {
		return err
	}
	if len(devs) != 1 || len(serials) != 1 {
		return fmt.Errorf("no passphrase on %s: plug in exactly one enrolled key to open it (now: %d FIDO device(s))", v.Device, len(devs))
	}
	authDev, tok, err := enrolledDevice(ctx, devs, h)
	if err != nil {
		return err
	}
	wipe, err := luks.WipeSelectionWithKey(h, list, owner, recordedToo, tok.Keyslots[0])
	if err != nil {
		return err
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("needs a terminal for the PIN prompt")
	}
	defer tty.Close()
	name := owner[tok.Keyslots[0]]
	if name == "" {
		name = "the plugged-in key"
	}
	fmt.Fprintf(tty, "Removing FIDO2 keyslot(s) %v from %s (%s), opened by %s (slot %d).\n", wipe, v.Device, v.Mapper, name, tok.Keyslots[0])
	backup, err := luks.BackupHeader(v.Device, v.UUID, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(tty, "LUKS header backed up to %s\n", backup)
	var pin []byte
	if tok.PINRequired {
		f, err := c.FIDOInfo(ctx, serials[0])
		if err != nil {
			return err
		}
		if ok, why := f.PINPromptAllowed(); !ok {
			return errors.New(why)
		}
		if pin, err = readSecret(tty, fmt.Sprintf("FIDO2 PIN of %s (%d tries left, asked once): ", name, f.PINRetries)); err != nil {
			return err
		}
		defer luks.Wipe(pin)
	}
	fmt.Fprintln(tty, "Touch the key when it blinks.")
	if err := luks.RunWipeWithKey(v.Device, authDev, wipe, pin, tty); err != nil {
		return fmt.Errorf("%w (header backup: %s)", err, backup)
	}
	after, err := luks.ReadHeader(v.Device)
	if err != nil {
		return err
	}
	for _, sl := range after.Slots {
		if slices.Contains(wipe, sl.ID) {
			return fmt.Errorf("slot %d is still there; header backup: %s", sl.ID, backup)
		}
	}
	fmt.Fprintf(tty, "Removed. FIDO2 slots left: %d.\n", len(after.FIDO2()))
	return nil
}
