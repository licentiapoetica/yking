package luks

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/licentiapoetica/yking/internal/plan"
)

// MigratePlan builds the boot migration: systemd initramfs with
// crypttab.initramfs (fido2-device=auto), cryptdevice= removed from GRUB,
// plus a fallback initramfs with the OLD hooks and a GRUB entry for it.
// cmdline is the running kernel command line, used only for root= when
// /etc/default/grub does not set it.
func MigratePlan(v Volume, b Boot, cmdline string, now time.Time) (*plan.Plan, error) {
	switch {
	case !v.Root || v.Version != 2:
		return nil, errors.New("the root volume must be LUKS2")
	case b.Method != "encrypt":
		return nil, fmt.Errorf("initramfs unlock hook is %q, not the old \"encrypt\" — nothing to migrate", b.Method)
	case b.UKI != "":
		return nil, errors.New("boot uses a unified kernel image; use MigratePlanUKI")
	case !b.GRUB:
		return nil, errors.New("only GRUB is supported")
	case len(b.Problems) > 0:
		return nil, errors.New(strings.Join(b.Problems, "; "))
	case b.ESPUUID == "":
		return nil, errors.New("cannot tell the UUID of the /boot partition")
	}
	if _, err := os.Stat(KernelImage); err != nil {
		return nil, fmt.Errorf("%s not found (only the \"linux\" kernel package is supported so far)", KernelImage)
	}
	conf, err := os.ReadFile(MkinitcpioConf)
	if err != nil {
		return nil, err
	}
	newHooks, err := ConvertHooks(b.Hooks)
	if err != nil {
		return nil, err
	}
	newConf, err := ReplaceHooks(string(conf), b.Hooks, newHooks)
	if err != nil {
		return nil, err
	}
	grub, err := os.ReadFile(GrubDefault)
	if err != nil {
		return nil, err
	}
	// What GRUB boots NEXT time (not /proc/cmdline, which may be stale after
	// a rollback without reboot) decides the fallback entry and the check.
	grubLine := GrubCmdline(string(grub))
	cd, err := FindCryptdevice(grubLine, v)
	if err != nil {
		return nil, err
	}
	ctOpts, err := cd.CrypttabOptions() // e.g. allow-discards → discard: TRIM keeps working
	if err != nil {
		return nil, err
	}
	newGrub, _, err := RemoveCryptdevice(string(grub))
	if err != nil {
		return nil, err
	}
	if v.RootLV {
		if newGrub, err = AddRootflagsTimeout(newGrub); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(CrypttabInitramfs); err == nil {
		return nil, fmt.Errorf("%s exists (deprecated); merge it into %s first", CrypttabInitramfs, Crypttab)
	}
	ct, _ := os.ReadFile(Crypttab)
	newCT := RenderCrypttab(string(ct), v.Mapper, v.UUID, ctOpts...)

	old := strings.Fields(grubLine)
	if !strings.Contains(" "+grubLine, " root=") {
		// GRUB adds root= itself; take it from the running system.
		for _, f := range strings.Fields(cmdline) {
			if strings.HasPrefix(f, "root=") {
				old = append([]string{f}, old...)
				break
			}
		}
	}
	script, err := FallbackScript(b.ESPUUID, strings.Join(dedupe(old), " "))
	if err != nil {
		return nil, err
	}

	p := plan.New("LUKS: switch boot to the systemd initramfs (FIDO2 unlock), keep a fallback entry", now)
	for _, w := range []struct {
		path    string
		content string
		mode    os.FileMode
	}{
		{FallbackConf, string(conf), 0o644}, // the OLD config, for the fallback image
		{MkinitcpioConf, newConf, 0o644},
		{Crypttab, newCT, modeOf(Crypttab, 0o600)}, // keep e.g. 0600: crypttab may name key files
		{GrubDefault, newGrub, 0o644},
		{GrubFallback, script, 0o755},
		{ConsoleDropIn, ConsoleDropInContent, 0o644},
		{MkinitcpioDropIn, MkinitcpioDropInContent, 0o644},
	} {
		if err := p.WriteFile(w.path, []byte(w.content), w.mode); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// modeOf returns path's permission bits, or def if it does not exist.
func modeOf(path string, def os.FileMode) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return def
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Rebuilds returns the FIXED commands to run after boot files changed, in
// order: fallback image (old hooks), main images, GRUB menu.
func Rebuilds(changed []string) [][]string {
	has := func(p string) bool {
		for _, c := range changed {
			if c == p {
				return true
			}
		}
		return false
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	var out [][]string
	if has(FallbackConf) || has(FallbackCmdline) {
		switch {
		case exists(FallbackConf) && exists(FallbackCmdline): // UKI: a fallback UKI with the old line
			out = append(out, []string{"mkinitcpio", "-c", FallbackConf, "-k", KernelImage, "-U", FallbackUKI, "--cmdline", FallbackCmdline})
		case exists(FallbackConf):
			out = append(out, []string{"mkinitcpio", "-c", FallbackConf, "-k", KernelImage, "-g", FallbackImage})
		default:
			// rolled back: the fallback image is no longer referenced
			out = append(out, []string{"rm", "-f", FallbackImage, FallbackUKI})
		}
	}
	if has(ConsoleDropIn) {
		out = append(out, []string{"systemctl", "daemon-reload"})
	}
	if has(MkinitcpioConf) || has(CrypttabInitramfs) || has(Crypttab) || has(ConsoleDropIn) || has(MkinitcpioDropIn) || has(KernelCmdline) {
		out = append(out, []string{"mkinitcpio", "-P"})
	}
	if has(GrubDefault) || has(GrubFallback) {
		out = append(out, []string{"grub-mkconfig", "-o", GrubCfg})
	}
	return out
}

func initramfsHas(image string, want ...string) error {
	out, err := exec.Command("lsinitcpio", image).Output()
	if err != nil {
		return fmt.Errorf("lsinitcpio %s: %w", image, err)
	}
	list := "\n" + string(out)
	for _, w := range want {
		if !strings.Contains(list, w) {
			return fmt.Errorf("%s lacks %s", image, strings.TrimSpace(w))
		}
	}
	return nil
}

// VerifyBoot checks the rebuilt images and GRUB menu match the config on
// disk. A failure makes the apply roll back.
func VerifyBoot(changed []string) error {
	touched := false
	for _, c := range changed {
		switch c {
		case MkinitcpioConf, CrypttabInitramfs, Crypttab, GrubDefault, GrubFallback, FallbackConf, ConsoleDropIn, MkinitcpioDropIn,
			KernelCmdline, FallbackCmdline:
			touched = true
		}
	}
	if !touched {
		return nil
	}
	conf, err := os.ReadFile(MkinitcpioConf)
	if err != nil {
		return err
	}
	hooks, err := ParseHooks(string(conf))
	if err != nil {
		return err
	}
	if DetectUKI("/etc/mkinitcpio.d", KernelCmdline, "/boot/initramfs-linux.img") != "" {
		return verifyUKI(MethodOf(hooks))
	}
	switch MethodOf(hooks) {
	case "sd-encrypt":
		want := []string{"\netc/crypttab", "libfido2.so", "systemd-cryptsetup"}
		if _, err := os.Stat(ConsoleDropIn); err == nil {
			want = append(want, "\n"+strings.TrimPrefix(ConsoleDropIn, "/"))
		}
		if err := initramfsHas("/boot/initramfs-linux.img", want...); err != nil {
			return err
		}
	case "encrypt":
		if err := initramfsHas("/boot/initramfs-linux.img", "\nhooks/encrypt"); err != nil {
			return err
		}
	}
	cfg, err := os.ReadFile(GrubCfg)
	if err != nil {
		return err
	}
	if _, err := os.Stat(GrubFallback); err == nil {
		if err := initramfsHas(FallbackImage, "\nhooks/encrypt"); err != nil {
			return err
		}
		if !strings.Contains(string(cfg), "yking fallback: old initramfs") {
			return errors.New("grub.cfg lacks the yking fallback entry")
		}
	}
	return nil
}

// PendingMarker exists while a boot change is applied but not yet rebuilt
// and verified. If it survives (power loss, killed process), the boot files
// and images may not match: run `yking luks repair` before rebooting.
const PendingMarker = "/var/lib/yking/boot-pending"

// BootPaths are all files whose change requires a rebuild.
var BootPaths = []string{FallbackConf, FallbackCmdline, MkinitcpioConf, Crypttab, CrypttabInitramfs, ConsoleDropIn, MkinitcpioDropIn, KernelCmdline, GrubDefault, GrubFallback}

// SetPending writes the marker with the plan id.
func SetPending(id string) error {
	if err := os.MkdirAll("/var/lib/yking", 0o755); err != nil {
		return err
	}
	return os.WriteFile(PendingMarker, []byte(id+"\n"), 0o644)
}

// ClearPending removes the marker (after everything is on disk).
func ClearPending() {
	syscall.Sync()
	os.Remove(PendingMarker)
	syscall.Sync()
}

// Pending returns the plan id of an unfinished boot change, or "".
func Pending() string {
	b, err := os.ReadFile(PendingMarker)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
