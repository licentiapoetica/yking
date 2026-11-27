package luks

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/plan"
)

// Unified kernel images (UKI): mkinitcpio builds kernel + initramfs + the
// kernel command line (/etc/kernel/cmdline) into one EFI binary that GRUB
// chainloads. The switch then edits /etc/kernel/cmdline instead of
// /etc/default/grub, and the fallback is a second UKI with the old hooks
// and the old command line.
const (
	KernelCmdline   = "/etc/kernel/cmdline"
	FallbackCmdline = "/etc/yking/kernel-cmdline-fallback"
	FallbackUKI     = "/boot/EFI/Linux/yking-fallback.efi"
	LinuxPreset     = "/etc/mkinitcpio.d/linux.preset"
)

var presetVarRe = regexp.MustCompile(`^\s*([A-Za-z_]+)=(.*)$`)

// Preset is what yking needs from linux.preset.
type Preset struct {
	Kernel string // ALL_kver
	UKI    string // default_uki
}

// ParsePreset reads a mkinitcpio preset. Options yking cannot account for
// (a different --cmdline) are refused.
func ParsePreset(b []byte) (Preset, error) {
	var p Preset
	for _, l := range strings.Split(string(b), "\n") {
		m := presetVarRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		v := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		switch m[1] {
		case "ALL_kver":
			p.Kernel = v
		case "default_uki":
			p.UKI = v
		case "default_options", "ALL_config":
			if strings.Contains(v, "--cmdline") {
				return p, fmt.Errorf("%s sets its own --cmdline; yking does not handle that", m[1])
			}
		}
	}
	if p.UKI == "" {
		return p, errors.New("the preset builds no default_uki")
	}
	return p, nil
}

// UKIRelPath is the image's path on the ESP mounted at /boot, as GRUB
// names it (/EFI/Linux/…).
func UKIRelPath(image string) (string, error) {
	rel, ok := strings.CutPrefix(image, "/boot/")
	if !ok || strings.Contains(rel, "..") {
		return "", fmt.Errorf("UKI %s is not on the ESP at /boot", image)
	}
	return "/" + rel, nil
}

// CmdlineWithout drops cryptdevice=/cryptkey= from a kernel command line
// and, for LVM on LUKS, adds the root device timeout to rootflags=.
func CmdlineWithout(cmdline string, rootLV bool) string {
	var keep []string
	found := false
	for _, f := range strings.Fields(cmdline) {
		if strings.HasPrefix(f, "cryptdevice=") || strings.HasPrefix(f, "cryptkey=") {
			continue
		}
		if rest, ok := strings.CutPrefix(f, "rootflags="); ok && rootLV {
			found = true
			if !strings.Contains(rest, "x-systemd.device-timeout") {
				f = "rootflags=" + rest + "," + RootDeviceTimeout
			}
		}
		keep = append(keep, f)
	}
	if rootLV && !found {
		keep = append(keep, "rootflags="+RootDeviceTimeout)
	}
	return strings.Join(keep, " ")
}

// FallbackScriptUKI is the GRUB entry chainloading the fallback UKI.
func FallbackScriptUKI(espUUID string) (string, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(espUUID) {
		return "", fmt.Errorf("bad ESP UUID %q", espUUID)
	}
	rel, _ := UKIRelPath(FallbackUKI)
	return `#!/bin/sh
exec tail -n +3 $0
# Managed by yking: boots the pre-migration UKI (old "encrypt" hook,
# passphrase prompt as before). Remove it with yking once FIDO2 boot works.
menuentry 'yking fallback: old UKI (passphrase)' {
	search --no-floppy --fs-uuid --set=root ` + espUUID + `
	chainloader ` + rel + `
}
`, nil
}

var fallbackUKIRe = regexp.MustCompile(`^#!/bin/sh
exec tail -n \+3 \$0
# Managed by yking: boots the pre-migration UKI \(old "encrypt" hook,
# passphrase prompt as before\)\. Remove it with yking once FIDO2 boot works\.
menuentry 'yking fallback: old UKI \(passphrase\)' \{
	search --no-floppy --fs-uuid --set=root [A-Za-z0-9-]+
	chainloader /EFI/Linux/yking-fallback\.efi
\}
$`)

// ValidateKernelCmdline accepts a one-line kernel command line with root=.
func ValidateKernelCmdline(path string, content []byte) error {
	if path != KernelCmdline && path != FallbackCmdline {
		return fmt.Errorf("unexpected file %s", path)
	}
	line := strings.TrimSpace(string(content))
	if strings.Contains(line, "\n") {
		return errors.New("kernel command line must be one line")
	}
	for _, a := range strings.Fields(line) {
		if !safeArgRe.MatchString(a) {
			return fmt.Errorf("kernel parameter %q has unexpected characters", a)
		}
	}
	if !strings.Contains(" "+line, " root=") {
		return errors.New("no root= on the kernel command line")
	}
	return nil
}

// MigratePlanUKI is MigratePlan for a UKI booted by GRUB.
func MigratePlanUKI(v Volume, b Boot, now time.Time) (*plan.Plan, error) {
	switch {
	case !v.Root || v.Version != 2:
		return nil, errors.New("the root volume must be LUKS2")
	case b.Method != "encrypt":
		return nil, fmt.Errorf("initramfs unlock hook is %q, not the old \"encrypt\" — nothing to migrate", b.Method)
	case !b.GRUB:
		return nil, errors.New("UKIs are handled only when GRUB boots them")
	case len(b.Problems) > 0:
		return nil, errors.New(strings.Join(b.Problems, "; "))
	case b.ESPUUID == "":
		return nil, errors.New("cannot tell the UUID of the /boot partition")
	}
	pb, err := os.ReadFile(LinuxPreset)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (only the \"linux\" kernel package is supported so far)", LinuxPreset, err)
	}
	preset, err := ParsePreset(pb)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", LinuxPreset, err)
	}
	if preset.Kernel != KernelImage {
		return nil, fmt.Errorf("%s builds from %q, not %s", LinuxPreset, preset.Kernel, KernelImage)
	}
	if _, err := UKIRelPath(preset.UKI); err != nil {
		return nil, err
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
	cb, err := os.ReadFile(KernelCmdline)
	if err != nil {
		return nil, err
	}
	oldCmd := strings.TrimSpace(string(cb))
	cd, err := FindCryptdevice(oldCmd, v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", KernelCmdline, err)
	}
	ctOpts, err := cd.CrypttabOptions()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(CrypttabInitramfs); err == nil {
		return nil, fmt.Errorf("%s exists (deprecated); merge it into %s first", CrypttabInitramfs, Crypttab)
	}
	ct, _ := os.ReadFile(Crypttab)
	newCT := RenderCrypttab(string(ct), v.Mapper, v.UUID, ctOpts...)
	script, err := FallbackScriptUKI(b.ESPUUID)
	if err != nil {
		return nil, err
	}

	p := plan.New("LUKS: switch the UKI to the systemd initramfs (FIDO2 unlock), keep a fallback UKI", now)
	for _, w := range []struct {
		path    string
		content string
		mode    os.FileMode
	}{
		{FallbackConf, string(conf), 0o644}, // the OLD config and command line, for the fallback UKI
		{FallbackCmdline, oldCmd + "\n", 0o644},
		{MkinitcpioConf, newConf, 0o644},
		{Crypttab, newCT, modeOf(Crypttab, 0o600)},
		{KernelCmdline, CmdlineWithout(oldCmd, v.RootLV) + "\n", modeOf(KernelCmdline, 0o644)},
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

// UKISections returns the embedded kernel command line and initramfs.
func UKISections(path string) (string, []byte, error) {
	f, err := pe.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	defer f.Close()
	read := func(name string) ([]byte, error) {
		s := f.Section(name)
		if s == nil {
			return nil, fmt.Errorf("%s has no %s section", path, name)
		}
		b, err := s.Data()
		if err != nil {
			return nil, err
		}
		if s.VirtualSize > 0 && int(s.VirtualSize) < len(b) {
			b = b[:s.VirtualSize] // Data() is padded to the file alignment
		}
		return b, nil
	}
	cmd, err := read(".cmdline")
	if err != nil {
		return "", nil, err
	}
	initrd, err := read(".initrd")
	if err != nil {
		return "", nil, err
	}
	return strings.TrimSpace(string(bytes.TrimRight(cmd, "\x00"))), initrd, nil
}

// SkipEarlyCPIO returns the initramfs after the uncompressed early cpio
// archives (microcode) that precede it.
func SkipEarlyCPIO(b []byte) ([]byte, error) {
	align := func(n int) int { return (n + 3) &^ 3 }
	for bytes.HasPrefix(b, []byte("070701")) {
		off := 0
		for {
			if off+110 > len(b) {
				return nil, errors.New("truncated cpio header")
			}
			h := b[off : off+110]
			field := func(i int) (int, error) {
				n, err := strconv.ParseUint(string(h[6+8*i:14+8*i]), 16, 32)
				return int(n), err
			}
			size, err1 := field(6)
			nameSize, err2 := field(11)
			if err := errors.Join(err1, err2); err != nil || string(h[:6]) != "070701" {
				return nil, errors.New("bad cpio header")
			}
			nameEnd := off + 110 + nameSize
			if nameEnd > len(b) {
				return nil, errors.New("truncated cpio name")
			}
			name := string(bytes.TrimRight(b[off+110:nameEnd], "\x00"))
			off = align(align(nameEnd) + size)
			if off > len(b) {
				return nil, errors.New("truncated cpio data")
			}
			if name == "TRAILER!!!" {
				break
			}
		}
		b = b[off:]
		for len(b) > 0 && b[0] == 0 { // padding between archives
			b = b[1:]
		}
	}
	return b, nil
}

// ukiHas checks a UKI's command line and initramfs contents.
func ukiHas(path string, cmdHas, cmdLacks string, want ...string) error {
	cmd, initrd, err := UKISections(path)
	if err != nil {
		return err
	}
	if cmdHas != "" && !strings.Contains(" "+cmd, " "+cmdHas) {
		return fmt.Errorf("%s: command line lacks %s", path, cmdHas)
	}
	if cmdLacks != "" && strings.Contains(" "+cmd, " "+cmdLacks) {
		return fmt.Errorf("%s: command line still has %s", path, cmdLacks)
	}
	main, err := SkipEarlyCPIO(initrd)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	tmp, err := os.CreateTemp("", "yking-initrd-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	tmp.Write(main)
	tmp.Close()
	if err := initramfsHas(tmp.Name(), want...); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// verifyUKI checks the images after a UKI change: the main UKI matches the
// HOOKS on disk, the fallback UKI keeps the old unlock and GRUB lists it.
func verifyUKI(method string) error {
	pb, err := os.ReadFile(LinuxPreset)
	if err != nil {
		return err
	}
	preset, err := ParsePreset(pb)
	if err != nil {
		return err
	}
	switch method {
	case "sd-encrypt":
		want := []string{"\netc/crypttab", "libfido2.so", "systemd-cryptsetup"}
		if _, err := os.Stat(ConsoleDropIn); err == nil {
			want = append(want, "\n"+strings.TrimPrefix(ConsoleDropIn, "/"))
		}
		if err := ukiHas(preset.UKI, "root=", "cryptdevice=", want...); err != nil {
			return err
		}
	case "encrypt":
		if err := ukiHas(preset.UKI, "cryptdevice=", "", "\nhooks/encrypt"); err != nil {
			return err
		}
	}
	if _, err := os.Stat(FallbackCmdline); err == nil {
		if err := ukiHas(FallbackUKI, "cryptdevice=", "", "\nhooks/encrypt"); err != nil {
			return err
		}
		cfg, err := os.ReadFile(GrubCfg)
		if err != nil {
			return err
		}
		if !strings.Contains(string(cfg), "yking fallback: old UKI") {
			return errors.New("grub.cfg lacks the yking fallback entry")
		}
	}
	return nil
}
