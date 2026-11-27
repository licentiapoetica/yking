package luks

import (
	"errors"
	"fmt"
	"regexp"
	"path/filepath"
	"strings"
)

// Files the boot migration writes.
const (
	MkinitcpioConf    = "/etc/mkinitcpio.conf"
	CrypttabInitramfs = "/etc/crypttab.initramfs" // deprecated by mkinitcpio 42; only read/rolled back
	Crypttab          = "/etc/crypttab"
	GrubDefault       = "/etc/default/grub"
	GrubFallback      = "/etc/grub.d/41_yking_fallback"
	FallbackConf      = "/etc/yking/mkinitcpio-fallback.conf"
	FallbackImage     = "/boot/initramfs-linux-yking-fallback.img"
	KernelImage       = "/boot/vmlinuz-linux"
	GrubCfg           = "/boot/grub/grub.cfg"
	ConsoleDropIn     = "/etc/systemd/system/systemd-cryptsetup@.service.d/yking-console.conf"
	MkinitcpioDropIn  = "/etc/mkinitcpio.conf.d/yking.conf"
)

// ConsoleDropInContent makes systemd-cryptsetup print its messages
// ("Please confirm presence on security token to unlock.") on the console
// at boot, even with "quiet". SYSTEMD_LOG_TARGET=console is needed because
// systemd tools otherwise log straight into the journal, bypassing stderr.
const ConsoleDropInContent = `# Managed by yking: show the unlock messages ("Please confirm presence on
# security token to unlock.") on the console at boot, even with "quiet".
[Service]
Environment=SYSTEMD_LOG_TARGET=console
StandardOutput=journal+console
StandardError=journal+console
`

// MkinitcpioDropInContent puts the console drop-in into the initramfs.
const MkinitcpioDropInContent = `# Managed by yking: include the unlock-message drop-in in the initramfs.
FILES+=(` + ConsoleDropIn + `)
`

// ValidateConsoleDropIn accepts only yking's drop-in, byte for byte.
func ValidateConsoleDropIn(path string, content []byte) error {
	if path != ConsoleDropIn || string(content) != ConsoleDropInContent {
		return errors.New("yking only writes its own systemd-cryptsetup drop-in, unchanged")
	}
	return nil
}

// ValidateMkinitcpioDropIn accepts only yking's mkinitcpio drop-in.
func ValidateMkinitcpioDropIn(path string, content []byte) error {
	if path != MkinitcpioDropIn || string(content) != MkinitcpioDropInContent {
		return errors.New("yking only writes its own mkinitcpio drop-in, unchanged")
	}
	return nil
}

// passthrough hooks work unchanged in a systemd initramfs.
var passthrough = map[string]bool{
	"base": true, "autodetect": true, "microcode": true, "modconf": true, "kms": true,
	"keyboard": true, "block": true, "lvm2": true, "mdadm_udev": true, "filesystems": true,
	"fsck": true, "plymouth": true,
}

// ConvertHooks turns a busybox HOOKS array into the systemd equivalent:
// udev→systemd, encrypt→sd-encrypt, keymap+consolefont→sd-vconsole.
// Hooks with no known systemd equivalent are refused.
func ConvertHooks(old []string) ([]string, error) {
	if MethodOf(old) != "encrypt" {
		return nil, errors.New("HOOKS do not use udev + encrypt; nothing to convert")
	}
	var out []string
	vconsole := false
	for _, h := range old {
		switch {
		case h == "udev":
			out = append(out, "systemd")
		case h == "encrypt":
			out = append(out, "sd-encrypt")
		case h == "keymap" || h == "consolefont":
			if !vconsole {
				out = append(out, "sd-vconsole")
				vconsole = true
			}
		case h == "usr" || h == "resume":
			// handled by systemd itself
		case passthrough[h]:
			out = append(out, h)
		default:
			return nil, fmt.Errorf("hook %q has no known systemd equivalent; yking will not convert", h)
		}
	}
	return out, nil
}

// ReplaceHooks returns conf with its HOOKS line set to hooks; a comment
// with the previous line is kept above it.
func ReplaceHooks(conf string, old, hooks []string) (string, error) {
	if _, err := ParseHooks(conf); err != nil {
		return "", err
	}
	line := "HOOKS=(" + strings.Join(hooks, " ") + ")"
	note := "# yking: converted for FIDO2 unlocking; was: HOOKS=(" + strings.Join(old, " ") + ")"
	return hooksRe.ReplaceAllLiteralString(conf, note+"\n"+line), nil
}

// CrypttabLine is the /etc/crypttab entry for the root volume, unlocked in
// the initramfs (x-initrd.attach). Without the key present, systemd asks
// for the passphrase after token-timeout (30s). NOTE: with the key present
// but no touch / a wrong PIN, systemd 262 does NOT fall back to the
// passphrase — unplug the key and reboot, or use the fallback entry.
func CrypttabLine(name, uuid string, extra ...string) string {
	return fmt.Sprintf("%s UUID=%s none %s", name, uuid, strings.Join(append([]string{"fido2-device=auto", "x-initrd.attach"}, extra...), ","))
}

// RenderCrypttab writes/replaces the entry for name in an existing
// /etc/crypttab (possibly only comments), keeping every other line.
func RenderCrypttab(existing, name, uuid string, extra ...string) string {
	var lines []string
	replaced := false
	for _, l := range strings.Split(strings.TrimRight(existing, "\n"), "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && !strings.HasPrefix(f[0], "#") && f[0] == name {
			lines = append(lines, CrypttabLine(name, uuid, extra...))
			replaced = true
			continue
		}
		if l != "" || len(lines) > 0 {
			lines = append(lines, l)
		}
	}
	if !replaced {
		lines = append(lines, "# yking: root volume, unlocked in the initramfs (FIDO2 key or passphrase)")
		lines = append(lines, CrypttabLine(name, uuid, extra...))
	}
	return strings.Join(lines, "\n") + "\n"
}

var crypttabName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ValidateCrypttab checks /etc/crypttab: 2–4 plain fields per entry, no
// keyscript= (which runs a program), and at least one entry. Other lines
// the user wrote are kept as they are.
func ValidateCrypttab(path string, content []byte) error {
	n := 0
	for i, l := range strings.Split(string(content), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 || len(f) > 4 || !crypttabName.MatchString(f[0]) {
			return fmt.Errorf("line %d: not a crypttab entry", i+1)
		}
		if strings.ContainsAny(t, "`$;|&") || strings.Contains(t, "keyscript=") {
			return fmt.Errorf("line %d: unsafe content", i+1)
		}
		n++
	}
	if n == 0 {
		return errors.New("no entries")
	}
	return nil
}

// ValidateMkinitcpio checks a mkinitcpio.conf (main or fallback): one
// consistent HOOKS line with an unlock hook.
func ValidateMkinitcpio(path string, content []byte) error {
	hooks, err := ParseHooks(string(content))
	if err != nil {
		return err
	}
	m := MethodOf(hooks)
	if m == "" {
		return errors.New("HOOKS have neither udev+encrypt nor systemd+sd-encrypt")
	}
	for _, h := range hooks {
		if (m == "sd-encrypt" && (h == "udev" || h == "encrypt" || h == "keymap")) || (m == "encrypt" && (h == "systemd" || h == "sd-encrypt")) {
			return fmt.Errorf("HOOKS mix busybox and systemd hooks (%s)", h)
		}
	}
	if strings.HasSuffix(path, "mkinitcpio-fallback.conf") && m != "encrypt" {
		return errors.New("fallback config must keep the old encrypt hook")
	}
	return nil
}

var grubVarRe = regexp.MustCompile(`^([A-Z_][A-Z0-9_]*)=(.*)$`)

// RemoveCryptdevice drops cryptdevice=… from GRUB_CMDLINE_LINUX and
// GRUB_CMDLINE_LINUX_DEFAULT (the mapping moves to crypttab.initramfs).
// Returns the new file and the removed parameter(s).
func RemoveCryptdevice(grub string) (string, []string, error) {
	var removed []string
	lines := strings.Split(grub, "\n")
	for i, l := range lines {
		m := grubVarRe.FindStringSubmatch(l)
		if m == nil || (m[1] != "GRUB_CMDLINE_LINUX" && m[1] != "GRUB_CMDLINE_LINUX_DEFAULT") {
			continue
		}
		v := m[2]
		if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' || strings.ContainsAny(v[1:len(v)-1], "\"$`\\") {
			return "", nil, fmt.Errorf("%s is not a plain double-quoted value; edit it by hand", m[1])
		}
		var keep []string
		for _, f := range strings.Fields(v[1 : len(v)-1]) {
			if strings.HasPrefix(f, "cryptdevice=") || strings.HasPrefix(f, "cryptkey=") {
				removed = append(removed, f)
				continue
			}
			keep = append(keep, f)
		}
		lines[i] = m[1] + `="` + strings.Join(keep, " ") + `"`
	}
	if len(removed) == 0 {
		return "", nil, errors.New("no cryptdevice= in GRUB_CMDLINE_LINUX(_DEFAULT)")
	}
	return strings.Join(lines, "\n"), removed, nil
}

// RootDeviceTimeout is added for LVM on LUKS: systemd does not know the
// root LV appears only after unlocking, so its default 90s device timeout
// would end a slow unlock (PIN, touch, typing) in emergency mode.
const RootDeviceTimeout = "x-systemd.device-timeout=0"

// AddRootflagsTimeout adds RootDeviceTimeout to rootflags= in
// GRUB_CMDLINE_LINUX (creating rootflags= if needed).
func AddRootflagsTimeout(grub string) (string, error) {
	lines := strings.Split(grub, "\n")
	for i, l := range lines {
		m := grubVarRe.FindStringSubmatch(l)
		if m == nil || m[1] != "GRUB_CMDLINE_LINUX" {
			continue
		}
		v := m[2]
		if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' || strings.ContainsAny(v[1:len(v)-1], "\"$`\\") {
			return "", errors.New("GRUB_CMDLINE_LINUX is not a plain double-quoted value; edit it by hand")
		}
		f := strings.Fields(v[1 : len(v)-1])
		found := false
		for j, x := range f {
			if rest, ok := strings.CutPrefix(x, "rootflags="); ok {
				found = true
				if !strings.Contains(rest, "x-systemd.device-timeout") {
					f[j] = "rootflags=" + rest + "," + RootDeviceTimeout
				}
			}
		}
		if !found {
			f = append(f, "rootflags="+RootDeviceTimeout)
		}
		lines[i] = `GRUB_CMDLINE_LINUX="` + strings.Join(f, " ") + `"`
		return strings.Join(lines, "\n"), nil
	}
	return "", errors.New("no GRUB_CMDLINE_LINUX line")
}

// GrubCmdline returns the combined kernel parameters GRUB passes today
// (GRUB_CMDLINE_LINUX + GRUB_CMDLINE_LINUX_DEFAULT).
func GrubCmdline(grub string) string {
	var parts []string
	for _, name := range []string{"GRUB_CMDLINE_LINUX", "GRUB_CMDLINE_LINUX_DEFAULT"} {
		for _, l := range strings.Split(grub, "\n") {
			if m := grubVarRe.FindStringSubmatch(l); m != nil && m[1] == name {
				parts = append(parts, strings.Trim(m[2], `"`))
			}
		}
	}
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}

// ValidateGrubDefault checks /etc/default/grub stays a plain variable file
// with a root= on the kernel command line.
func ValidateGrubDefault(path string, content []byte) error {
	if !strings.HasSuffix(path, "/default/grub") {
		return fmt.Errorf("unexpected file %s", path)
	}
	for i, l := range strings.Split(string(content), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || grubVarRe.MatchString(t) {
			continue
		}
		return fmt.Errorf("line %d is not a variable assignment", i+1)
	}
	if !strings.Contains(GrubCmdline(string(content)), "root=") {
		return errors.New("no root= on the kernel command line")
	}
	return nil
}

var safeArgRe = regexp.MustCompile(`^[A-Za-z0-9_.,:=/@+-]+$`)

// FallbackScript is /etc/grub.d/41_yking_fallback: a fixed menu entry that
// boots the kernel with the OLD command line and the fallback initramfs
// (busybox encrypt hook: the passphrase prompt exactly as before).
func FallbackScript(espUUID, oldCmdline string) (string, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(espUUID) {
		return "", fmt.Errorf("bad ESP UUID %q", espUUID)
	}
	for _, a := range strings.Fields(oldCmdline) {
		if !safeArgRe.MatchString(a) {
			return "", fmt.Errorf("kernel parameter %q has unexpected characters", a)
		}
	}
	return `#!/bin/sh
exec tail -n +3 $0
# Managed by yking: boots the pre-migration initramfs (old "encrypt" hook,
# passphrase prompt as before). Remove it with yking once FIDO2 boot works.
menuentry 'yking fallback: old initramfs (passphrase)' {
	search --no-floppy --fs-uuid --set=root ` + espUUID + `
	linux /vmlinuz-linux ` + strings.Join(strings.Fields(oldCmdline), " ") + `
	initrd /initramfs-linux-yking-fallback.img
}
`, nil
}

var fallbackRe = regexp.MustCompile(`^#!/bin/sh
exec tail -n \+3 \$0
# Managed by yking: boots the pre-migration initramfs \(old "encrypt" hook,
# passphrase prompt as before\)\. Remove it with yking once FIDO2 boot works\.
menuentry 'yking fallback: old initramfs \(passphrase\)' \{
	search --no-floppy --fs-uuid --set=root [A-Za-z0-9-]+
	linux /vmlinuz-linux [A-Za-z0-9_.,:=/@+ -]+
	initrd /initramfs-linux-yking-fallback\.img
\}
$`)

// ValidateFallbackScript accepts only the script FallbackScript generates.
func ValidateFallbackScript(path string, content []byte) error {
	if !strings.HasSuffix(path, "/41_yking_fallback") {
		return fmt.Errorf("yking only writes its own GRUB script, not %s", path)
	}
	if !fallbackRe.Match(content) {
		return errors.New("GRUB script differs from what yking generates")
	}
	return nil
}

// CryptDevice is a parsed cryptdevice=<device>:<name>[:<options>] (the
// busybox "encrypt" hook's parameter).
type CryptDevice struct {
	Device  string // UUID=…, PARTUUID=…, LABEL=…, PARTLABEL=… or a /dev path
	Name    string
	Options []string
}

// ParseCryptdevice reads one cryptdevice= parameter. The device may itself
// contain ':' (/dev/disk/by-path/pci-0000:00:1f.2-…), so the last field is
// options only when it consists of options yking knows.
func ParseCryptdevice(param string) (CryptDevice, bool) {
	v, ok := strings.CutPrefix(param, "cryptdevice=")
	if !ok {
		return CryptDevice{}, false
	}
	parts := strings.Split(v, ":")
	n := len(parts)
	if n < 2 {
		return CryptDevice{}, false
	}
	c := CryptDevice{Device: strings.Join(parts[:n-1], ":"), Name: parts[n-1]}
	if opts := strings.Split(parts[n-1], ","); n >= 3 && knownOptions(opts) {
		c = CryptDevice{Device: strings.Join(parts[:n-2], ":"), Name: parts[n-2], Options: opts}
	}
	if c.Device == "" || c.Name == "" {
		return CryptDevice{}, false
	}
	return c, true
}

// encryptOptions maps the encrypt hook's options to crypttab options.
var encryptOptions = map[string]string{
	"allow-discards":     "discard",
	"no-read-workqueue":  "no-read-workqueue",
	"no-write-workqueue": "no-write-workqueue",
}

func knownOptions(opts []string) bool {
	for _, o := range opts {
		if _, ok := encryptOptions[o]; !ok {
			return false
		}
	}
	return true
}

// CrypttabOptions converts the options; an unknown one is an error (it is
// never dropped silently).
func (c CryptDevice) CrypttabOptions() ([]string, error) {
	var out []string
	for _, o := range c.Options {
		t, ok := encryptOptions[o]
		if !ok {
			return nil, fmt.Errorf("cryptdevice option %q has no crypttab equivalent yking knows; edit by hand", o)
		}
		out = append(out, t)
	}
	return out, nil
}

// resolveDev follows /dev symlinks (tests replace it).
var resolveDev = filepath.EvalSymlinks

// Names reports whether the parameter's device is v and its name v's
// mapping.
func (c CryptDevice) Names(v Volume) bool {
	if c.Name != v.Mapper {
		return false
	}
	if u, ok := strings.CutPrefix(c.Device, "UUID="); ok && strings.EqualFold(u, v.UUID) {
		return true
	}
	path := c.Device
	for prefix, dir := range map[string]string{"UUID=": "by-uuid", "PARTUUID=": "by-partuuid", "LABEL=": "by-label", "PARTLABEL=": "by-partlabel"} {
		if rest, ok := strings.CutPrefix(c.Device, prefix); ok {
			path = "/dev/disk/" + dir + "/" + rest
		}
	}
	a, err1 := resolveDev(path)
	b, err2 := resolveDev(v.Device)
	return err1 == nil && err2 == nil && a == b
}

// FindCryptdevice returns the cryptdevice= of grubLine that opens v.
func FindCryptdevice(grubLine string, v Volume) (CryptDevice, error) {
	var seen []string
	for _, f := range strings.Fields(grubLine) {
		c, ok := ParseCryptdevice(f)
		if !ok {
			continue
		}
		if c.Names(v) {
			return c, nil
		}
		if p := strings.Split(f, ":"); len(p) >= 3 && p[len(p)-2] == v.Mapper {
			return CryptDevice{}, fmt.Errorf("%s: option(s) %q unknown to yking (known: allow-discards, no-read-workqueue, no-write-workqueue); edit by hand", f, p[len(p)-1])
		}
		seen = append(seen, f)
	}
	if len(seen) == 0 {
		return CryptDevice{}, errors.New("no cryptdevice= on the GRUB kernel command line (GRUB_CMDLINE_LINUX in /etc/default/grub)")
	}
	return CryptDevice{}, fmt.Errorf("%s does not open %s as %q", strings.Join(seen, " "), v.Device, v.Mapper)
}
