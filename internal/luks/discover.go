// Package luks handles FIDO2 unlocking of LUKS volumes and the switch of
// the initramfs to systemd (sd-encrypt), which FIDO2 unlocking needs.
//
// Safety rules:
//   - The passphrase keyslot is never removed; FIDO2 slots are added next to it.
//   - The LUKS header is backed up before any change.
//   - Nothing is ever written to the YubiKey's storage (systemd-cryptenroll
//     creates a non-resident hmac-secret credential).
//   - The boot migration keeps a fallback initramfs built with the OLD hooks
//     and a GRUB entry for it.
package luks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Volume is one LUKS block device.
type Volume struct {
	Device  string // /dev/vda2
	UUID    string
	Version int    // 1 or 2
	Mapper  string // open mapping name (e.g. cryptroot), "" if closed
	Root    bool   // the root filesystem lives inside it
	RootLV  bool   // … on an LVM logical volume (needs the root device timeout fix)
}

type lsblkDev struct {
	Name        string     `json:"name"`
	KName       string     `json:"kname"`
	Type        string     `json:"type"`
	FSType      string     `json:"fstype"`
	FSVer       string     `json:"fsver"`
	UUID        string     `json:"uuid"`
	Mountpoints []string   `json:"mountpoints"`
	Children    []lsblkDev `json:"children"`
}

// ParseLsblk extracts LUKS volumes from `lsblk -J -o NAME,KNAME,TYPE,FSTYPE,FSVER,UUID,MOUNTPOINTS`.
func ParseLsblk(b []byte) ([]Volume, error) {
	var doc struct {
		Devices []lsblkDev `json:"blockdevices"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []Volume
	var walk func(d lsblkDev)
	walk = func(d lsblkDev) {
		if d.FSType == "crypto_LUKS" {
			v := Volume{Device: "/dev/" + d.KName, UUID: d.UUID}
			fmt.Sscanf(d.FSVer, "%d", &v.Version)
			for _, c := range d.Children {
				if c.Type == "crypt" {
					v.Mapper = c.Name
					v.Root = hasRoot(c)
					for _, lv := range c.Children {
						if lv.Type == "lvm" && hasRoot(lv) {
							v.RootLV = true
						}
					}
				}
			}
			out = append(out, v)
		}
		for _, c := range d.Children {
			walk(c)
		}
	}
	for _, d := range doc.Devices {
		walk(d)
	}
	return out, nil
}

func hasRoot(d lsblkDev) bool {
	for _, m := range d.Mountpoints {
		if m == "/" {
			return true
		}
	}
	for _, c := range d.Children {
		if hasRoot(c) {
			return true
		}
	}
	return false
}

// Volumes lists LUKS volumes (no root needed).
func Volumes() ([]Volume, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "lsblk", "-J", "-o", "NAME,KNAME,TYPE,FSTYPE,FSVER,UUID,MOUNTPOINTS").Output()
	if err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	return ParseLsblk(out)
}

// Boot describes how the root volume is unlocked at boot today.
type Boot struct {
	Method     string // "encrypt" (busybox), "sd-encrypt", or "" unknown
	Hooks      []string
	Cmdline    string
	CryptParam string // the cryptdevice=… / rd.luks.… token(s) found
	GRUB       bool   // /etc/default/grub + grub-mkconfig present
	ESPUUID    string // filesystem UUID of the partition mounted at /boot
	Problems   []string
}

var hooksRe = regexp.MustCompile(`(?m)^HOOKS=\(([^)]*)\)`)

// ParseHooks returns the HOOKS array of a mkinitcpio.conf.
func ParseHooks(conf string) ([]string, error) {
	m := hooksRe.FindAllStringSubmatch(conf, -1)
	if len(m) != 1 {
		return nil, fmt.Errorf("expected exactly one HOOKS=(…) line, found %d", len(m))
	}
	return strings.Fields(m[0][1]), nil
}

// MethodOf tells which unlock hook a HOOKS array uses.
func MethodOf(hooks []string) string {
	has := func(h string) bool {
		for _, x := range hooks {
			if x == h {
				return true
			}
		}
		return false
	}
	switch {
	case has("sd-encrypt") && has("systemd"):
		return "sd-encrypt"
	case has("encrypt") && has("udev"):
		return "encrypt"
	}
	return ""
}

// DiscoverBoot reads mkinitcpio.conf, the kernel command line and GRUB.
func DiscoverBoot() Boot {
	var b Boot
	conf, err := os.ReadFile("/etc/mkinitcpio.conf")
	if err != nil {
		b.Problems = append(b.Problems, "no /etc/mkinitcpio.conf (only mkinitcpio is supported so far)")
	} else if b.Hooks, err = ParseHooks(string(conf)); err != nil {
		b.Problems = append(b.Problems, "mkinitcpio.conf: "+err.Error())
	}
	if ents, _ := os.ReadDir("/etc/mkinitcpio.conf.d"); len(ents) > 0 {
		for _, e := range ents {
			if "/etc/mkinitcpio.conf.d/"+e.Name() == MkinitcpioDropIn {
				continue
			}
			if c, err := os.ReadFile("/etc/mkinitcpio.conf.d/" + e.Name()); err == nil && hooksRe.Match(c) {
				b.Problems = append(b.Problems, "/etc/mkinitcpio.conf.d/"+e.Name()+" overrides HOOKS; yking does not handle that yet")
			}
		}
	}
	b.Method = MethodOf(b.Hooks)
	if c, err := os.ReadFile("/proc/cmdline"); err == nil {
		b.Cmdline = strings.TrimSpace(string(c))
		var params []string
		for _, f := range strings.Fields(b.Cmdline) {
			if strings.HasPrefix(f, "cryptdevice=") || strings.HasPrefix(f, "rd.luks.") {
				params = append(params, f)
			}
		}
		b.CryptParam = strings.Join(params, " ")
	}
	_, e1 := os.Stat("/etc/default/grub")
	_, e2 := exec.LookPath("grub-mkconfig")
	b.GRUB = e1 == nil && e2 == nil
	if !b.GRUB {
		b.Problems = append(b.Problems, "GRUB not found (only GRUB is supported so far)")
	}
	if out, err := exec.Command("findmnt", "-n", "-o", "UUID", "/boot").Output(); err == nil {
		b.ESPUUID = strings.TrimSpace(string(out))
	}
	return b
}
