package luks

import (
	"strings"
	"testing"
)

const brokenUKICfg = `### BEGIN /etc/grub.d/10_linux ###
menuentry 'Arch Linux' --class arch $menuentry_id_option 'gnulinux-simple-x' {
	search --no-floppy --fs-uuid --set=root ABCD-1234
	linux   /vmlinuz-linux root=/dev/mapper/vg0-root rw loglevel=3 quiet
	initrd  /intel-ucode.img
}
submenu 'Advanced options' {
	menuentry 'x' {
		linux /vmlinuz-linux
	}
}
`

const ukiEntry = `menuentry 'Arch Linux (UKI)' --class arch {
	search --no-floppy --fs-uuid --set=root ABCD-1234
	chainloader /EFI/Linux/arch-linux.efi
}
`

func TestDefaultBoots(t *testing.T) {
	// The laptop's panic: 10_linux first, microcode only.
	err := DefaultBoots(brokenUKICfg, "0", "/EFI/Linux/arch-linux.efi")
	if err == nil || !strings.Contains(err.Error(), "does not chainload") {
		t.Fatalf("broken default not caught: %v", err)
	}
	if err := DefaultBoots(brokenUKICfg, "0", ""); err == nil {
		t.Fatal("classic: entry without initramfs accepted")
	}
	fixed := "### BEGIN /etc/grub.d/09_uki_default ###\n" + ukiEntry + brokenUKICfg
	if err := DefaultBoots(fixed, "0", "/EFI/Linux/arch-linux.efi"); err != nil {
		t.Fatal(err)
	}
	if err := DefaultBoots(fixed, "0", "/EFI/Linux/other.efi"); err == nil {
		t.Fatal("wrong UKI accepted")
	}
	classic := strings.Replace(brokenUKICfg, "initrd  /intel-ucode.img", "initrd  /intel-ucode.img /initramfs-linux.img", 1)
	if err := DefaultBoots(classic, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := DefaultBoots(classic, "saved", ""); err == nil || !strings.Contains(err.Error(), "GRUB_DEFAULT") {
		t.Fatalf("GRUB_DEFAULT=saved: %v", err)
	}
	if _, err := FirstEntry("set timeout=5\n"); err == nil {
		t.Fatal("no entry accepted")
	}
}
