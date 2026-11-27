package luks

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePreset(t *testing.T) {
	p, err := ParsePreset([]byte("ALL_kver=\"/boot/vmlinuz-linux\"\nPRESETS=('default' 'fallback')\n#default_image=\"/boot/initramfs-linux.img\"\ndefault_uki=\"/boot/EFI/Linux/arch-linux.efi\"\nfallback_uki=\"/boot/EFI/Linux/arch-linux-fallback.efi\"\nfallback_options=\"-S autodetect\"\n"))
	if err != nil || p.Kernel != "/boot/vmlinuz-linux" || p.UKI != "/boot/EFI/Linux/arch-linux.efi" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ParsePreset([]byte("default_uki=\"/boot/x.efi\"\ndefault_options=\"--cmdline /etc/other\"\n")); err == nil {
		t.Fatal("own --cmdline accepted")
	}
	if _, err := ParsePreset([]byte("default_image=\"/boot/initramfs-linux.img\"\n")); err == nil {
		t.Fatal("no UKI accepted")
	}
	if rel, err := UKIRelPath("/boot/EFI/Linux/arch-linux.efi"); err != nil || rel != "/EFI/Linux/arch-linux.efi" {
		t.Fatal(rel, err)
	}
	if _, err := UKIRelPath("/efi/EFI/Linux/arch-linux.efi"); err == nil {
		t.Fatal("ESP outside /boot accepted")
	}
}

func TestCmdlineWithout(t *testing.T) {
	in := "cryptdevice=UUID=11111111-2222-3333-4444-555555555555:cryptlvm root=/dev/vg0/root zswap.enabled=0 rw rootfstype=ext4"
	got := CmdlineWithout(in, true)
	if got != "root=/dev/vg0/root zswap.enabled=0 rw rootfstype=ext4 rootflags=x-systemd.device-timeout=0" {
		t.Fatal(got)
	}
	if got := CmdlineWithout("cryptdevice=x:y root=/dev/sda2 rootflags=noatime cryptkey=rootfs:/k", true); got != "root=/dev/sda2 rootflags=noatime,x-systemd.device-timeout=0" {
		t.Fatal(got)
	}
	if got := CmdlineWithout("cryptdevice=x:y root=/dev/sda2", false); got != "root=/dev/sda2" {
		t.Fatal(got)
	}
	if ValidateKernelCmdline(KernelCmdline, []byte(got+"\n")) != nil {
		t.Fatal("valid line refused")
	}
	for _, bad := range []string{"quiet\n", "root=/dev/sda2 init=$(x)\n", "root=/a\nroot=/b\n"} {
		if ValidateKernelCmdline(KernelCmdline, []byte(bad)) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFallbackScriptUKI(t *testing.T) {
	s, err := FallbackScriptUKI("ABCD-1234")
	if err != nil || ValidateFallbackScript(GrubFallback, []byte(s)) != nil || !strings.Contains(s, "chainloader /EFI/Linux/yking-fallback.efi") {
		t.Fatalf("%v\n%s", err, s)
	}
	if ValidateFallbackScript(GrubFallback, []byte(strings.Replace(s, "chainloader", "linux", 1))) == nil {
		t.Fatal("altered script accepted")
	}
}

// newc writes a cpio archive (what mkinitcpio and microcode images use).
func newc(files map[string]string) []byte {
	var b bytes.Buffer
	pad := func() {
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	entry := func(name, data string, mode int) {
		fmt.Fprintf(&b, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X", 1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
		b.WriteString(name + "\x00")
		pad()
		b.WriteString(data)
		pad()
	}
	for n, d := range files {
		entry(n, d, 0o100644)
	}
	entry("TRAILER!!!", "", 0)
	for b.Len()%512 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func TestSkipEarlyCPIO(t *testing.T) {
	early := newc(map[string]string{"kernel/x86/microcode/GenuineIntel.bin": "ucode"})
	main := []byte("\x28\xb5\x2f\xfdcompressed")
	got, err := SkipEarlyCPIO(append(append([]byte{}, early...), main...))
	if err != nil || !bytes.Equal(got, main) {
		t.Fatalf("%q %v", got, err)
	}
	if got, _ := SkipEarlyCPIO(main); !bytes.Equal(got, main) {
		t.Fatal("no early cpio: must be unchanged")
	}
}

// A real PE built from systemd's EFI stub: the sections are read back and
// the initramfs inside is listed by lsinitcpio.
func TestUKIHas(t *testing.T) {
	stub := "/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
	for _, need := range []string{"objcopy", "zstd", "lsinitcpio"} {
		if _, err := exec.LookPath(need); err != nil {
			t.Skip(need + " not available")
		}
	}
	if _, err := os.Stat(stub); err != nil {
		t.Skip("no systemd EFI stub")
	}
	dir := t.TempDir()
	mainCPIO := filepath.Join(dir, "main.cpio")
	os.WriteFile(mainCPIO, newc(map[string]string{"hooks/encrypt": "#!/bin/ash\n", "etc/crypttab": ""}), 0o644)
	if out, err := exec.Command("zstd", "-q", "-f", mainCPIO, "-o", mainCPIO+".zst").CombinedOutput(); err != nil {
		t.Fatalf("zstd: %v %s", err, out)
	}
	z, _ := os.ReadFile(mainCPIO + ".zst")
	initrd := filepath.Join(dir, "initrd")
	os.WriteFile(initrd, append(newc(map[string]string{"kernel/x86/microcode/GenuineIntel.bin": "ucode"}), z...), 0o644)
	cmd := filepath.Join(dir, "cmdline")
	os.WriteFile(cmd, []byte("cryptdevice=UUID=11111111-2222-3333-4444-555555555555:cryptlvm root=/dev/vg0/root rw\x00"), 0o644)
	uki := filepath.Join(dir, "test.efi")
	if out, err := exec.Command("objcopy",
		"--add-section", ".cmdline="+cmd, "--change-section-vma", ".cmdline=0x30000",
		"--add-section", ".initrd="+initrd, "--change-section-vma", ".initrd=0x3000000",
		stub, uki).CombinedOutput(); err != nil {
		t.Skipf("objcopy cannot build a test UKI here: %v %s", err, out)
	}
	c, _, err := UKISections(uki)
	if err != nil || !strings.HasPrefix(c, "cryptdevice=UUID=") {
		t.Fatalf("%q %v", c, err)
	}
	if err := ukiHas(uki, "cryptdevice=", "", "\nhooks/encrypt"); err != nil {
		t.Fatal(err)
	}
	if err := ukiHas(uki, "root=", "cryptdevice=", "\nhooks/encrypt"); err == nil || !strings.Contains(err.Error(), "still has cryptdevice") {
		t.Fatalf("old line not caught: %v", err)
	}
	if err := ukiHas(uki, "cryptdevice=", "", "libfido2.so"); err == nil {
		t.Fatal("missing file not caught")
	}
}
