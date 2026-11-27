package luks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func fx(t *testing.T, n string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", n))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseLsblk(t *testing.T) {
	v, err := ParseLsblk([]byte(fx(t, "lsblk.json")))
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v[0].Device != "/dev/vda2" || v[0].Version != 2 || v[0].Mapper != "cryptroot" || !v[0].Root || !v[0].RootLV || v[0].UUID == "" {
		t.Errorf("got %+v", v)
	}
}

func TestParseHeader(t *testing.T) {
	h, err := ParseHeader([]byte(fx(t, "header-password-only.json")))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Slots) != 1 || !slices.Equal(h.PasswordSlots(), []int{0}) || len(h.FIDO2()) != 0 {
		t.Errorf("password-only: %+v", h)
	}
	h, err = ParseHeader([]byte(fx(t, "header-fido2.json")))
	if err != nil {
		t.Fatal(err)
	}
	f := h.FIDO2()
	if len(f) != 1 || !slices.Equal(f[0].Keyslots, []int{1}) || !f[0].PINRequired || f[0].UPRequired || f[0].Credential != "Q1JFRA==" {
		t.Errorf("fido2 token: %+v", f)
	}
	if !slices.Equal(h.PasswordSlots(), []int{0}) || h.Slots[1].Token == nil {
		t.Errorf("slots: %+v", h.Slots)
	}
}

func TestConvertHooks(t *testing.T) {
	host := strings.Fields("base udev autodetect microcode modconf kms keyboard keymap consolefont block encrypt lvm2 filesystems fsck")
	got, err := ConvertHooks(host)
	if err != nil {
		t.Fatal(err)
	}
	want := "base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt lvm2 filesystems fsck"
	if strings.Join(got, " ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
	if MethodOf(got) != "sd-encrypt" {
		t.Error("converted hooks not recognised as sd-encrypt")
	}
	if _, err := ConvertHooks(append(host, "netconf")); err == nil {
		t.Error("unknown hook accepted")
	}
	if _, err := ConvertHooks(got); err == nil {
		t.Error("already converted hooks accepted")
	}
}

func TestReplaceHooksOnRealConf(t *testing.T) {
	conf := fx(t, "mkinitcpio.conf")
	old, err := ParseHooks(conf)
	if err != nil {
		t.Fatal(err)
	}
	nh, _ := ConvertHooks(old)
	out, err := ReplaceHooks(conf, old, nh)
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := ParseHooks(out); MethodOf(h) != "sd-encrypt" {
		t.Errorf("new hooks: %v", h)
	}
	if !strings.Contains(out, "# yking: converted for FIDO2 unlocking; was: HOOKS=(base udev") {
		t.Error("no note with the old line")
	}
	if len(strings.Split(out, "\n")) != len(strings.Split(conf, "\n"))+1 {
		t.Error("more than the HOOKS line changed")
	}
	if err := ValidateMkinitcpio(MkinitcpioConf, []byte(out)); err != nil {
		t.Error(err)
	}
	if err := ValidateMkinitcpio(FallbackConf, []byte(conf)); err != nil {
		t.Errorf("fallback (old) conf refused: %v", err)
	}
	if err := ValidateMkinitcpio(FallbackConf, []byte(out)); err == nil {
		t.Error("fallback conf with new hooks accepted")
	}
	mixed := hooksRe.ReplaceAllLiteralString(out, "HOOKS=(base systemd autodetect keyboard keymap block sd-encrypt lvm2 filesystems fsck)")
	if err := ValidateMkinitcpio(MkinitcpioConf, []byte(mixed)); err == nil {
		t.Error("mixed hooks accepted")
	}
}

func TestCrypttab(t *testing.T) {
	host := "# /etc/crypttab: mappings for encrypted partitions.\n#\n# <name>       <device>                         <password> <options>\n"
	c := RenderCrypttab(host, "cryptroot", "479e17f9-090b-47e0-ac64-6aa013bfb3fc")
	if !strings.HasPrefix(c, host) || !strings.HasSuffix(c, "cryptroot UUID=479e17f9-090b-47e0-ac64-6aa013bfb3fc none fido2-device=auto,x-initrd.attach\n") {
		t.Errorf("got %q", c)
	}
	if err := ValidateCrypttab(Crypttab, []byte(c)); err != nil {
		t.Error(err)
	}
	c2 := RenderCrypttab("# mine\nother UUID=x /root/key discard\ncryptroot UUID=old none\n", "cryptroot", "new")
	if !strings.Contains(c2, "other UUID=x /root/key discard") || !strings.Contains(c2, "cryptroot UUID=new none fido2-device=auto,x-initrd.attach") || strings.Contains(c2, "UUID=old") {
		t.Errorf("replace: %q", c2)
	}
	if err := ValidateCrypttab(Crypttab, []byte(c2)); err != nil {
		t.Errorf("user's own keyfile line refused: %v", err)
	}
	for _, bad := range []string{"", "# only comments\n", "cryptroot\n", "cryptroot UUID=x none keyscript=/bin/sh\n", "c UUID=x none a,$(id)\n"} {
		if err := ValidateCrypttab(Crypttab, []byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRootflags(t *testing.T) {
	out, err := AddRootflagsTimeout("GRUB_CMDLINE_LINUX=\"root=/dev/mapper/vg-root rw\"\n")
	if err != nil || !strings.Contains(out, "root=/dev/mapper/vg-root rw rootflags=x-systemd.device-timeout=0\"") {
		t.Errorf("add: %q %v", out, err)
	}
	out, _ = AddRootflagsTimeout("GRUB_CMDLINE_LINUX=\"root=x rootflags=noatime\"\n")
	if !strings.Contains(out, "rootflags=noatime,x-systemd.device-timeout=0") {
		t.Errorf("merge: %q", out)
	}
	again, _ := AddRootflagsTimeout(out)
	if strings.Count(again, "device-timeout") != 1 {
		t.Errorf("not idempotent: %q", again)
	}
}

func TestGrub(t *testing.T) {
	g := fx(t, "grub")
	before := GrubCmdline(g)
	if !strings.Contains(before, "cryptdevice=UUID=") || !strings.Contains(before, "root=/dev/mapper/vgcrypt-archcrypt") {
		t.Fatalf("cmdline = %q", before)
	}
	out, removed, err := RemoveCryptdevice(g)
	if err != nil {
		t.Fatal(err)
	}
	after := GrubCmdline(out)
	if len(removed) != 1 || strings.Contains(after, "cryptdevice") || !strings.Contains(after, "root=/dev/mapper/vgcrypt-archcrypt rw") || !strings.Contains(after, "quiet") {
		t.Errorf("after = %q removed = %v", after, removed)
	}
	if err := ValidateGrubDefault(GrubDefault, []byte(out)); err != nil {
		t.Error(err)
	}
	if _, _, err := RemoveCryptdevice(out); err == nil {
		t.Error("second removal should report nothing to remove")
	}
	if _, _, err := RemoveCryptdevice("GRUB_CMDLINE_LINUX=\"$(evil) cryptdevice=x\"\n"); err == nil {
		t.Error("shell expansion accepted")
	}
	if err := ValidateGrubDefault(GrubDefault, []byte("GRUB_CMDLINE_LINUX=\"quiet\"\n")); err == nil {
		t.Error("grub without root= accepted")
	}

	s, err := FallbackScript("F5D9-2456", before)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFallbackScript(GrubFallback, []byte(s)); err != nil {
		t.Errorf("own script refused: %v\n%s", err, s)
	}
	if err := ValidateFallbackScript(GrubFallback, []byte(strings.Replace(s, "initrd /initramfs", "insmod evil\n\tinitrd /initramfs", 1))); err == nil {
		t.Error("modified script accepted")
	}
	if _, err := FallbackScript("F5D9-2456", "root=x init=$(sh)"); err == nil {
		t.Error("unsafe kernel parameter accepted")
	}
}

func TestEnrollArgs(t *testing.T) {
	a, err := EnrollArgs("/dev/vda2", "/dev/hidraw2", UnlockTouch)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(a, " ")
	want := "--fido2-device=/dev/hidraw2 --fido2-with-client-pin=no --fido2-with-user-presence=yes --fido2-with-user-verification=no /dev/vda2"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	for _, bad := range [][2]string{{"/dev/vda2; rm", "/dev/hidraw2"}, {"/dev/vda2", "/dev/sda"}, {"vda2", "/dev/hidraw2"}} {
		if _, err := EnrollArgs(bad[0], bad[1], UnlockPINTouch); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	for _, a := range []string{"--wipe-slot", "--password", "--recovery-key"} {
		if strings.Contains(got, a) {
			t.Errorf("enroll args must never contain %s", a)
		}
	}
	if u, _ := ParseUnlock("touch"); u.PIN() || !u.Touch() {
		t.Error("touch mode")
	}
	if _, err := ParseUnlock("none"); err == nil {
		t.Error("unknown unlock accepted")
	}
	if _, err := ParseUnlock("pin"); err == nil || !strings.Contains(err.Error(), "touch") {
		t.Errorf("PIN-only must be refused with a reason: %v", err)
	}
}

func TestNewFIDO2Token(t *testing.T) {
	before, _ := ParseHeader([]byte(fx(t, "header-password-only.json")))
	after, _ := ParseHeader([]byte(fx(t, "header-fido2.json")))
	tok, err := NewFIDO2Token(before, after)
	if err != nil || tok.Keyslots[0] != 1 {
		t.Fatalf("tok=%+v err=%v", tok, err)
	}
	if _, err := NewFIDO2Token(after, after); err == nil {
		t.Error("no new token should be an error")
	}
}

// fakeAsk creates a systemd-style ask file plus a datagram socket and
// returns a channel receiving what an agent sends.
func fakeAsk(t *testing.T, dir string, pid int, name, msg string) <-chan string {
	t.Helper()
	sock := filepath.Join(dir, "sck."+name)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err == nil {
			got <- string(buf[:n])
		}
	}()
	content := fmt.Sprintf("[Ask]\nPID=%d\nSocket=%s\nEcho=0\nMessage=%s\n", pid, sock, msg)
	os.WriteFile(filepath.Join(dir, "ask."+name), []byte(content), 0o600)
	return got
}

func withAskDir(t *testing.T) string {
	dir := t.TempDir()
	old := AskDir
	AskDir = dir
	t.Cleanup(func() { AskDir = old })
	return dir
}

func TestAgentAnswersOnceThenKills(t *testing.T) {
	dir := withAskDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	killed := make(chan bool, 1)
	done := make(chan error, 1)
	go func() { done <- AnswerPINOnce(ctx, 4242, []byte("123456"), func() { killed <- true }, false) }()

	fakeAsk(t, dir, 9999, "other", "Please enter security token PIN") // other process: ignored
	first := fakeAsk(t, dir, 4242, "a", "Please enter security token PIN (remaining attempts before lock-out: 8):")
	select {
	case v := <-first:
		if v != "+123456" {
			t.Fatalf("sent %q", v)
		}
	case <-ctx.Done():
		t.Fatal("first request not answered")
	}
	second := fakeAsk(t, dir, 4242, "b", "Please enter security token PIN (remaining attempts before lock-out: 7):")
	if err := <-done; !errors.Is(err, ErrSecondRequest) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-killed:
	default:
		t.Fatal("process not killed on second request")
	}
	select {
	case v := <-second:
		t.Fatalf("second request answered with %q", v)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestAgentRefusesNonPINAndRefuseAll(t *testing.T) {
	dir := withAskDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	killed := false
	go func() {
		time.Sleep(100 * time.Millisecond)
		fakeAsk(t, dir, 7, "p", "Please enter current passphrase for disk")
	}()
	if err := AnswerPINOnce(ctx, 7, []byte("1234"), func() { killed = true }, false); !errors.Is(err, ErrSecondRequest) || !killed {
		t.Errorf("passphrase request: err=%v killed=%v", err, killed)
	}
	dir2 := withAskDir(t)
	killed = false
	go func() {
		time.Sleep(100 * time.Millisecond)
		fakeAsk(t, dir2, 8, "q", "Please enter security token PIN")
	}()
	if err := AnswerPINOnce(ctx, 8, nil, func() { killed = true }, true); !errors.Is(err, ErrSecondRequest) || !killed {
		t.Errorf("refuseAll: err=%v killed=%v", err, killed)
	}
}

func TestDropIns(t *testing.T) {
	if err := ValidateConsoleDropIn(ConsoleDropIn, []byte(ConsoleDropInContent)); err != nil {
		t.Error(err)
	}
	if err := ValidateConsoleDropIn(ConsoleDropIn, []byte(ConsoleDropInContent+"ExecStartPre=/bin/sh\n")); err == nil {
		t.Error("modified drop-in accepted")
	}
	if err := ValidateMkinitcpioDropIn(MkinitcpioDropIn, []byte(MkinitcpioDropInContent)); err != nil {
		t.Error(err)
	}
	if err := ValidateMkinitcpioDropIn("/etc/mkinitcpio.conf.d/other.conf", []byte(MkinitcpioDropInContent)); err == nil {
		t.Error("other drop-in name accepted")
	}
	if !strings.Contains(ConsoleDropInContent, "SYSTEMD_LOG_TARGET=console") {
		t.Error("without SYSTEMD_LOG_TARGET=console the messages bypass the console (tested in the VM)")
	}
	r := Rebuilds([]string{ConsoleDropIn, MkinitcpioDropIn})
	if len(r) != 2 || r[0][1] != "daemon-reload" || r[1][1] != "-P" {
		t.Errorf("rebuilds = %v", r)
	}
}
