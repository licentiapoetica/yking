package fido

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCountDevices(t *testing.T) {
	root := t.TempDir()
	add := func(name string, desc []byte) {
		d := filepath.Join(root, name, "device")
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "report_descriptor"), desc, 0o444)
	}
	add("hidraw0", []byte{0x05, 0x01, 0x09, 0x06})             // keyboard
	add("hidraw1", []byte{0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1}) // YubiKey FIDO
	add("hidraw2", []byte{0x06, 0x00, 0xff, 0x09})             // vendor
	os.MkdirAll(filepath.Join(root, "hidraw3"), 0o755)         // no descriptor

	n, err := CountDevices(root)
	if err != nil || n != 1 {
		t.Fatalf("got %d, %v", n, err)
	}
	add("hidraw4", []byte{0x06, 0xd0, 0xf1})
	if n, _ := CountDevices(root); n != 2 {
		t.Fatalf("got %d, want 2", n)
	}
}

func TestProbeRefusesBadInput(t *testing.T) {
	for _, c := range []struct{ dev, rp, kh string }{
		{"/dev/sda", "pam://h", "abc"},
		{"/dev/hidraw1", "pam://h", "a b"},
		{"/dev/hidraw1", "pam://h\nx", "abc"},
		{"/dev/hidraw1", "", "abc"},
	} {
		if err := Probe(t.Context(), c.dev, c.rp, c.kh); err == nil || err == ErrNotThisKey {
			t.Errorf("Probe(%q,%q,%q) = %v", c.dev, c.rp, c.kh, err)
		}
	}
	a := strings.Join(ProbeArgs("/dev/hidraw5"), " ")
	if a != "-G -t up=false -t uv=false -t pin=false /dev/hidraw5" {
		t.Errorf("args = %q", a)
	}
	for _, forbidden := range []string{"-v", "-p", "pin=true", "uv=true", "up=true", "-r"} {
		for _, x := range ProbeArgs("/dev/hidraw5") {
			if x == forbidden {
				t.Errorf("probe must stay silent, found %q", x)
			}
		}
	}
}

func TestDevices(t *testing.T) {
	root := t.TempDir()
	for name, desc := range map[string][]byte{"hidraw3": {0x06, 0xd0, 0xf1}, "hidraw4": {0x05, 0x01}} {
		d := filepath.Join(root, name, "device")
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "report_descriptor"), desc, 0o444)
	}
	got, _ := Devices(root)
	if len(got) != 1 || got[0] != "/dev/hidraw3" {
		t.Errorf("got %v", got)
	}
}
