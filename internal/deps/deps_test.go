package deps

import (
	"errors"
	"strings"
	"testing"
)

func system(osr string, missing ...string) System {
	gone := map[string]bool{}
	for _, m := range missing {
		gone[m] = true
	}
	return System{
		LookPath: func(b string) (string, error) {
			if gone[b] {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + b, nil
		},
		Exists:     func(p string) bool { return !gone[p] },
		PAMModule:  func() bool { return !gone["pam_u2f.so"] },
		OTPAccess:  func() string { return "" },
		OSRelease:  osr,
		PCSCSocket: "/run/pcscd/pcscd.comm",
		CCIDDriver: "/usr/lib/pcsc/drivers/ifd-ccid.bundle",
	}
}

func TestDistro(t *testing.T) {
	for osr, want := range map[string]Distro{
		"ID=arch\n":                      Arch,
		"ID=endeavouros\nID_LIKE=arch\n": Arch,
		"ID=debian\n":                    Debian,
		"ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n": Debian,
		"ID=fedora\n": Other,
	} {
		if got := DistroOf(osr); got != want {
			t.Errorf("%q: %v", osr, got)
		}
	}
}

func TestAllThere(t *testing.T) {
	if p := Check(system("ID=arch\n")); len(p) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestPCSCNotRunning(t *testing.T) {
	p := Check(system("ID=arch\n", "/run/pcscd/pcscd.comm", "gpg"))
	if len(p) != 2 || p[0].What != "pcscd not running" || !p[0].Required || p[0].Fix != "sudo systemctl enable --now pcscd.socket" {
		t.Fatalf("%+v", p)
	}
	if p[1].Required || p[1].Fix != "sudo pacman -S --needed gnupg" {
		t.Fatalf("optional gpg: %+v", p[1])
	}
}

func TestDebianNamesAndMergedFix(t *testing.T) {
	p := Check(system("ID=debian\n", "pcscd", "fido2-assert", "pam_u2f.so"))
	got := strings.Join(Fixes(p), " | ")
	if got != "sudo apt install fido2-tools pcscd libccid libpam-u2f" {
		t.Fatalf("%q from %+v", got, p)
	}
}
