// Package deps checks the programs and services yking relies on and says
// how to install what is missing (Arch and Debian/Ubuntu package names).
package deps

import (
	"bufio"
	"os"
	"os/exec"
	"strings"

	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/sshkey"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// Distro is the package family.
type Distro int

const (
	Other Distro = iota
	Arch
	Debian // also Ubuntu, Mint
)

// Tool is something yking runs.
type Tool struct {
	Bin      string // executable in $PATH
	For      string // what breaks without it
	Required bool   // yking's core (keys, PAM, SSH) needs it
	Arch     string // package names
	Debian   string
}

// Tools in the order they matter.
var Tools = []Tool{
	{ykman.Binary, "reading and setting up keys", true, "yubikey-manager", "yubikey-manager"},
	{fido.AssertBinary, "key tests, PAM credential checks", true, "libfido2", "fido2-tools"},
	{"pamu2fcfg", "PAM credentials", true, "pam-u2f", "pamu2fcfg"},
	{sshkey.KeygenBinary, "SSH keys", true, "openssh", "openssh-client"},
	{"pcscd", "smart-card access: OpenPGP, OTP on newer keys", true, "pcsclite ccid", "pcscd libccid"},
	{"cryptsetup", "disk encryption", false, "cryptsetup", "cryptsetup-bin"},
	{"systemd-cryptenroll", "disk encryption with keys", false, "systemd", "systemd-cryptsetup"},
	{"gpg", "PGP", false, "gnupg", "gnupg scdaemon"},
	{"git", "git signing", false, "git", "git"},
}

// Problem is one missing piece and the command that fixes it.
type Problem struct {
	What     string
	For      string
	Required bool
	Fix      string   // shell command to show (may be empty)
	Pkgs     []string // packages that fix it (Install)
	Unit     string   // systemd unit to enable --now
}

// System is what Check looks at (tests replace it).
type System struct {
	LookPath   func(string) (string, error)
	Exists     func(string) bool
	PAMModule  func() bool // pam_u2f.so installed
	OTPAccess  func() string
	OSRelease  string // contents of /etc/os-release
	PCSCSocket string
	CCIDDriver string
}

// Local is this machine.
func Local(pamModule func() bool, otpAccess func() string) System {
	osr, _ := os.ReadFile("/etc/os-release")
	return System{
		LookPath:   exec.LookPath,
		Exists:     func(p string) bool { _, err := os.Stat(p); return err == nil },
		PAMModule:  pamModule,
		OTPAccess:  otpAccess,
		OSRelease:  string(osr),
		PCSCSocket: "/run/pcscd/pcscd.comm",
		CCIDDriver: "/usr/lib/pcsc/drivers/ifd-ccid.bundle",
	}
}

// DistroOf reads ID / ID_LIKE from os-release.
func DistroOf(osRelease string) Distro {
	ids := ""
	sc := bufio.NewScanner(strings.NewReader(osRelease))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && (k == "ID" || k == "ID_LIKE") {
			ids += " " + strings.Trim(v, `"`)
		}
	}
	for _, id := range strings.Fields(ids) {
		switch id {
		case "arch":
			return Arch
		case "debian", "ubuntu":
			return Debian
		}
	}
	return Other
}

// Install is the command installing pkgs ("" when unknown).
func Install(d Distro, pkgs string) string {
	switch {
	case pkgs == "":
		return ""
	case d == Arch:
		return "sudo pacman -S --needed " + pkgs
	case d == Debian:
		return "sudo apt install " + pkgs
	}
	return ""
}

func pkgOf(d Distro, t Tool) string {
	if d == Debian {
		return t.Debian
	}
	return t.Arch
}

// Check returns what is missing, most important first.
func Check(s System) []Problem {
	d := DistroOf(s.OSRelease)
	var out []Problem
	add := func(p Problem) { out = append(out, p) }
	for _, t := range Tools {
		if _, err := s.LookPath(t.Bin); err != nil {
			fix := Install(d, pkgOf(d, t))
			if fix == "" {
				fix = "install " + t.Bin
			}
			p := Problem{What: t.Bin + " missing", For: t.For, Required: t.Required, Fix: fix}
			if d != Other {
				p.Pkgs = strings.Fields(pkgOf(d, t))
			}
			if t.Bin == "pcscd" {
				p.Unit = pcscdUnit
			}
			add(p)
			continue
		}
		if t.Bin != "pcscd" {
			continue
		}
		if !s.Exists(s.CCIDDriver) {
			pkg := map[Distro]string{Arch: "ccid", Debian: "libccid"}[d]
			add(Problem{What: "CCID driver missing", For: "pcscd cannot see the YubiKey", Required: true, Fix: Install(d, pkg), Pkgs: strings.Fields(pkg)})
		}
		if !s.Exists(s.PCSCSocket) {
			add(Problem{What: "pcscd not running", For: t.For, Required: true, Fix: "sudo systemctl enable --now " + pcscdUnit, Unit: pcscdUnit})
		}
	}
	if s.PAMModule != nil && !s.PAMModule() {
		pkg := map[Distro]string{Arch: "pam-u2f", Debian: "libpam-u2f"}[d]
		add(Problem{What: "pam_u2f.so missing", For: "logging in with a key", Required: true, Fix: Install(d, pkg), Pkgs: strings.Fields(pkg)})
	}
	if s.OTPAccess != nil {
		if why := s.OTPAccess(); why != "" && !strings.HasPrefix(why, "no YubiKey") {
			add(Problem{What: why, For: "KeePassXC challenge-response", Fix: "KeePassXC screen (v) → u"})
		}
	}
	// Required first, keeping the order within each group.
	var req, opt []Problem
	for _, p := range out {
		if p.Required {
			req = append(req, p)
		} else {
			opt = append(opt, p)
		}
	}
	return append(req, opt...)
}

const pcscdUnit = "pcscd.socket"

// Actions is what yking can fix by itself: packages and units, deduplicated.
func Actions(ps []Problem) (pkgs, units []string) {
	seen := map[string]bool{}
	for _, p := range ps {
		for _, k := range p.Pkgs {
			if !seen[k] {
				seen[k] = true
				pkgs = append(pkgs, k)
			}
		}
		if p.Unit != "" && !seen[p.Unit] {
			seen[p.Unit] = true
			units = append(units, p.Unit)
		}
	}
	return pkgs, units
}

// InstallArgs is the non-interactive install command for pkgs.
func InstallArgs(d Distro, pkgs []string) []string {
	switch d {
	case Arch:
		return append([]string{"pacman", "-S", "--needed", "--noconfirm"}, pkgs...)
	case Debian:
		return append([]string{"apt-get", "install", "-y"}, pkgs...)
	}
	return nil
}

// Fixes merges the install commands of problems into one per kind, so the
// user runs one line: "sudo pacman -S --needed a b c".
func Fixes(ps []Problem) []string {
	var pkgs, other []string
	var prefix string
	seen := map[string]bool{}
	installs := func(fix string) bool {
		for _, pre := range []string{"sudo pacman -S --needed ", "sudo apt install "} {
			if rest, ok := strings.CutPrefix(fix, pre); ok {
				prefix = pre
				for _, f := range strings.Fields(rest) {
					if !seen[f] {
						seen[f] = true
						pkgs = append(pkgs, f)
					}
				}
				return true
			}
		}
		return false
	}
	for _, p := range ps {
		if !installs(p.Fix) && p.Fix != "" && !seen[p.Fix] {
			seen[p.Fix] = true
			other = append(other, p.Fix)
		}
	}
	var out []string
	if len(pkgs) > 0 {
		out = append(out, prefix+strings.Join(pkgs, " "))
	}
	return append(out, other...)
}
