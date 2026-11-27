package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/plan"
)

// HomeDir is the user's GnuPG home.
func HomeDir(home string) string {
	if h := os.Getenv("GNUPGHOME"); h != "" {
		return h
	}
	return filepath.Join(home, ".gnupg")
}

// ScdaemonPath is the user's scdaemon.conf.
func ScdaemonPath(home string) string { return filepath.Join(HomeDir(home), "scdaemon.conf") }

// scdaemon's own USB driver grabs the YubiKey exclusively, so gpg and
// ykman (pcscd) lock each other out. disable-ccid makes it use pcscd;
// pcsc-shared lets both use the card.
var scdaemonOptions = []string{"disable-ccid", "pcsc-shared"}

func options(content string) map[string]bool {
	set := map[string]bool{}
	for _, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		set[strings.Fields(l)[0]] = true
	}
	return set
}

// ScdaemonOK reports whether scdaemon.conf shares the card with pcscd.
func ScdaemonOK(content string) bool {
	set := options(content)
	for _, o := range scdaemonOptions {
		if !set[o] {
			return false
		}
	}
	return true
}

// ScdaemonPlan adds the missing options to scdaemon.conf.
func ScdaemonPlan(home string, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(ScdaemonPath(home))
	if err != nil {
		return nil, err
	}
	cur := string(base.Data)
	set := options(cur)
	var add []string
	for _, o := range scdaemonOptions {
		if !set[o] {
			add = append(add, o)
		}
	}
	if len(add) == 0 {
		return nil, plan.ErrNoChanges
	}
	if cur != "" && !strings.HasSuffix(cur, "\n") {
		cur += "\n"
	}
	cur += "# yking: share the YubiKey with pcscd (ykman)\n" + strings.Join(add, "\n") + "\n"
	p := plan.New("gpg: use pcscd for the YubiKey", now)
	p.Replace(base, []byte(cur), 0o600)
	return p, nil
}

// ValidateScdaemon accepts scdaemon.conf with the sharing options.
func ValidateScdaemon(path string, content []byte) error {
	if filepath.Base(path) != "scdaemon.conf" {
		return fmt.Errorf("yking does not write %s", path)
	}
	if bytes.ContainsRune(content, 0) {
		return errors.New("NUL byte in scdaemon.conf")
	}
	if !ScdaemonOK(string(content)) {
		return errors.New("scdaemon.conf lacks disable-ccid / pcsc-shared")
	}
	return nil
}

// GitConfigPath is the global git config file git itself uses.
func GitConfigPath(home string) string {
	dot := filepath.Join(home, ".gitconfig")
	if _, err := os.Stat(dot); err == nil {
		return dot
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	if p := filepath.Join(xdg, "git", "config"); fileExists(p) {
		return p
	}
	return dot
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// GitSigningPlan makes git sign commits and tags with subkey fpr.
func GitSigningPlan(home, fpr string, now time.Time) (*plan.Plan, error) {
	path := GitConfigPath(home)
	base, err := plan.ReadBase(path)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "yking-gitconfig-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	tmp.Write(base.Data)
	tmp.Close()
	for _, kv := range [][2]string{
		{"user.signingkey", fpr + "!"},
		{"gpg.format", "openpgp"},
		{"commit.gpgsign", "true"},
		{"tag.gpgsign", "true"},
	} {
		cmd := exec.Command("git", "config", "--file", tmp.Name(), kv[0], kv[1])
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git config %s: %v: %s", kv[0], err, strings.TrimSpace(string(out)))
		}
	}
	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, err
	}
	p := plan.New("git: sign commits and tags with "+Short(fpr), now)
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	p.Replace(base, content, mode)
	if p.Empty() {
		return nil, plan.ErrNoChanges
	}
	return p, nil
}

// GitSigningKey is the configured user.signingkey ("" if none).
func GitSigningKey() string {
	out, err := exec.Command("git", "config", "--global", "--get", "user.signingkey").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ValidateGitConfig accepts the global git config files.
func ValidateGitConfig(path string, content []byte) error {
	base := filepath.Base(path)
	if base != ".gitconfig" && !(base == "config" && filepath.Base(filepath.Dir(path)) == "git") {
		return fmt.Errorf("yking does not write %s", path)
	}
	if bytes.ContainsRune(content, 0) {
		return errors.New("NUL byte in git config")
	}
	return nil
}
