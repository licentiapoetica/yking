package pam

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// DefaultMappingPath is pam_u2f's default per-user mapping location.
func DefaultMappingPath(home string) string {
	return filepath.Join(home, ".config", "Yubico", "u2f_keys")
}

// CountCredentials returns how many credentials user has in a pam_u2f
// mapping file ("user:cred:cred…" per line). Missing file → 0.
func CountCredentials(path, user string) (int, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) > 1 && parts[0] == user {
			for _, c := range parts[1:] {
				if strings.TrimSpace(c) != "" {
					n++
				}
			}
		}
	}
	return n, sc.Err()
}

// Facts is what the safety check needs to know.
type Facts struct {
	ModuleInstalled bool // pam_u2f.so present
	Credentials     int  // in the user's mapping
	RegisteredKeys  int  // in yking's keyring
	// ConfirmedKeys are registered keys whose credential was found on the
	// key itself (yking's silent check) and is still in the mapping.
	ConfirmedKeys int
	// PolkitAsksRoot: polkit's admin identity is not this user (Arch: user
	// not in "wheel"), so polkit authenticates ROOT — who has no key
	// credential. Key-only polkit then fails instantly.
	PolkitAsksRoot bool
}

// Check evaluates a set of changes against the safety rules. blocks must
// be empty for the plan to be built; warns are shown alongside.
//
//   - Any mode but off needs pam_u2f installed and ≥1 credential.
//   - Switching a service TO "key only" or "password + key" needs ≥2
//     registered keys and ≥2 credentials (losing one key must not lock
//     you out). Keeping such a mode that already exists only warns.
//   - At least one login path (sudo, login screen, console) must still
//     accept the password alone.
func Check(states []State, changes []Change, f Facts) (blocks, warns []string) {
	final := map[string]Config{}
	for _, s := range states {
		final[s.Service.Name] = s.Current
	}
	cur := map[string]Config{}
	for k, v := range final {
		cur[k] = v
	}
	for _, c := range changes {
		final[c.Service] = c.To
	}

	var noCreds, blocked, kept []string
	for _, s := range states {
		name := s.Service.Name
		to, was := final[name], cur[name]
		if to.Mode == ModeOff {
			continue
		}
		changed := to.Mode != was.Mode || to.Unlock != was.Unlock
		if changed && !f.ModuleInstalled {
			blocks = append(blocks, "pam_u2f.so is not installed (install pam-u2f / libpam-u2f)")
		}
		if changed && f.Credentials == 0 {
			noCreds = append(noCreds, name)
		}
		if (to.Mode == ModeOnly || to.Mode == ModeAnd) && f.ConfirmedKeys < 2 {
			if to.Mode != was.Mode {
				blocked = append(blocked, name)
			} else {
				kept = append(kept, name)
			}
		}
	}
	if len(noCreds) > 0 {
		blocks = append(blocks, fmt.Sprintf("No key credential in the mapping yet, so enabling %s would lock you out.", strings.Join(noCreds, ", ")))
	}
	if len(blocked) > 0 {
		blocks = append(blocks, fmt.Sprintf(
			"\"key only\" / \"password + key\" need at least 2 keys confirmed to work with PAM, so losing one cannot lock you out.\n"+
				"  Affected: %s. Confirmed: %d. On the main screen: register keys (e), then check each one (c).",
			strings.Join(blocked, ", "), f.ConfirmedKeys))
	}
	if len(kept) > 0 {
		warns = append(warns, fmt.Sprintf("%s: no password fallback, but only %d key(s) confirmed to work with PAM — check your keys (main screen → c).",
			strings.Join(kept, ", "), f.ConfirmedKeys))
	}

	if f.PolkitAsksRoot {
		to, was := final["polkit-1"], cur["polkit-1"]
		if to.Mode == ModeOnly || to.Mode == ModeAnd {
			msg := "polkit asks for ROOT (you are not in the \"wheel\" group), and root has no key credential:\n" +
				"  \"key only\" / \"password + key\" makes admin prompts fail (e.g. Flatpak installs). Use \"key or password\",\n" +
				"  or add yourself to wheel (sudo usermod -aG wheel $USER, then log in again)."
			if to.Mode != was.Mode {
				blocks = append(blocks, msg)
			} else {
				warns = append(warns, msg)
			}
		}
	}

	passwordPath := false
	for _, s := range states {
		if s.Service.LoginPath && final[s.Service.Name].Mode.PasswordWorks() {
			passwordPath = true
		}
	}
	if !passwordPath {
		blocks = append(blocks, "No way in with a password would be left. Keep at least one of sudo, the login screen or the\n"+
			"  text console at \"off\" or \"key or password\" — the console (Ctrl+Alt+F2) is a good emergency door.")
	}
	return dedupe(blocks), dedupe(warns)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// PolkitAsksRoot reports whether polkit would authenticate root instead of
// user for admin actions: Arch's default rule makes "wheel" the admins; a
// user outside wheel gets asked for root. (Extra rules in
// /etc/polkit-1/rules.d are not readable without root and not considered.)
func PolkitAsksRoot(username string) bool {
	u, err := user.Lookup(username)
	if err != nil {
		return false
	}
	g, err := user.LookupGroup("wheel")
	if err != nil {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, id := range gids {
		if id == g.Gid {
			return false
		}
	}
	return true
}
