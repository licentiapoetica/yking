package sshkey

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"yking/internal/keyring"
	"yking/internal/plan"
)

// SSHBinary is the ssh client. Only this package runs it.
const SSHBinary = "ssh"

// Deploying is ALWAYS an explicit, per-host user action. Nothing in yking
// deploys automatically or edits ~/.ssh/config.

var b64Re = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

var targetRe = regexp.MustCompile(`^([A-Za-z0-9._][A-Za-z0-9._-]*@)?[A-Za-z0-9_][A-Za-z0-9._:-]*$`)

// ValidTarget checks a "host", "alias" or "user@host" target. It must not
// start with "-" (would be parsed as an ssh option).
func ValidTarget(t string) error {
	if !targetRe.MatchString(t) {
		return fmt.Errorf("invalid target %q (use host, ssh alias or user@host)", t)
	}
	return nil
}

// AuthorizedLine is the authorized_keys line for a key. PIN-only keys need
// "no-touch-required" or sshd rejects their signatures.
func AuthorizedLine(pubLine string, e keyring.SSHKey) (string, error) {
	f := strings.Fields(strings.TrimSpace(pubLine))
	if len(f) < 2 {
		return "", errors.New("bad public key line")
	}
	line := strings.Join(f, " ")
	if e.NoTouchRequired {
		line = "no-touch-required " + line
	}
	return line, nil
}

// remoteAdd runs under POSIX sh on the server. It reads the full line and
// the bare key blob from stdin. It never removes or rewrites existing lines.
// Must not contain single quotes (it is wrapped in sh -c '…').
const remoteAdd = `umask 077
IFS= read -r line || exit 3
IFS= read -r blob || exit 3
mkdir -p "$HOME/.ssh" || exit 4
f="$HOME/.ssh/authorized_keys"
if [ -f "$f" ] && grep -qxF -- "$line" "$f"; then echo "yking-result:already"; exit 0; fi
if [ -f "$f" ] && grep -qF -- "$blob" "$f"; then echo "yking-result:different"; exit 0; fi
if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then printf "\n" >> "$f" || exit 5; fi
printf "%s\n" "$line" >> "$f" || exit 5
grep -qxF -- "$line" "$f" && echo "yking-result:added"`

// DeployResult is what the server reported.
type DeployResult int

const (
	DeployUnknown   DeployResult = iota
	DeployAdded                  // line appended
	DeployAlready                // exact line already there
	DeployDifferent              // key present with other options; left alone
)

func (r DeployResult) String() string {
	switch r {
	case DeployAdded:
		return "added"
	case DeployAlready:
		return "already present"
	case DeployDifferent:
		return "present with different options (left unchanged)"
	default:
		return "unknown"
	}
}

// DeployCommand builds the ssh command adding line to target's
// authorized_keys. With identity == "" the user's normal ssh auth is used;
// otherwise only that key file is offered (passwords remain possible).
// Prompts go to the terminal.
func DeployCommand(target, line, identity string) (*exec.Cmd, error) {
	if err := ValidTarget(target); err != nil {
		return nil, err
	}
	var idArgs []string
	if identity != "" {
		if !filepath.IsAbs(identity) {
			return nil, fmt.Errorf("identity file must be an absolute path: %q", identity)
		}
		if fi, err := os.Stat(identity); err != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("identity file %s not usable", identity)
		}
		idArgs = []string{"-i", identity, "-o", "IdentitiesOnly=yes"}
	}
	f := strings.Fields(line)
	blob := ""
	for i, p := range f {
		if strings.HasPrefix(p, "sk-") && i+1 < len(f) {
			blob = f[i+1]
			break
		}
	}
	if blob == "" {
		return nil, errors.New("line has no security-key blob")
	}
	args := append(idArgs, "-o", "ClearAllForwardings=yes", "--", target, "sh -c '"+remoteAdd+"'")
	cmd := exec.Command(SSHBinary, args...)
	cmd.Stdin = strings.NewReader(line + "\n" + blob + "\n")
	return cmd, nil
}

// IdentityFiles lists private key files in dir: regular files that have a
// matching .pub next to them. Sorted, absolute paths.
func IdentityFiles(dir string) []string {
	pubs, _ := filepath.Glob(filepath.Join(dir, "*.pub"))
	sort.Strings(pubs)
	var out []string
	for _, p := range pubs {
		priv := strings.TrimSuffix(p, ".pub")
		if fi, err := os.Stat(priv); err == nil && fi.Mode().IsRegular() {
			out = append(out, priv)
		}
	}
	return out
}

// ParseDeployOutput finds the result marker in captured stdout.
func ParseDeployOutput(out []byte) DeployResult {
	switch {
	case bytes.Contains(out, []byte("yking-result:added")):
		return DeployAdded
	case bytes.Contains(out, []byte("yking-result:already")):
		return DeployAlready
	case bytes.Contains(out, []byte("yking-result:different")):
		return DeployDifferent
	}
	return DeployUnknown
}

// TestLoginCommand logs in with ONLY this key (no passwords, no other
// keys) and runs `true`. env carries the askpass PIN guard.
func TestLoginCommand(target, privPath string, env []string) (*exec.Cmd, error) {
	if err := ValidTarget(target); err != nil {
		return nil, err
	}
	cmd := exec.Command(SSHBinary,
		"-i", privPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PreferredAuthentications=publickey",
		"-o", "ClearAllForwardings=yes",
		"--", target, "true")
	cmd.Env = append(os.Environ(), env...)
	return cmd, nil
}

// RecordHostPlan adds target to the hosts of the SSH key with fingerprint.
// Returns ErrNoChanges if already recorded.
func RecordHostPlan(krPath, fingerprint, target string, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	kr, err := keyring.Parse(base.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", krPath, err)
	}
	for i := range kr.Keys {
		k := &kr.Keys[i]
		for j := range k.SSH {
			s := &k.SSH[j]
			if s.Fingerprint != fingerprint {
				continue
			}
			for _, h := range s.Hosts {
				if h == target {
					return nil, plan.ErrNoChanges
				}
			}
			s.Hosts = append(s.Hosts, target)
			content, err := kr.Encode()
			if err != nil {
				return nil, err
			}
			p := plan.New(fmt.Sprintf("record %s as deployed to %s", s.Comment, target), now)
			p.Replace(base, content, 0o644)
			return p, nil
		}
	}
	return nil, fmt.Errorf("SSH key %s is not in the keyring", fingerprint)
}
