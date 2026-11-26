package sshkey

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// remoteRemove runs under POSIX sh on the server. It reads the key blob
// from stdin and removes every authorized_keys line containing it — but
// only if at least one OTHER key line remains (never lock the user out of
// the server), and only after a backup copy was made next to the file.
// Must not contain single quotes.
const remoteRemove = `umask 077
IFS= read -r blob || exit 3
f="$HOME/.ssh/authorized_keys"
if [ ! -f "$f" ] || ! grep -qF -- "$blob" "$f"; then echo "yking-result:absent"; exit 0; fi
others=$(grep -vF -- "$blob" "$f" | grep -cE "^[^#[:space:]]")
if [ "$others" -lt 1 ]; then echo "yking-result:last"; exit 0; fi
b="$f.yking-bak-$(date +%Y%m%d%H%M%S)"
cp -p "$f" "$b" || exit 5
t="$f.yking-tmp.$$"
grep -vF -- "$blob" "$f" > "$t" || exit 5
chmod 600 "$t" && mv "$t" "$f" || exit 5
if grep -qF -- "$blob" "$f"; then exit 6; fi
echo "yking-result:removed $b"`

// RemoveResult is what the server reported.
type RemoveResult struct {
	Kind   string // "removed", "absent", "last", "" (unknown)
	Backup string // server-side backup path when removed
}

func (r RemoveResult) String() string {
	switch r.Kind {
	case "removed":
		return "removed (server backup: " + r.Backup + ")"
	case "absent":
		return "was not there (nothing to do)"
	case "last":
		return "NOT removed: it is the only key in authorized_keys there — add another key first"
	}
	return "unknown result"
}

// Done reports whether the key is gone from the host.
func (r RemoveResult) Done() bool { return r.Kind == "removed" || r.Kind == "absent" }

// ParseRemoveOutput finds the result marker.
func ParseRemoveOutput(out []byte) RemoveResult {
	for _, l := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "yking-result:"); ok {
			kind, backup, _ := strings.Cut(rest, " ")
			return RemoveResult{Kind: kind, Backup: backup}
		}
	}
	return RemoveResult{}
}

// BlobOf returns the base64 key blob of a public key line.
func BlobOf(pubLine string) (string, error) {
	f := strings.Fields(pubLine)
	for i, p := range f {
		if strings.HasPrefix(p, "sk-") && i+1 < len(f) {
			return f[i+1], nil
		}
	}
	return "", errors.New("not a security-key public key")
}

// RemoveCommand builds the ssh command removing blob from target's
// authorized_keys, connecting as DeployCommand does.
func RemoveCommand(target, blob, identity string) (*exec.Cmd, error) {
	if err := ValidTarget(target); err != nil {
		return nil, err
	}
	if blob == "" || !b64Re.MatchString(blob) {
		return nil, errors.New("bad key blob")
	}
	var args []string
	if identity != "" {
		if !filepath.IsAbs(identity) {
			return nil, fmt.Errorf("identity file must be an absolute path: %q", identity)
		}
		if fi, err := os.Stat(identity); err != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("identity file %s not usable", identity)
		}
		args = append(args, "-i", identity, "-o", "IdentitiesOnly=yes")
	}
	args = append(args, "-o", "ClearAllForwardings=yes", "--", target, "sh -c '"+remoteRemove+"'")
	cmd := exec.Command(SSHBinary, args...)
	cmd.Stdin = bytes.NewReader([]byte(blob + "\n"))
	return cmd, nil
}
