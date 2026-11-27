package pgp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// GPG runs gpg against one home directory ("" = the user's default).
type GPG struct {
	Home string
	// Stderr receives gpg's messages (nil: kept only for errors).
	Stderr io.Writer
}

func (g GPG) base() []string {
	args := []string{"--batch", "--no-tty", "--with-colons"}
	if g.Home != "" {
		args = append([]string{"--homedir", g.Home}, args...)
	}
	return args
}

func (g GPG) env() []string {
	env := append(os.Environ(), "LC_ALL=C", "LANG=C")
	if g.Home != "" {
		env = append(env, "GNUPGHOME="+g.Home)
	}
	return env
}

// run executes gpg with stdin and returns stdout.
func (g GPG) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "gpg", append(g.base(), args...)...)
	cmd.Env = g.env()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if g.Stderr != nil {
		cmd.Stderr = io.MultiWriter(&errb, g.Stderr)
	}
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("gpg %s: %w: %s", args[0], err, lastLines(errb.String(), 2))
	}
	return out.Bytes(), nil
}

func lastLines(s string, n int) string {
	var l []string
	for _, x := range strings.Split(s, "\n") {
		if x = strings.TrimSpace(x); x != "" {
			l = append(l, x)
		}
	}
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " / ")
}

// withPass runs gpg in loopback mode with the passphrase on stdin.
func (g GPG) withPass(ctx context.Context, pass string, args ...string) ([]byte, error) {
	a := append([]string{"--pinentry-mode", "loopback", "--passphrase-fd", "0"}, args...)
	return g.run(ctx, []byte(pass+"\n"), a...)
}

// Secret lists identities with secret material.
func (g GPG) Secret(ctx context.Context) ([]Identity, error) {
	out, err := g.run(ctx, nil, "--fixed-list-mode", "--with-keygrip", "--list-secret-keys")
	if err != nil {
		return nil, err
	}
	return ParseSecret(out), nil
}

// Find returns the identity with primary fingerprint fpr.
func (g GPG) Find(ctx context.Context, fpr string) (Identity, error) {
	ids, err := g.Secret(ctx)
	if err != nil {
		return Identity{}, err
	}
	for _, id := range ids {
		if id.Fingerprint == fpr {
			return id, nil
		}
	}
	return Identity{}, fmt.Errorf("no secret key %s", fpr)
}

// Protected reports whether the agent's key for keygrip has a passphrase.
func (g GPG) Protected(ctx context.Context, keygrip string) (bool, error) {
	out, err := g.agent(ctx, "KEYINFO "+keygrip)
	if err != nil {
		return false, err
	}
	// S KEYINFO <grip> <type> <serial> <idstr> <cached> <protection> …
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) >= 8 && f[0] == "S" && f[1] == "KEYINFO" {
			return f[7] != "C", nil
		}
	}
	return false, fmt.Errorf("agent does not know key %s", keygrip)
}

// agent sends commands to this home's gpg-agent (on stdin, never argv).
func (g GPG) agent(ctx context.Context, cmds ...string) ([]byte, error) {
	var args []string
	if g.Home != "" {
		args = append(args, "--homedir", g.Home)
	}
	cmd := exec.CommandContext(ctx, "gpg-connect-agent", args...)
	cmd.Env = g.env()
	cmd.Stdin = strings.NewReader(strings.Join(append(cmds, "/bye"), "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("gpg-connect-agent: %w", err)
	}
	if bytes.Contains(out, []byte("\nERR ")) || bytes.HasPrefix(out, []byte("ERR ")) {
		return out, fmt.Errorf("gpg-agent: %s", lastLines(string(out), 1))
	}
	return out, nil
}

// Kill stops this home's gpg daemons (agent, scdaemon).
func (g GPG) Kill(component string) {
	args := []string{"--kill", component}
	if g.Home != "" {
		args = append([]string{"--homedir", g.Home}, args...)
	}
	cmd := exec.Command("gpgconf", args...)
	cmd.Env = g.env()
	cmd.Run()
}

// ExportSecretSubkeys exports only the given subkeys' secrets (the primary
// as a stub), still protected by their passphrase.
func (g GPG) ExportSecretSubkeys(ctx context.Context, pass string, subs []string) ([]byte, error) {
	args := []string{"--armor", "--export-secret-subkeys"}
	for _, s := range subs {
		args = append(args, s+"!")
	}
	out, err := g.withPass(ctx, pass, args...)
	if err == nil && !bytes.Contains(out, []byte("PRIVATE KEY BLOCK")) {
		err = errors.New("gpg exported nothing")
	}
	return out, err
}

// ExportPublic exports the public key.
func (g GPG) ExportPublic(ctx context.Context, fpr string) ([]byte, error) {
	out, err := g.run(ctx, nil, "--export", fpr)
	if err == nil && len(out) == 0 {
		err = fmt.Errorf("no public key %s", fpr)
	}
	return out, err
}

// Import imports keys (secret ones need their passphrase).
func (g GPG) Import(ctx context.Context, pass string, data []byte) error {
	f, err := os.CreateTemp(g.Home, "import-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	f.Close()
	_, err = g.withPass(ctx, pass, "--import", f.Name())
	return err
}

// Preset caches the passphrase for keygrip in the agent (needs
// allow-preset-passphrase), so the card dialog only asks for the PIN.
func (g GPG) Preset(ctx context.Context, keygrip, pass string) error {
	_, err := g.agent(ctx, "PRESET_PASSPHRASE "+keygrip+" -1 "+strings.ToUpper(hex.EncodeToString([]byte(pass))))
	return err
}

// Generate creates a new identity: certify-only ed25519 primary, cv25519
// encryption and ed25519 signing subkeys.
func (g GPG) Generate(ctx context.Context, pass, uid, expire string) (string, error) {
	if _, err := g.withPass(ctx, pass, "--quick-generate-key", uid, "ed25519", "cert", expire); err != nil {
		return "", err
	}
	ids, err := g.Secret(ctx)
	if err != nil {
		return "", err
	}
	var fpr string
	var newest time.Time
	for _, id := range ids {
		for _, u := range id.UIDs {
			if u == uid && !id.Created.Before(newest) {
				fpr, newest = id.Fingerprint, id.Created
			}
		}
	}
	if fpr == "" {
		return "", errors.New("new key not found")
	}
	for _, sub := range [][2]string{{"cv25519", "encr"}, {"ed25519", "sign"}} {
		if _, err := g.withPass(ctx, pass, "--quick-add-key", fpr, sub[0], sub[1], expire); err != nil {
			return fpr, err
		}
	}
	return fpr, nil
}

// AddSubkey adds a subkey (algo ed25519/cv25519, usage sign/encr/auth).
func (g GPG) AddSubkey(ctx context.Context, pass, fpr, algo, usage, expire string) error {
	_, err := g.withPass(ctx, pass, "--quick-add-key", fpr, algo, usage, expire)
	return err
}

// DeleteSecretSubkeys removes the secret parts of the given subkeys only.
func (g GPG) DeleteSecretSubkeys(ctx context.Context, subs []string) error {
	args := []string{"--yes", "--delete-secret-keys"}
	for _, s := range subs {
		args = append(args, s+"!")
	}
	_, err := g.run(ctx, nil, args...)
	return err
}

// CardStatus reads the plugged card (also creates key stubs for it).
func (g GPG) CardStatus(ctx context.Context) ([]byte, error) {
	return g.run(ctx, nil, "--card-status")
}

// CardFingerprints parses the fpr line of `gpg --card-status --with-colons`.
func CardFingerprints(status []byte) map[string]bool {
	set := map[string]bool{}
	for _, l := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(l, "fpr:") {
			continue
		}
		for _, f := range strings.Split(l, ":")[1:] {
			if len(f) == 40 {
				set[strings.ToUpper(f)] = true
			}
		}
	}
	return set
}

// dialog runs gpg with a status/command dialog.
func (g GPG) dialog(ctx context.Context, onStatus func(string, []string), answer handler, args ...string) error {
	stR, stW, err := os.Pipe()
	if err != nil {
		return err
	}
	cmR, cmW, err := os.Pipe()
	if err != nil {
		stR.Close()
		stW.Close()
		return err
	}
	a := append([]string{"--pinentry-mode", "loopback", "--status-fd", "3", "--command-fd", "4"}, args...)
	cmd := exec.CommandContext(ctx, "gpg", append(g.base(), a...)...)
	cmd.Env = g.env()
	cmd.ExtraFiles = []*os.File{stW, cmR}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		stR.Close()
		stW.Close()
		cmR.Close()
		cmW.Close()
		return err
	}
	stW.Close()
	cmR.Close()
	derr := drive(stR, cmW, onStatus, answer)
	stR.Close()
	cmW.Close()
	werr := cmd.Wait()
	if derr != nil {
		return derr
	}
	if werr != nil {
		return fmt.Errorf("gpg: %w: %s", werr, lastLines(errb.String(), 2))
	}
	return nil
}

// RuntimeHome creates a throwaway GnuPG home in $XDG_RUNTIME_DIR, which
// must be a tmpfs: secret keys never touch a disk there.
func RuntimeHome() (GPG, func(), error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return GPG{}, nil, errors.New("XDG_RUNTIME_DIR is not set")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return GPG{}, nil, err
	}
	if st.Type != 0x01021994 { // TMPFS_MAGIC
		return GPG{}, nil, fmt.Errorf("%s is not a tmpfs; refusing to put secret keys there", dir)
	}
	CleanStale(dir)
	home, err := os.MkdirTemp(dir, staleTag)
	if err != nil {
		return GPG{}, nil, err
	}
	conf := map[string]string{
		"gpg-agent.conf": "allow-preset-passphrase\nallow-loopback-pinentry\n",
		"scdaemon.conf":  "disable-ccid\npcsc-shared\n",
	}
	for name, c := range conf {
		if err := os.WriteFile(filepath.Join(home, name), []byte(c), 0o600); err != nil {
			os.RemoveAll(home)
			return GPG{}, nil, err
		}
	}
	g := GPG{Home: home}
	return g, func() { g.Kill("all"); os.RemoveAll(home) }, nil
}

const staleTag = "yking-gpg-*"

// CleanStale removes throwaway homes a killed run left behind.
func CleanStale(dir string) {
	old, _ := filepath.Glob(filepath.Join(dir, staleTag))
	for _, h := range old {
		GPG{Home: h}.Kill("all")
		os.RemoveAll(h)
	}
}
