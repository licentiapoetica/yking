package pgp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScdaemonPlan(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GNUPGHOME", "")
	os.MkdirAll(HomeDir(home), 0o700)
	os.WriteFile(ScdaemonPath(home), []byte("pcsc-shared"), 0o600)
	p, err := ScdaemonPlan(home, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := p.Steps[0].Content
	if got != "pcsc-shared\n# yking: share the YubiKey with pcscd (ykman)\ndisable-ccid\n" || ValidateScdaemon(ScdaemonPath(home), []byte(got)) != nil {
		t.Fatalf("%q", got)
	}
	os.WriteFile(ScdaemonPath(home), []byte(got), 0o600)
	if _, err := ScdaemonPlan(home, time.Now()); err == nil {
		t.Fatal("second plan should be empty")
	}
	if ValidateScdaemon(filepath.Join(home, ".gnupg", "gpg.conf"), []byte(got)) == nil {
		t.Fatal("other files must be refused")
	}
}

func TestGitSigningPlan(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[user]\n\tname = Alice Example\n"), 0o644)
	p, err := GitSigningPlan(home, sigSub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := p.Steps[0].Content
	for _, want := range []string{"name = Alice Example", "signingkey = " + sigSub + "!", "gpgsign = true", "format = openpgp"} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q in\n%s", want, c)
		}
	}
	if ValidateGitConfig(p.Steps[0].Path, []byte(c)) != nil {
		t.Fatal("validator refused")
	}
}
