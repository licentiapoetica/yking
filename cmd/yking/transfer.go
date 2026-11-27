package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/fsutil"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/transfer"
)

// cmdExport: yking export [-o FILE] [--no-ssh]
func cmdExport(krPath string, args []string) error {
	flags := flag.NewFlagSet("export", flag.ExitOnError)
	out := flags.String("o", "yking-export-"+time.Now().Format("2006-01-02")+".toml", "output file")
	noSSH := flags.Bool("no-ssh", false, "leave out the SSH key handle files")
	flags.Parse(args)

	kr, err := keyring.Load(krPath)
	if err != nil {
		return err
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	sts, _ := pam.Discover(pam.EtcDir, pam.VendorDir)
	var ev *events.Config
	if b, err := os.ReadFile(events.ConfigPath); err == nil {
		if ev, err = events.Parse(b); err != nil {
			return fmt.Errorf("%s: %w", events.ConfigPath, err)
		}
	}
	e, err := transfer.Build(transfer.Options{Keyring: kr, PAM: sts, Events: ev, User: u.Username, SSHFiles: !*noSSH, Now: time.Now()})
	if err != nil {
		return err
	}
	b, err := e.Encode()
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(*out)
	if inGitRepo(filepath.Dir(abs)) {
		return fmt.Errorf("%s is inside a git repository — an export must never end up in a repo; write it elsewhere (-o)", abs)
	}
	if _, err := os.Stat(abs); err == nil {
		return fmt.Errorf("%s exists; not overwriting", abs)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := fsutil.WriteAtomic(abs, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("Exported %d key(s), %d PAM service(s), %d SSH key file(s)%s to %s (mode 600).\n",
		len(e.Keys), len(e.PAM), len(e.SSHFiles), map[bool]string{true: ", plug/unplug actions", false: ""}[e.Events != nil], abs)
	fmt.Println("It holds SSH key handles: keep it private. On the other machine: yking import " + filepath.Base(abs))
	return nil
}

func inGitRepo(dir string) bool {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// cmdImport: yking import FILE — stages the import; the TUI (i) walks
// through the steps.
func cmdImport(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: yking import FILE")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	e, err := transfer.Parse(b)
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if err := transfer.SavePending(home, e); err != nil {
		return err
	}
	var labels []string
	for _, k := range e.Keys {
		labels = append(labels, k.Label)
	}
	fmt.Printf("Import staged: keys %s, %d PAM service(s), %d SSH key file(s).\n", strings.Join(labels, ", "), len(e.PAM), len(e.SSHFiles))
	fmt.Println("Next: start yking and press i — it walks you through each step.")
	return nil
}
