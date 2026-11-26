// Package askpass makes yking act as SSH_ASKPASS for ssh-keygen and ssh so
// that a FIDO2 PIN is asked for at most ONCE per operation.
//
// ssh-keygen retries a wrong PIN up to three times. Eight wrong PINs block
// FIDO2 and the only recovery is a reset, which would wipe every site
// registration on the key. So: the first PIN request is answered from a
// hidden prompt on the terminal; any second request means the PIN was
// wrong, and yking kills ssh-keygen before it can try again. An empty or
// too-short PIN is never sent.
package askpass

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// EnvState names the env var pointing at the one-shot state file. Its
// presence switches the yking binary into askpass mode.
const EnvState = "YKING_ASKPASS_STATE"

// Info is shown in the PIN prompt.
type Info struct {
	Label        string `json:"label"`
	Serial       string `json:"serial"`
	Retries      int    `json:"retries"`        // -1 unknown
	MinPINLength int    `json:"min_pin_length"` // 0 unknown
	Used         bool   `json:"used"`
}

// Session is one guarded ssh-keygen run.
type Session struct {
	dir string
	// Env must be added to ssh-keygen's environment.
	Env []string
}

// Prepare creates the state for one guarded run. self is the yking binary.
func Prepare(self string, info Info) (*Session, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	dir, err := os.MkdirTemp(base, "yking-askpass-")
	if err != nil {
		return nil, err
	}
	state := filepath.Join(dir, "state.json")
	if err := writeState(state, info); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return &Session{dir: dir, Env: []string{
		"SSH_ASKPASS=" + self,
		"SSH_ASKPASS_REQUIRE=force",
		EnvState + "=" + state,
	}}, nil
}

// PINWasRequested reports whether ssh-keygen asked for the PIN.
func (s *Session) PINWasRequested() bool {
	i, err := readState(filepath.Join(s.dir, "state.json"))
	return err == nil && i.Used
}

// Close removes the state.
func (s *Session) Close() { os.RemoveAll(s.dir) }

// Deps are swappable for tests.
type Deps struct {
	Tty        io.ReadWriter // terminal for prompt and messages
	ReadSecret func() (string, error)
	KillParent func() error
	PromptKind string // $SSH_ASKPASS_PROMPT
	StatePath  string
	Stdout     io.Writer
}

// Main is the askpass entry point (argv[1] is ssh's prompt). Returns the
// process exit code.
func Main(args []string) int {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		killParent()
		return 1
	}
	defer tty.Close()
	d := Deps{
		Tty:        tty,
		ReadSecret: func() (string, error) { b, err := term.ReadPassword(int(tty.Fd())); return string(b), err },
		KillParent: killParent,
		PromptKind: os.Getenv("SSH_ASKPASS_PROMPT"),
		StatePath:  os.Getenv(EnvState),
		Stdout:     os.Stdout,
	}
	prompt := ""
	if len(args) > 0 {
		prompt = args[0]
	}
	return Run(prompt, d)
}

// Run implements the one-shot policy.
func Run(prompt string, d Deps) int {
	abort := func(msg string) int {
		fmt.Fprintf(d.Tty, "\r\nyking: %s\r\n", msg)
		d.KillParent()
		return 1
	}

	if d.PromptKind == "none" { // notification only ("touch your key")
		fmt.Fprintf(d.Tty, "\r\n%s\r\n", strings.TrimSpace(prompt))
		return 0
	}
	if d.PromptKind == "confirm" {
		return abort("unexpected confirmation request; stopping")
	}
	if !strings.Contains(strings.ToLower(prompt), "pin") {
		return abort(fmt.Sprintf("unexpected prompt %q; stopping", prompt))
	}

	info, err := readState(d.StatePath)
	if err != nil {
		return abort("askpass state missing; stopping (" + err.Error() + ")")
	}
	if info.Used {
		return abort("the PIN was not accepted. Stopped so no further attempts are used.\r\n" +
			"       Check `yking detect` for the remaining tries before trying again.")
	}
	// Mark used BEFORE prompting: even if anything below fails, a second
	// request can never be answered.
	info.Used = true
	if err := writeState(d.StatePath, info); err != nil {
		return abort("cannot record PIN request; stopping")
	}

	tries := "unknown"
	if info.Retries >= 0 {
		tries = fmt.Sprint(info.Retries)
	}
	fmt.Fprintf(d.Tty, "\r\nFIDO2 PIN for key %q (%s) — %s tries left.\r\n", info.Label, info.Serial, tries)
	fmt.Fprintf(d.Tty, "Asked ONCE; a wrong PIN stops here without retrying.\r\nPIN: ")
	pin, err := d.ReadSecret()
	fmt.Fprint(d.Tty, "\r\n")
	if err != nil {
		return abort("could not read PIN; stopping")
	}
	minLen := max(info.MinPINLength, 4)
	if len([]rune(pin)) < minLen {
		return abort(fmt.Sprintf("PIN shorter than %d characters; not sent (no attempt used)", minLen))
	}
	fmt.Fprintln(d.Stdout, pin)
	return 0
}

func killParent() error {
	ppid := os.Getppid()
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ppid))
	if err != nil {
		return err
	}
	// Only ever kill the OpenSSH tool that asked us; never anything else.
	switch strings.TrimSpace(string(comm)) {
	case "ssh-keygen", "ssh":
	default:
		return errors.New("parent is not ssh-keygen/ssh; not killing")
	}
	return syscall.Kill(ppid, syscall.SIGKILL)
}

func readState(path string) (Info, error) {
	var i Info
	if path == "" {
		return i, errors.New("no state path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return i, err
	}
	return i, json.Unmarshal(b, &i)
}

func writeState(path string, i Info) error {
	b, err := json.Marshal(i)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
