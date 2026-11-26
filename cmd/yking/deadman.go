package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/licentiapoetica/yking/internal/plan"
)

// deadmanTimeout is how long a PAM change stays without confirmation.
const deadmanTimeout = 3 * time.Minute

// Key events understood by the dead-man screen.
const (
	keyEnter = '\r'
	keyCtrlC = 0x03
	keyEOF   = 0
)

// keys reads single key presses. On a terminal it uses raw mode (no echo,
// no Enter needed); otherwise (tests, pipes) one line = one key, empty
// line = Enter. Typed characters are never echoed.
type keys struct {
	r     *bufio.Reader
	fd    int
	tty   bool
	mu    sync.Mutex
	saved *term.State
}

func newKeys(in io.Reader) *keys {
	k := &keys{r: bufio.NewReader(in)}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		k.fd, k.tty = int(f.Fd()), true
	}
	return k
}

func (k *keys) raw() {
	if !k.tty {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.saved == nil {
		k.saved, _ = term.MakeRaw(k.fd)
	}
}

// restore returns the terminal to normal; safe to call any number of times.
func (k *keys) restore() {
	if !k.tty {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.saved != nil {
		term.Restore(k.fd, k.saved)
		k.saved = nil
	}
}

// flush drops pending input, both buffered here and in the terminal.
func (k *keys) flush() {
	if !k.tty {
		return
	}
	k.r.Discard(k.r.Buffered())
	unix.IoctlSetInt(k.fd, unix.TCFLSH, unix.TCIFLUSH)
}

// next blocks for one key. Terminal escape sequences (arrow keys, and
// answers to colour/cursor queries such as "ESC]11;rgb:…") are skipped
// whole, so their letters never count as key presses.
func (k *keys) next() byte {
	if k.tty {
		for {
			b, err := k.r.ReadByte()
			if err != nil {
				return keyEOF
			}
			switch b {
			case 0x1b:
				if err := k.skipEscape(); err != nil {
					return keyEOF
				}
				continue
			case '\n':
				return keyEnter
			}
			return b
		}
	}
	l, err := k.r.ReadString('\n')
	if err != nil && l == "" {
		return keyEOF
	}
	l = strings.TrimSpace(l)
	if l == "" {
		return keyEnter
	}
	return strings.ToLower(l)[0]
}

// skipEscape consumes the rest of an escape sequence (ESC already read):
// CSI "ESC [ … final", OSC "ESC ] … BEL|ESC \\", or a two-byte sequence.
func (k *keys) skipEscape() error {
	b, err := k.r.ReadByte()
	if err != nil {
		return err
	}
	switch b {
	case '[':
		for {
			c, err := k.r.ReadByte()
			if err != nil {
				return err
			}
			if c >= 0x40 && c <= 0x7e {
				return nil
			}
		}
	case ']', 'P', '_', '^':
		for {
			c, err := k.r.ReadByte()
			if err != nil {
				return err
			}
			if c == 0x07 {
				return nil
			}
			if c == 0x1b {
				if _, err := k.r.ReadByte(); err != nil { // the "\\" of ESC \\
					return err
				}
				return nil
			}
		}
	}
	return nil
}

// nl is the line ending: raw mode needs an explicit carriage return.
func (k *keys) nl() string {
	if k.tty {
		return "\r\n"
	}
	return "\n"
}

// deadman runs right after a PAM plan was applied, as root. The change
// survives only if the user presses k in time. r, Ctrl+C, the terminal
// closing (SIGHUP), end of input or the timeout restore the previous
// files. Being root already, rollback never depends on the (possibly
// broken) new PAM configuration.
//
// Terminal rules (a PIN was once leaked by breaking them):
//   - Nothing reads the terminal while a child process (the sudo test)
//     owns it; the terminal is back in normal mode before the child runs.
//   - Typed characters are never echoed or put into messages.
func deadman(a *plan.Applier, m *plan.Manifest, in io.Reader, out io.Writer) error {
	k := newKeys(in)
	defer k.restore()
	// Drop anything typed or answered by the terminal before this point.
	k.flush()
	say := func(format string, args ...any) {
		fmt.Fprintf(out, strings.ReplaceAll(format, "\n", k.nl()), args...)
	}

	var once sync.Once
	var rbErr error
	rollback := func(why string) error {
		once.Do(func() {
			k.restore()
			fmt.Fprintf(out, "\n\nyking: %s — restoring the previous PAM files…\n", why)
			if _, err := a.Rollback(m.ID, false); err != nil {
				if _, err2 := a.Rollback(m.ID, true); err2 != nil {
					rbErr = fmt.Errorf("ROLLBACK FAILED (%v); originals are in %s", err2, filepath.Join(a.BackupRoot, m.ID))
					return
				}
			}
			fmt.Fprintln(out, "yking: done, everything is as before.")
			rbErr = fmt.Errorf("PAM change rolled back: %s", why)
		})
		return rbErr
	}

	// Signals roll back at any moment.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(sig)
	stopSig := make(chan struct{})
	defer close(stopSig)
	go func() {
		select {
		case s := <-sig:
			fmt.Fprintln(out, "yking:", rollback("received "+s.String()))
			exit(1)
		case <-stopSig:
		}
	}()

	var services []string
	for _, e := range m.Entries {
		services = append(services, filepath.Base(e.Path))
	}
	rule := strings.Repeat("─", 58)
	say("\n%s\n yking: PAM change applied for %s\n%s\n", rule, strings.Join(services, ", "), rule)

	// Phase 1: optional sudo test. One key, then the terminal goes back to
	// normal before sudo runs, and nothing else reads it meanwhile.
	if slices.Contains(services, "sudo") {
		say(" Test sudo with the NEW config now?   [Enter] test    [n] skip    [r] roll back\n ")
		k.raw()
		var key byte
		for key == 0 || !strings.ContainsRune("yn\rr\x03", rune(key)) {
			if key = k.next(); key == keyEOF {
				break
			}
		}
		k.restore()
		// Typed-ahead input (e.g. a PIN typed too early) must not reach
		// sudo's PIN prompt.
		k.flush()
		say("\n")
		switch key {
		case keyEOF:
			return rollback("input closed")
		case 'r', keyCtrlC:
			return rollback("you chose to roll back")
		case 'n':
			say(" sudo test skipped.\n")
		default: // Enter or y
			say(" Running `sudo -v` as you. Authenticate the way the NEW config expects.\n")
			if err := testSudo(); err != nil {
				say(" sudo test FAILED: %v\n", err)
				return rollback("sudo test failed")
			}
			say(" sudo test OK.\n")
		}
	}

	// Phase 2: no child processes any more.
	say(`
  1. Lock the screen (Meta+L) and unlock it, if the lock screen changed.
  2. Optional, in another terminal:  sudo -k && sudo true
  3. Come back here and press  k  to keep the change.

  If you press r or Ctrl+C, or don't press k in time,
  your previous PAM files are restored automatically.

`)
	k.raw()
	pressed := make(chan byte)
	go func() {
		for {
			key := k.next()
			pressed <- key
			if key == keyEOF {
				return
			}
		}
	}()
	deadline := time.Now().Add(deadmanTimeout)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	status := func() {
		left := time.Until(deadline).Round(time.Second)
		fmt.Fprintf(out, "\r  ▶ auto-rollback in %d:%02d    [k] keep    [r] roll back now   ", int(left.Minutes()), int(left.Seconds())%60)
	}
	status()
	for {
		select {
		case key := <-pressed:
			switch key {
			case 'k', 'K':
				k.restore()
				fmt.Fprint(out, "\n\nyking: keeping the change.\n")
				return nil
			case 'r', 'R', keyCtrlC:
				return rollback("you chose to roll back")
			case keyEOF:
				return rollback("input closed")
			}
			// any other key: ignored, never shown
		case <-tick.C:
			if time.Now().After(deadline) {
				return rollback("no confirmation within " + deadmanTimeout.String())
			}
			status()
		}
	}
}

// Swappable for tests.
var (
	exit     = os.Exit
	testSudo = testSudoAsUser
)

// testSudoAsUser drops to the user who ran sudo/pkexec and runs a fresh
// `sudo -v` (cached credentials cleared first), exercising the new stack.
func testSudoAsUser() error {
	uidStr := os.Getenv("SUDO_UID")
	if uidStr == "" {
		uidStr = os.Getenv("PKEXEC_UID")
	}
	if uidStr == "" || uidStr == "0" {
		return fmt.Errorf("cannot tell which user to test as")
	}
	u, err := user.LookupId(uidStr)
	if err != nil {
		return err
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	var groups []uint32
	if gs, err := u.GroupIds(); err == nil {
		for _, g := range gs {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				groups = append(groups, uint32(n))
			}
		}
	}
	run := func(args ...string) error {
		cmd := exec.Command("sudo", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}}
		cmd.Env = []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username,
			"PATH=/usr/local/bin:/usr/bin:/bin", "TERM=" + os.Getenv("TERM"), "LANG=" + os.Getenv("LANG")}
		cmd.Dir = u.HomeDir
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}
	if err := run("-k"); err != nil {
		return fmt.Errorf("sudo -k: %w", err)
	}
	fmt.Printf("yking: running `sudo -v` as %s — authenticate the way the new config expects.\n", u.Username)
	return run("-v")
}
