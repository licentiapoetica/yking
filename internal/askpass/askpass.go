// Package askpass lets ssh and ssh-keygen ask their questions inside the
// yking TUI instead of on a bare terminal.
//
// yking runs them in their own session, without a terminal, and with
// SSH_ASKPASS=yking and SSH_ASKPASS_REQUIRE=force. Every prompt (PIN,
// password, host key, "confirm user presence") then makes ssh start
// `yking` as its askpass helper. The helper (Main) forwards the prompt over
// a private unix socket to the running TUI (Broker) and prints the TUI's
// answer for ssh. The policy (a FIDO2 PIN is asked at most once, never
// echoed, never sent if too short) lives in the TUI, which also owns and
// can kill the ssh process.
package askpass

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// EnvSock names the env var with the broker's socket. Its presence
// switches the yking binary into askpass-helper mode.
const EnvSock = "YKING_ASKPASS_SOCK"

// Kind is what ssh wants.
type Kind string

const (
	KindAsk     Kind = "ask"     // an answer (PIN, password, passphrase, yes/no)
	KindConfirm Kind = "confirm" // yes/no, answered by the exit code
	KindNotify  Kind = "notify"  // a notice ("touch your key"); ssh kills the helper when done
	// yking's own root apply talks to the TUI too:
	KindChoice Kind = "choice" // pick one of Options (answer = its Key), optionally before Deadline
	KindPhase  Kind = "phase"  // a new stage starts (Prompt is its title); answered at once
)

// Option is one answer of a KindChoice question. Key "enter" means Enter.
type Option struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type request struct {
	Kind     Kind      `json:"kind"`
	Prompt   string    `json:"prompt"`
	Options  []Option  `json:"options,omitempty"`
	Deadline time.Time `json:"deadline,omitempty"`
}

type reply struct {
	OK     bool   `json:"ok"`
	Answer string `json:"answer,omitempty"`
}

// Main is the helper entry point (argv[1] is ssh's prompt). Returns the
// exit code for ssh: 0 with the answer on stdout, 1 to refuse.
func Main(args []string) int {
	prompt := ""
	if len(args) > 0 {
		prompt = args[0]
	}
	kind := KindAsk
	switch os.Getenv("SSH_ASKPASS_PROMPT") {
	case "none":
		kind = KindNotify
	case "confirm":
		kind = KindConfirm
	}
	answer, ok, err := Ask(os.Getenv(EnvSock), kind, prompt)
	if err != nil || !ok {
		return 1
	}
	if kind == KindAsk {
		fmt.Println(answer)
	}
	return 0
}

// Ask sends one prompt to the broker and waits for its answer. A notice
// waits until the broker or ssh ends it and always succeeds.
func Ask(sock string, kind Kind, prompt string) (string, bool, error) {
	return send(sock, request{Kind: kind, Prompt: prompt})
}

// Choose asks the TUI to pick one of options. With a deadline, it gives up
// then (os.ErrDeadlineExceeded). Any error means there was no answer.
func Choose(sock, prompt string, options []Option, deadline time.Time) (string, error) {
	a, ok, err := send(sock, request{Kind: KindChoice, Prompt: prompt, Options: options, Deadline: deadline})
	if err == nil && !ok {
		err = errors.New("refused")
	}
	return a, err
}

// Phase tells the TUI that a new stage starts.
func Phase(sock, title string) error {
	_, _, err := send(sock, request{Kind: KindPhase, Prompt: title})
	return err
}

func send(sock string, q request) (string, bool, error) {
	kind := q.Kind
	if sock == "" {
		return "", false, errors.New("no broker socket")
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		if kind == KindNotify {
			return "", true, nil // nowhere to show it: not a reason to stop ssh
		}
		return "", false, err
	}
	defer c.Close()
	if !q.Deadline.IsZero() {
		c.SetDeadline(q.Deadline)
	}
	if err := json.NewEncoder(c).Encode(q); err != nil {
		return "", kind == KindNotify, err
	}
	var r reply
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		if kind == KindNotify {
			return "", true, nil
		}
		return "", false, err
	}
	return r.Answer, r.OK, nil
}

// Request is one prompt waiting in the TUI. Answer or Refuse it exactly
// once (later calls are ignored). Gone is closed when the helper hung up:
// ssh ended a notice, or gave up on the question.
type Request struct {
	Kind     Kind
	Prompt   string
	Options  []Option  // KindChoice
	Deadline time.Time // KindChoice; zero = none
	Gone     <-chan struct{}

	conn net.Conn
	once sync.Once
}

// Answer sends text to ssh.
func (r *Request) Answer(text string) { r.send(reply{OK: true, Answer: text}) }

// Refuse makes the helper fail: ssh treats it as cancelled.
func (r *Request) Refuse() { r.send(reply{OK: false}) }

func (r *Request) send(rep reply) {
	r.once.Do(func() {
		json.NewEncoder(r.conn).Encode(rep)
		r.conn.Close()
	})
}

// Broker receives prompts from helpers started by one ssh run.
type Broker struct {
	dir  string
	sock string
	ln   *net.UnixListener
	reqs chan *Request
	done chan struct{}

	mu    sync.Mutex
	conns map[net.Conn]bool
}

// NewBroker listens on a socket in a fresh 0700 directory under
// $XDG_RUNTIME_DIR. Only processes of the same user may connect.
func NewBroker() (*Broker, error) {
	dir, err := os.MkdirTemp(os.Getenv("XDG_RUNTIME_DIR"), "yking-askpass-")
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	b := &Broker{dir: dir, sock: sock, ln: ln, reqs: make(chan *Request, 8), done: make(chan struct{}), conns: map[net.Conn]bool{}}
	go b.accept()
	return b, nil
}

// Env makes ssh/ssh-keygen (and `sudo -A`) use self (the yking binary) as
// askpass for every prompt and notice.
func (b *Broker) Env(self string) []string {
	return []string{"SSH_ASKPASS=" + self, "SSH_ASKPASS_REQUIRE=force", "SUDO_ASKPASS=" + self, EnvSock + "=" + b.sock}
}

// Sock is the socket path (passed to yking's root apply as --tui).
func (b *Broker) Sock() string { return b.sock }

// Requests delivers prompts in arrival order.
func (b *Broker) Requests() <-chan *Request { return b.reqs }

// Done is closed by Close.
func (b *Broker) Done() <-chan struct{} { return b.done }

// Close stops listening, hangs up on every helper and removes the socket.
func (b *Broker) Close() {
	select {
	case <-b.done:
		return
	default:
	}
	close(b.done)
	b.ln.Close()
	b.mu.Lock()
	for c := range b.conns {
		c.Close()
	}
	b.mu.Unlock()
	os.RemoveAll(b.dir)
}

func (b *Broker) accept() {
	for {
		c, err := b.ln.AcceptUnix()
		if err != nil {
			return
		}
		go b.serve(c)
	}
}

func (b *Broker) serve(c *net.UnixConn) {
	if !sameUser(c) {
		c.Close()
		return
	}
	b.mu.Lock()
	select {
	case <-b.done:
		b.mu.Unlock()
		c.Close()
		return
	default:
	}
	b.conns[c] = true
	b.mu.Unlock()

	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	dec := json.NewDecoder(c)
	var q request
	if err := dec.Decode(&q); err != nil || !validKind(q.Kind) {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	gone := make(chan struct{})
	r := &Request{Kind: q.Kind, Prompt: strings.TrimSpace(q.Prompt), Options: q.Options, Deadline: q.Deadline, Gone: gone, conn: c}
	go func() { // the helper never sends more; any read result means it hung up
		var x [1]byte
		c.Read(x[:])
		close(gone)
		b.mu.Lock()
		delete(b.conns, c)
		b.mu.Unlock()
	}()
	select {
	case b.reqs <- r:
	case <-b.done:
		c.Close()
	}
}

func validKind(k Kind) bool {
	switch k {
	case KindAsk, KindConfirm, KindNotify, KindChoice, KindPhase:
		return true
	}
	return false
}

// sameUser checks the peer's uid (SO_PEERCRED): this user, or root (yking's
// own elevated apply; root could read the socket directory anyway).
func sameUser(c *net.UnixConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		ok = err == nil && (int(cred.Uid) == os.Getuid() || cred.Uid == 0)
	})
	return ok
}
