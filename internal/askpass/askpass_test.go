package askpass

import (
	"bytes"
	"strings"
	"testing"
)

type harness struct {
	s      *Session
	tty    bytes.Buffer
	out    bytes.Buffer
	killed int
	pin    string
}

func newHarness(t *testing.T, info Info) *harness {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	s, err := Prepare("/usr/bin/yking", info)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return &harness{s: s, pin: "123456"}
}

func (h *harness) run(prompt, kind string) int {
	var state string
	for _, e := range h.s.Env {
		if v, ok := strings.CutPrefix(e, EnvState+"="); ok {
			state = v
		}
	}
	h.out.Reset()
	return Run(prompt, Deps{
		Tty:        &h.tty,
		ReadSecret: func() (string, error) { return h.pin, nil },
		KillParent: func() error { h.killed++; return nil },
		PromptKind: kind,
		StatePath:  state,
		Stdout:     &h.out,
	})
}

func TestOneShot(t *testing.T) {
	h := newHarness(t, Info{Label: "home-backup", Serial: "22222222", Retries: 8})
	if code := h.run("Enter PIN for authenticator: ", ""); code != 0 || h.out.String() != "123456\n" || h.killed != 0 {
		t.Fatalf("first: code=%d out=%q killed=%d", code, h.out.String(), h.killed)
	}
	if !strings.Contains(h.tty.String(), "8 tries left") {
		t.Errorf("prompt did not show retries: %q", h.tty.String())
	}
	if !h.s.PINWasRequested() {
		t.Error("PINWasRequested = false")
	}
	// ssh-keygen asks again => PIN was wrong => kill, send nothing.
	if code := h.run("Enter PIN for authenticator: ", ""); code == 0 || h.out.Len() != 0 || h.killed != 1 {
		t.Fatalf("second: code=%d out=%q killed=%d", code, h.out.String(), h.killed)
	}
}

func TestShortPINNotSent(t *testing.T) {
	h := newHarness(t, Info{Retries: 8, MinPINLength: 6})
	h.pin = "1234"
	if code := h.run("Enter PIN for authenticator: ", ""); code == 0 || h.out.Len() != 0 || h.killed != 1 {
		t.Fatalf("code=%d out=%q killed=%d", code, h.out.String(), h.killed)
	}
	h2 := newHarness(t, Info{Retries: 8})
	h2.pin = ""
	if code := h2.run("Enter PIN for authenticator: ", ""); code == 0 || h2.out.Len() != 0 {
		t.Fatal("empty PIN was sent")
	}
}

func TestUnexpectedPrompts(t *testing.T) {
	h := newHarness(t, Info{Retries: 8})
	if code := h.run("Enter passphrase: ", ""); code == 0 || h.killed != 1 || h.out.Len() != 0 {
		t.Error("passphrase prompt should abort")
	}
	if code := h.run("Allow use of key?", "confirm"); code == 0 || h.killed != 2 {
		t.Error("confirm prompt should abort")
	}
	if code := h.run("Confirm user presence", "none"); code != 0 || h.killed != 2 {
		t.Error("notification should pass through without killing")
	}
	if h.s.PINWasRequested() {
		t.Error("no PIN was requested")
	}
}
