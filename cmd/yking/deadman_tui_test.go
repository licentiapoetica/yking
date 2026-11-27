package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/askpass"
)

// tuiSide plays the TUI: it answers phases at once and choices from answers.
func tuiSide(t *testing.T, b *askpass.Broker, answers ...string) <-chan []string {
	seen := make(chan []string, 1)
	go func() {
		var got []string
		for {
			select {
			case r := <-b.Requests():
				got = append(got, string(r.Kind)+":"+strings.SplitN(r.Prompt, "\n", 2)[0])
				switch r.Kind {
				case askpass.KindPhase:
					r.Answer("")
				case askpass.KindChoice:
					if len(answers) == 0 {
						continue // no answer: wait for the deadline
					}
					r.Answer(answers[0])
					answers = answers[1:]
				}
			case <-b.Done():
				seen <- got
				return
			}
		}
	}()
	return seen
}

func broker(t *testing.T) *askpass.Broker {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	b, err := askpass.NewBroker()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func stubSudoTUI(t *testing.T, err error) *int {
	calls := 0
	old := testSudoTUI
	testSudoTUI = func(string) error { calls++; return err }
	t.Cleanup(func() { testSudoTUI = old })
	return &calls
}

func TestDeadmanTUIKeep(t *testing.T) {
	calls := stubSudoTUI(t, nil)
	a, m, path, orig := appliedPAM(t, "sudo")
	b := broker(t)
	seen := tuiSide(t, b, "enter", "k")
	err := deadmanTUI(a, m, b.Sock())
	b.Close()
	if err != nil {
		t.Fatalf("keep: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) == orig {
		t.Error("rolled back despite keep")
	}
	if *calls != 1 {
		t.Errorf("sudo test ran %d times", *calls)
	}
	got := strings.Join(<-seen, " | ")
	for _, want := range []string{"choice:PAM change applied for sudo", "phase:sudo test with the NEW config", "phase:keep the PAM change?", "choice:1. Lock the screen"} {
		if !strings.Contains(got, want) {
			t.Errorf("TUI saw %q, missing %q", got, want)
		}
	}
}

func TestDeadmanTUIRollsBack(t *testing.T) {
	old := deadmanTUITimeout
	deadmanTUITimeout = 300 * time.Millisecond
	t.Cleanup(func() { deadmanTUITimeout = old })
	for name, c := range map[string]struct {
		svc     string
		sudoErr error
		answers []string
		closeAt time.Duration // TUI goes away
		want    string
	}{
		"r at sudo question": {svc: "sudo", answers: []string{"r"}, want: "you chose"},
		"sudo test fails":    {svc: "sudo", sudoErr: errors.New("exit status 1"), answers: []string{"enter"}, want: "sudo test failed"},
		"skip then r":        {svc: "sudo", answers: []string{"n", "r"}, want: "you chose"},
		"no answer in time":  {svc: "kde", want: "no confirmation"},
		"tui gone":           {svc: "kde", closeAt: 50 * time.Millisecond, want: "rolled back"},
		"strange answer":     {svc: "kde", answers: []string{"x"}, want: "unexpected"},
	} {
		stubSudoTUI(t, c.sudoErr)
		a, m, path, orig := appliedPAM(t, c.svc)
		b := broker(t)
		tuiSide(t, b, c.answers...)
		if c.closeAt > 0 {
			time.AfterFunc(c.closeAt, b.Close)
		}
		err := deadmanTUI(a, m, b.Sock())
		b.Close()
		if err == nil || !strings.Contains(err.Error(), "rolled back") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v", name, err)
		}
		if got, _ := os.ReadFile(path); string(got) != orig {
			t.Errorf("%s: file not restored", name)
		}
	}
}

// No TUI at all (socket missing): roll back, never keep.
func TestDeadmanTUINoSocket(t *testing.T) {
	a, m, path, orig := appliedPAM(t, "kde")
	if err := deadmanTUI(a, m, t.TempDir()+"/nothing"); err == nil {
		t.Error("kept without a TUI")
	}
	if got, _ := os.ReadFile(path); string(got) != orig {
		t.Error("file not restored")
	}
}
