package askpass

import (
	"strings"
	"testing"
	"time"
)

func newBroker(t *testing.T) *Broker {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	b, err := NewBroker()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func sock(b *Broker) string {
	for _, e := range b.Env("/usr/bin/yking") {
		if v, ok := strings.CutPrefix(e, EnvSock+"="); ok {
			return v
		}
	}
	return ""
}

type result struct {
	answer string
	ok     bool
	err    error
}

func ask(b *Broker, kind Kind, prompt string) <-chan result {
	ch := make(chan result, 1)
	go func() {
		a, ok, err := Ask(sock(b), kind, prompt)
		ch <- result{a, ok, err}
	}()
	return ch
}

func next(t *testing.T, b *Broker) *Request {
	t.Helper()
	select {
	case r := <-b.Requests():
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("no request")
	}
	return nil
}

func wait(t *testing.T, ch <-chan result) result {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("helper did not return")
	}
	return result{}
}

func TestEnvForcesAskpass(t *testing.T) {
	b := newBroker(t)
	env := strings.Join(b.Env("/usr/bin/yking"), "\n")
	for _, want := range []string{"SSH_ASKPASS=/usr/bin/yking", "SSH_ASKPASS_REQUIRE=force", EnvSock + "="} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %q: %s", want, env)
		}
	}
}

func TestAnswerAndRefuse(t *testing.T) {
	b := newBroker(t)
	h := ask(b, KindAsk, "Enter PIN for ED25519-SK key /home/alice/.ssh/yk-main-01: ")
	r := next(t, b)
	if r.Kind != KindAsk || !strings.HasPrefix(r.Prompt, "Enter PIN for ED25519-SK key") {
		t.Fatalf("request = %+v", r)
	}
	r.Answer("123456")
	r.Answer("second answer is ignored")
	if got := wait(t, h); got.err != nil || !got.ok || got.answer != "123456" {
		t.Errorf("got %+v", got)
	}

	h = ask(b, KindAsk, "alice@host.example's password: ")
	next(t, b).Refuse()
	if got := wait(t, h); got.ok {
		t.Errorf("refused request succeeded: %+v", got)
	}
}

// A notice blocks the helper until the TUI (or ssh) ends it; Gone tells
// the TUI the helper is gone.
func TestNotifyAndGone(t *testing.T) {
	b := newBroker(t)
	h := ask(b, KindNotify, "Confirm user presence for key ED25519-SK SHA256:abc")
	r := next(t, b)
	if r.Kind != KindNotify {
		t.Fatalf("kind = %s", r.Kind)
	}
	select {
	case <-h:
		t.Fatal("notice returned before it was ended")
	case <-time.After(100 * time.Millisecond):
	}
	b.Close()
	if got := wait(t, h); !got.ok {
		t.Errorf("notice should always succeed: %+v", got)
	}
	select {
	case <-r.Gone:
	case <-time.After(3 * time.Second):
		t.Error("Gone not closed")
	}
}

func TestNoBroker(t *testing.T) {
	if _, ok, _ := Ask(t.TempDir()+"/none", KindAsk, "PIN"); ok {
		t.Error("question without broker succeeded")
	}
	if _, ok, _ := Ask(t.TempDir()+"/none", KindNotify, "touch"); !ok {
		t.Error("notice without broker must not stop ssh")
	}
}

func TestBadRequestIgnored(t *testing.T) {
	b := newBroker(t)
	if _, ok, _ := Ask(sock(b), Kind("exec"), "x"); ok {
		t.Error("unknown kind accepted")
	}
	select {
	case r := <-b.Requests():
		t.Errorf("unknown kind delivered: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
}
