package main

import (
	"os/exec"
	"strings"
	"testing"
)

// A fake pamu2fcfg: asks for the PIN on its terminal, prints a credential
// only for the right one, and asks again for a wrong one.
const fakeReg = `printf 'Enter PIN for /dev/hidraw1: '; read p
while [ "$p" != 123456 ]; do printf 'Enter PIN for /dev/hidraw1: '; read p; done
echo ':kh,pk,es256,+presence'`

func TestRunOnPTYAnswersPINOnce(t *testing.T) {
	asks := 0
	cred, err := runOnPTY(exec.Command("sh", "-c", fakeReg), func() (string, error) { asks++; return "123456", nil })
	if err != nil || cred != ":kh,pk,es256,+presence" || asks != 1 {
		t.Fatalf("cred=%q err=%v asks=%d", cred, err, asks)
	}
	asks = 0
	_, err = runOnPTY(exec.Command("sh", "-c", fakeReg), func() (string, error) { asks++; return "000000", nil })
	if err == nil || !strings.Contains(err.Error(), "asked again") || asks != 1 {
		t.Fatalf("wrong PIN: err=%v asks=%d", err, asks)
	}
	cred, err = runOnPTY(exec.Command("sh", "-c", "echo ':kh2,pk2,es256,+presence'"), func() (string, error) {
		t.Fatal("no PIN expected")
		return "", nil
	})
	if err != nil || cred != ":kh2,pk2,es256,+presence" {
		t.Fatalf("no-PIN run: %q %v", cred, err)
	}
}
