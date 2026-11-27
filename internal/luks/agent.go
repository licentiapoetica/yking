package luks

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// AskDir is where systemd tools place password requests when they have no
// terminal (systemd ask-password agent protocol).
var AskDir = "/run/systemd/ask-password"

// askRequest is one ask.* file.
type askRequest struct {
	PID     int
	Socket  string
	Message string
}

func readAsk(path string) (askRequest, error) {
	f, err := os.Open(path)
	if err != nil {
		return askRequest{}, err
	}
	defer f.Close()
	var r askRequest
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "PID":
			r.PID, _ = strconv.Atoi(v)
		case "Socket":
			r.Socket = v
		case "Message":
			r.Message = v
		}
	}
	return r, sc.Err()
}

// ErrSecondRequest means the process asked again (wrong PIN) or asked for
// something other than a PIN; it was stopped.
var ErrSecondRequest = errors.New("a second or unexpected password request came; the process was stopped so no further PIN attempt is used")

// AnswerPINOnce acts as an ask-password agent for exactly one process: the
// first PIN request from pid gets secret; any further request (or a request
// that is not about a PIN) calls kill and ends with ErrSecondRequest.
// Returns nil when ctx ends normally (process finished).
func AnswerPINOnce(ctx context.Context, pid int, secret []byte, kill func(), refuseAll bool) error {
	seen := map[string]bool{}
	answered := false
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		files, _ := filepath.Glob(filepath.Join(AskDir, "ask.*"))
		for _, f := range files {
			if seen[f] {
				continue
			}
			r, err := readAsk(f)
			if err != nil || r.PID != pid {
				continue
			}
			seen[f] = true
			isPIN := strings.Contains(strings.ToLower(r.Message), "pin")
			if refuseAll || answered || !isPIN || filepath.Dir(filepath.Clean(r.Socket)) != filepath.Clean(AskDir) {
				kill()
				return ErrSecondRequest
			}
			if err := send(r.Socket, append([]byte("+"), secret...)); err != nil {
				kill()
				return err
			}
			answered = true
		}
	}
}

func send(socket string, msg []byte) error {
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(msg)
	return err
}
