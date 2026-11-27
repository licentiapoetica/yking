// Package runner executes external programs. It exists so every shell-out in
// yking goes through one interface that tests can replace with a fake.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds every external command so a hung tool (e.g. a key
// waiting for touch) never freezes the TUI.
const DefaultTimeout = 15 * time.Second

// Result is the outcome of one command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs a program with arguments. Implementations must not use a shell.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

// Exec is the real Runner backed by os/exec.
type Exec struct {
	Timeout time.Duration
}

// StdinRunner can also feed stdin (secrets never go on a command line).
type StdinRunner interface {
	RunStdin(ctx context.Context, stdin []byte, name string, args ...string) (Result, error)
}

// Run executes name with args, forcing the C locale so output is parseable.
func (e Exec) Run(ctx context.Context, name string, args ...string) (Result, error) {
	return e.RunStdin(ctx, nil, name, args...)
}

// RunStdin is Run with stdin (nil: none).
func (e Exec) RunStdin(ctx context.Context, stdin []byte, name string, args ...string) (Result, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.Stdin = nil // never let a tool read an interactive answer from us
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return res, nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, &ExitError{Name: name, Code: res.ExitCode, Stderr: strings.TrimSpace(stderr.String())}
	}
	return res, err
}

// ExitError reports a non-zero exit.
type ExitError struct {
	Name   string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("%s exited %d: %s", e.Name, e.Code, e.Stderr)
	}
	return fmt.Sprintf("%s exited %d", e.Name, e.Code)
}
