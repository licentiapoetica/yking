package fido

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

// AssertBinary is libfido2's assertion tool. Only this package runs it.
const AssertBinary = "fido2-assert"

// Devices returns /dev paths of all FIDO HID devices (any vendor).
func Devices(sysRoot string) ([]string, error) {
	ents, err := os.ReadDir(sysRoot)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		desc, err := os.ReadFile(filepath.Join(sysRoot, e.Name(), "device", "report_descriptor"))
		if err == nil && bytes.Contains(desc, usagePageFIDO) {
			out = append(out, "/dev/"+e.Name())
		}
	}
	return out, nil
}

var (
	devRe = regexp.MustCompile(`^/dev/hidraw[0-9]+$`)
	b64Re = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)
)

// ErrNotThisKey means the credential does not belong to the device.
var ErrNotThisKey = errors.New("credential not on this key")

// Probe asks device whether it holds the non-resident credential
// keyHandle for rpID, WITHOUT user presence, user verification or PIN:
// no touch, no PIN attempt, nothing stored. The tool runs without a
// controlling terminal and with empty stdin, so it cannot prompt.
func Probe(ctx context.Context, device, rpID, keyHandle string) error {
	if !devRe.MatchString(device) {
		return fmt.Errorf("bad device %q", device)
	}
	if !b64Re.MatchString(keyHandle) {
		return errors.New("bad key handle")
	}
	if rpID == "" || bytes.ContainsAny([]byte(rpID), "\n\r") {
		return errors.New("bad relying party id")
	}
	var cdh [32]byte
	rand.Read(cdh[:])
	input := base64.StdEncoding.EncodeToString(cdh[:]) + "\n" + rpID + "\n" + keyHandle + "\n"

	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, AssertBinary, ProbeArgs(device)...)
	cmd.Stdin = bytes.NewReader([]byte(input)) // parameters only; never a PIN
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return fmt.Errorf("%s timed out", AssertBinary)
	case bytes.Contains(stderr.Bytes(), []byte("FIDO_ERR_NO_CREDENTIALS")):
		return ErrNotThisKey
	default:
		return fmt.Errorf("%s: %v %s", AssertBinary, err, bytes.TrimSpace(stderr.Bytes()))
	}
}

// ProbeArgs are the fixed arguments: silent assertion, input on stdin.
func ProbeArgs(device string) []string {
	return []string{"-G", "-t", "up=false", "-t", "uv=false", "-t", "pin=false", device}
}
