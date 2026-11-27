// Package ykman wraps the ykman CLI behind an allowlist (see policy.go).
// It is the only package in yking allowed to invoke ykman.
package ykman

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/licentiapoetica/yking/internal/runner"
)

// Binary is the ykman executable name.
const Binary = "ykman"

// Client runs policy-checked ykman commands.
type Client struct {
	r runner.Runner
}

// New returns a Client using r.
func New(r runner.Runner) *Client { return &Client{r: r} }

// run is the single choke point for ykman execution.
func (c *Client) run(ctx context.Context, args ...string) ([]byte, error) {
	if _, err := Check(args); err != nil {
		return nil, err
	}
	res, err := c.r.Run(ctx, Binary, args...)
	if err != nil {
		return res.Stdout, err
	}
	return res.Stdout, nil
}

// Version returns ykman's version line.
func (c *Client) Version(ctx context.Context) (string, error) {
	out, err := c.run(ctx, "--version")
	if err != nil {
		return "", err
	}
	return parseVersion(out), nil
}

// ListDevices returns one line per connected YubiKey, including keys whose
// serial cannot be read (e.g. FIDO-only Security Key models).
func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	out, err := c.run(ctx, "list")
	if err != nil {
		return nil, err
	}
	return parseList(out), nil
}

// ListSerials returns the serials of connected keys.
func (c *Client) ListSerials(ctx context.Context) ([]string, error) {
	out, err := c.run(ctx, "list", "--serials")
	if err != nil {
		return nil, err
	}
	return parseSerials(out), nil
}

// Info reads general device info.
func (c *Client) Info(ctx context.Context, serial string) (DeviceInfo, error) {
	out, err := c.run(ctx, "--device", serial, "info")
	if err != nil {
		return DeviceInfo{}, err
	}
	return parseInfo(out), nil
}

// FIDOInfo reads FIDO2 state (PIN set/retries). Never asks for the PIN.
func (c *Client) FIDOInfo(ctx context.Context, serial string) (FIDOInfo, error) {
	out, err := c.run(ctx, "--device", serial, "fido", "info")
	if err != nil {
		return FIDOInfo{PINRetries: -1, CredsRemaining: -1}, err
	}
	return parseFIDOInfo(out), nil
}

// OTPInfo reads which OTP slots are programmed.
func (c *Client) OTPInfo(ctx context.Context, serial string) (OTPInfo, error) {
	out, err := c.run(ctx, "--device", serial, "otp", "info")
	if err != nil {
		return OTPInfo{}, err
	}
	return parseOTPInfo(out), nil
}

// OpenPGPInfo reads PIN tries and settings of the OpenPGP app.
func (c *Client) OpenPGPInfo(ctx context.Context, serial string) (OpenPGPInfo, error) {
	out, err := c.run(ctx, "--device", serial, "openpgp", "info")
	if err != nil {
		return OpenPGPInfo{PINTries: -1, AdminPINTries: -1, ResetCodeTries: -1}, err
	}
	return parseOpenPGPInfo(out), nil
}

// PGPSlot reads one OpenPGP key slot (slot: sig, dec or aut).
func (c *Client) PGPSlot(ctx context.Context, serial, slot string) (PGPSlot, error) {
	out, err := c.run(ctx, "--device", serial, "openpgp", "keys", "info", slot)
	var ee *runner.ExitError
	if errors.As(err, &ee) && strings.Contains(ee.Stderr, "No key stored") {
		return PGPSlot{Empty: true}, nil
	}
	if err != nil {
		return PGPSlot{}, err
	}
	return parsePGPSlot(out), nil
}

// ErrSlotNotEmpty: yking writes only into an empty OTP slot.
var ErrSlotNotEmpty = errors.New("OTP slot 2 is not empty; nothing written")

// ProgramChalResp writes an HMAC-SHA1 challenge-response secret into OTP
// slot 2, but only if a fresh read shows the slot empty (ykman itself
// would overwrite). The secret goes over stdin.
func (c *Client) ProgramChalResp(ctx context.Context, serial string, secret []byte, touch bool) error {
	sr, ok := c.r.(runner.StdinRunner)
	if !ok {
		return errors.New("runner cannot pass a secret on stdin")
	}
	info, err := c.OTPInfo(ctx, serial)
	if err != nil {
		return err
	}
	if info.Slot2 != SlotEmpty {
		return ErrSlotNotEmpty
	}
	args := []string{"--device", serial, "otp", "chalresp", "2"}
	if touch {
		args = []string{"--device", serial, "otp", "chalresp", "--touch", "2"}
	}
	if _, err := Check(args); err != nil {
		return err
	}
	_, err = sr.RunStdin(ctx, []byte(hex.EncodeToString(secret)+"\ny\n"), Binary, args...)
	return err
}

// ClearChalResp deletes OTP slot 2: the one deleting command yking has.
// Callers must have the user confirm it for this very key.
func (c *Client) ClearChalResp(ctx context.Context, serial string) error {
	sr, ok := c.r.(runner.StdinRunner)
	if !ok {
		return errors.New("runner cannot answer the confirmation")
	}
	info, err := c.OTPInfo(ctx, serial)
	if err != nil {
		return err
	}
	if info.Slot2 != SlotProgrammed {
		return errors.New("OTP slot 2 is already empty")
	}
	args := []string{"--device", serial, "otp", "delete", "2"}
	if k, err := Check(args); err != nil || k != Clear {
		return fmt.Errorf("refused: %v", err)
	}
	_, err = sr.RunStdin(ctx, []byte("y\n"), Binary, args...)
	return err
}

// Calculate sends challenge to OTP slot 2 and returns the response (needs
// a touch if the slot requires one).
func (c *Client) Calculate(ctx context.Context, serial string, challenge []byte) ([]byte, error) {
	out, err := c.run(ctx, "--device", serial, "otp", "calculate", "2", hex.EncodeToString(challenge))
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(out)))
}

// FormatSerial renders a numeric serial the way ykman expects it.
func FormatSerial(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
