// Package ykman wraps the ykman CLI behind an allowlist (see policy.go).
// It is the only package in yking allowed to invoke ykman.
package ykman

import (
	"context"
	"strconv"

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

// FormatSerial renders a numeric serial the way ykman expects it.
func FormatSerial(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
