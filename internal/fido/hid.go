// Package fido inspects FIDO HID devices via sysfs (read-only).
package fido

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// DefaultSysRoot is where Linux exposes hidraw devices.
const DefaultSysRoot = "/sys/class/hidraw"

// usagePageFIDO is "Usage Page (FIDO Alliance 0xF1D0)" in a HID report
// descriptor (long item, little-endian).
var usagePageFIDO = []byte{0x06, 0xd0, 0xf1}

// CountDevices returns how many FIDO authenticators (any vendor) are
// connected. ssh-keygen picks whichever one the user touches, so yking
// requires exactly one before generating a key it attributes to a serial.
func CountDevices(sysRoot string) (int, error) {
	ents, err := os.ReadDir(sysRoot)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		desc, err := os.ReadFile(filepath.Join(sysRoot, e.Name(), "device", "report_descriptor"))
		if err != nil {
			continue
		}
		if bytes.Contains(desc, usagePageFIDO) {
			n++
		}
	}
	return n, nil
}

// usageKeyboard is "Usage Page (Generic Desktop), Usage (Keyboard)": the
// YubiKey's OTP interface, which challenge-response over USB goes through.
var usageKeyboard = []byte{0x05, 0x01, 0x09, 0x06}

// YubicoOTPNodes lists the hidraw names (hidraw7, …) of YubiKey OTP
// interfaces.
func YubicoOTPNodes(sysRoot string) ([]string, error) {
	ents, err := os.ReadDir(sysRoot)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		dev := filepath.Join(sysRoot, e.Name(), "device")
		ev, err := os.ReadFile(filepath.Join(dev, "uevent"))
		if err != nil || !strings.Contains(string(ev), "HID_ID=0003:00001050:") {
			continue
		}
		desc, err := os.ReadFile(filepath.Join(dev, "report_descriptor"))
		if err == nil && bytes.HasPrefix(desc, usageKeyboard) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
