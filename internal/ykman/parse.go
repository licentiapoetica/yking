package ykman

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

var (
	listSerialRe = regexp.MustCompile(`Serial:\s*([0-9]+)`)
	retriesRe    = regexp.MustCompile(`([0-9]+)\s+attempt`)
	firstIntRe   = regexp.MustCompile(`[0-9]+`)
	multiSpaceRe = regexp.MustCompile(`\s{2,}`)
)

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		out = append(out, strings.TrimRight(sc.Text(), " \r"))
	}
	return out
}

func parseVersion(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndex(s, "version:"); i >= 0 {
		return strings.TrimSpace(s[i+len("version:"):])
	}
	return s
}

func parseList(b []byte) []Device {
	var out []Device
	for _, l := range lines(b) {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		d := Device{Description: l}
		if m := listSerialRe.FindStringSubmatch(l); m != nil {
			d.Serial = m[1]
			d.Description = strings.TrimSpace(l[:strings.Index(l, m[0])])
		}
		out = append(out, d)
	}
	return out
}

func parseSerials(b []byte) []string {
	var out []string
	for _, l := range lines(b) {
		l = strings.TrimSpace(l)
		if serialRe.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

// splitKV splits "Key: value" lines; returns ok=false for other lines.
func splitKV(l string) (string, string, bool) {
	i := strings.Index(l, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(l[:i]), strings.TrimSpace(l[i+1:]), true
}

func parseInfo(b []byte) DeviceInfo {
	info := DeviceInfo{Apps: map[string]AppState{}}
	inApps := false
	for _, l := range lines(b) {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if strings.HasPrefix(l, "Applications") {
			inApps = true
			continue
		}
		if inApps {
			cols := splitColumns(l)
			if len(cols) >= 2 {
				st := AppState{USB: cols[1]}
				if len(cols) >= 3 {
					st.NFC = cols[2]
				}
				info.Apps[cols[0]] = st
			}
			continue
		}
		k, v, ok := splitKV(l)
		if !ok {
			continue
		}
		switch k {
		case "Device type":
			info.DeviceType = v
		case "Serial number":
			info.Serial = v
		case "Firmware version":
			info.Firmware = v
		case "Form factor":
			info.FormFactor = v
		case "Enabled USB interfaces":
			info.USBInterfaces = v
		}
	}
	return info
}

func splitColumns(l string) []string {
	var parts []string
	if strings.Contains(l, "\t") {
		parts = strings.Split(l, "\t")
	} else {
		parts = multiSpaceRe.Split(l, -1)
	}
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseFIDOInfo handles both the ykman 5.x table format ("PIN: 8 attempt(s)
// remaining") and the older sentence format ("PIN is set, with 8 attempt(s)
// remaining.").
func parseFIDOInfo(b []byte) FIDOInfo {
	f := FIDOInfo{PINRetries: -1, CredsRemaining: -1}
	for _, l := range lines(b) {
		lower := strings.ToLower(strings.TrimSpace(l))
		switch {
		case strings.HasPrefix(lower, "pin"):
			switch {
			case strings.Contains(lower, "not set"):
				f.PINSet = false
			case strings.Contains(lower, "blocked"):
				f.PINSet = true
				f.PINBlocked = true
				f.PINRetries = 0
			default:
				if m := retriesRe.FindStringSubmatch(lower); m != nil {
					f.PINSet = true
					f.PINRetries, _ = strconv.Atoi(m[1])
				} else if strings.Contains(lower, "is set") {
					f.PINSet = true
				}
			}
		case strings.HasPrefix(lower, "minimum pin length"):
			if m := firstIntRe.FindString(lower); m != "" {
				f.MinPINLength, _ = strconv.Atoi(m)
			}
		case strings.HasPrefix(lower, "credential storage remaining"):
			if m := firstIntRe.FindString(lower); m != "" {
				f.CredsRemaining, _ = strconv.Atoi(m)
			}
		case strings.HasPrefix(lower, "always require uv"):
			_, v, _ := splitKV(l)
			f.AlwaysUV = v
		}
	}
	return f
}

func parseOTPInfo(b []byte) OTPInfo {
	var o OTPInfo
	for _, l := range lines(b) {
		k, v, ok := splitKV(l)
		if !ok {
			continue
		}
		st := SlotUnknown
		switch strings.ToLower(v) {
		case "empty":
			st = SlotEmpty
		case "programmed":
			st = SlotProgrammed
		}
		switch strings.ToLower(k) {
		case "slot 1":
			o.Slot1 = st
		case "slot 2":
			o.Slot2 = st
		}
	}
	return o
}

func parseOpenPGPInfo(b []byte) OpenPGPInfo {
	o := OpenPGPInfo{PINTries: -1, AdminPINTries: -1, ResetCodeTries: -1}
	num := func(v string) int {
		n, err := strconv.Atoi(v)
		if err != nil {
			return -1
		}
		return n
	}
	for _, l := range lines(b) {
		k, v, ok := splitKV(l)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "openpgp version":
			o.Version = v
		case "pin tries remaining":
			o.PINTries = num(v)
		case "admin pin tries remaining":
			o.AdminPINTries = num(v)
		case "reset code tries remaining":
			o.ResetCodeTries = num(v)
		case "require pin for signature":
			o.SignaturePolicy = v
		}
	}
	return o
}

func parsePGPSlot(b []byte) PGPSlot {
	var s PGPSlot
	for _, l := range lines(b) {
		k, v, ok := splitKV(l)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "fingerprint":
			s.Fingerprint = strings.ToUpper(strings.ReplaceAll(v, " ", ""))
		case "algorithm":
			s.Algorithm = v
		case "touch policy":
			s.Touch = v
		}
	}
	return s
}
