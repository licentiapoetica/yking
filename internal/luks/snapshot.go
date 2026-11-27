package luks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/fsutil"
)

// The TUI runs as the user and cannot read LUKS headers. Every root
// `yking luks …` leaves this snapshot of the slot lists (public metadata
// only: slot numbers, kinds, cipher, KDF) for the disk screen.

// SnapshotPath is world-readable on purpose: it holds no secrets.
var SnapshotPath = "/var/lib/yking/luks-slots.json"

// Snapshot is the slot list of every LUKS volume at ReadAt.
type Snapshot struct {
	ReadAt  time.Time    `json:"read_at"`
	Volumes []SnapVolume `json:"volumes"`
}

// SnapVolume is one volume.
type SnapVolume struct {
	Device  string     `json:"device"`
	UUID    string     `json:"uuid"`
	Version int        `json:"version"`
	Cipher  string     `json:"cipher,omitempty"`
	Slots   []SnapSlot `json:"slots"`
	Err     string     `json:"error,omitempty"`
}

// Slot kinds.
const (
	KindPassphrase = "passphrase" // or a key file: no token
	KindFIDO2      = "fido2"
	KindRecovery   = "recovery"
	KindTPM2       = "tpm2"
)

// SnapSlot is one keyslot.
type SnapSlot struct {
	ID    int    `json:"id"`
	Kind  string `json:"kind"`
	KDF   string `json:"kdf,omitempty"`
	PIN   bool   `json:"pin,omitempty"`
	Touch bool   `json:"touch,omitempty"`
}

// SnapSlots converts a LUKS2 header.
func SnapSlots(h Header) []SnapSlot {
	var out []SnapSlot
	for _, s := range h.Slots {
		ss := SnapSlot{ID: s.ID, KDF: s.KDF, Kind: KindPassphrase}
		if t := s.Token; t != nil {
			switch t.Type {
			case "systemd-fido2":
				ss.Kind, ss.PIN, ss.Touch = KindFIDO2, t.PINRequired, t.UPRequired
			case "systemd-recovery":
				ss.Kind = KindRecovery
			case "systemd-tpm2":
				ss.Kind = KindTPM2
			default:
				ss.Kind = t.Type
			}
		}
		out = append(out, ss)
	}
	return out
}

var luks1SlotRe = regexp.MustCompile(`^Key Slot ([0-9]+): ENABLED`)

// ParseLUKS1Dump reads the enabled slots and cipher of `cryptsetup
// luksDump` for a LUKS1 volume (no JSON there; all slots are passphrases).
func ParseLUKS1Dump(b []byte) (string, []SnapSlot) {
	var name, mode string
	var slots []SnapSlot
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if m := luks1SlotRe.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			slots = append(slots, SnapSlot{ID: n, Kind: KindPassphrase, KDF: "pbkdf2"})
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			switch k {
			case "Cipher name":
				name = strings.TrimSpace(v)
			case "Cipher mode":
				mode = strings.TrimSpace(v)
			}
		}
	}
	if name != "" && mode != "" {
		return name + "-" + mode, slots
	}
	return name, slots
}

// TakeSnapshot reads every volume's header (root) and writes SnapshotPath.
func TakeSnapshot(vols []Volume, now time.Time) error {
	s := Snapshot{ReadAt: now.UTC().Truncate(time.Second)}
	for _, v := range vols {
		sv := SnapVolume{Device: v.Device, UUID: v.UUID, Version: v.Version}
		if v.Version == 2 {
			h, err := ReadHeader(v.Device)
			if err != nil {
				sv.Err = err.Error()
			} else {
				sv.Cipher, sv.Slots = h.Cipher, SnapSlots(h)
			}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			out, err := exec.CommandContext(ctx, "cryptsetup", "luksDump", v.Device).Output()
			cancel()
			if err != nil {
				sv.Err = err.Error()
			} else {
				sv.Cipher, sv.Slots = ParseLUKS1Dump(out)
			}
		}
		s.Volumes = append(s.Volumes, sv)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(SnapshotPath, b, 0o644)
}

// ReadSnapshot loads the snapshot (nil, nil if none yet).
func ReadSnapshot() (*Snapshot, error) {
	b, err := os.ReadFile(SnapshotPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Volume returns the snapshot of the volume with uuid.
func (s *Snapshot) Volume(uuid string) *SnapVolume {
	if s == nil {
		return nil
	}
	for i := range s.Volumes {
		if s.Volumes[i].UUID == uuid {
			return &s.Volumes[i]
		}
	}
	return nil
}
