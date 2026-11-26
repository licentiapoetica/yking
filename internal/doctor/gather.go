package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/events"
	"github.com/licentiapoetica/yking/internal/fsutil"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/sshkey"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// TestsPath is where key test dates live (the user's own state; no root).
func TestsPath(home string) string {
	return filepath.Join(home, ".local", "state", "yking", "tests.json")
}

// LoadTests reads the key test dates.
func LoadTests(home string) map[string]time.Time {
	out := map[string]time.Time{}
	b, err := os.ReadFile(TestsPath(home))
	if err == nil {
		json.Unmarshal(b, &out)
	}
	return out
}

// RecordTest stores now as serial's last test.
func RecordTest(home, serial string, now time.Time) error {
	t := LoadTests(home)
	t[serial] = now.UTC().Truncate(time.Second)
	b, _ := json.MarshalIndent(t, "", "  ")
	if err := os.MkdirAll(filepath.Dir(TestsPath(home)), 0o700); err != nil {
		return err
	}
	return fsutil.WriteAtomic(TestsPath(home), append(b, '\n'), 0o600)
}

// Options locate things (overridable in tests).
type Options struct {
	KeyringPath string
	Home        string
	User        string
	Client      *ykman.Client // nil: skip connected keys
	Self        string        // running binary, to compare with the installed one
}

// Gather collects Inputs from the system. Read-only.
func Gather(o Options) (Inputs, error) {
	in := Inputs{Now: time.Now(), User: o.User, Tests: LoadTests(o.Home)}
	kr, err := keyring.Load(o.KeyringPath)
	if err != nil {
		return in, err
	}
	in.Keyring = kr

	in.MappingPath = pam.DefaultMappingPath(o.Home)
	if fi, err := os.Stat(in.MappingPath); err == nil {
		in.MappingMode = fi.Mode().Perm() // permission bits
		if in.MappingMode == 0 {
			in.MappingMode = fs.ModeSticky // present but mode 0000: keep a non-zero marker
		}
		if b, err := os.ReadFile(in.MappingPath); err == nil {
			in.Mapping, _ = pam.ParseMapping(string(b))
		}
	}

	in.PAM, _ = pam.Discover(pam.EtcDir, pam.VendorDir)
	in.ModuleInstalled = pam.ModuleExists("pam_u2f.so")
	in.PAMWrites = lastPAMWrites()

	e := &in.Events
	_, cerr := os.Stat(events.ConfigPath)
	e.Configured = cerr == nil
	if inst, err := os.ReadFile(events.BinaryPath); err == nil {
		e.BinaryInstalled = true
		if self, err := os.ReadFile(o.Self); err == nil {
			e.BinaryCurrent = fsutil.SHA256(self) == fsutil.SHA256(inst)
		}
	}
	if b, err := os.ReadFile(events.RulePath); err == nil {
		e.RuleExists, e.RuleCurrent = true, string(b) == events.Rule
	}
	if b, err := os.ReadFile(events.UnitPath); err == nil {
		e.UnitExists, e.UnitCurrent = true, string(b) == events.Unit
	}

	sshDir := filepath.Join(o.Home, ".ssh")
	if fi, err := os.Stat(sshDir); err == nil {
		in.SSHDir = File{sshDir, fi.Mode().Perm() | fs.ModeDir}
		ents, _ := os.ReadDir(sshDir)
		for _, d := range ents {
			if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
				continue
			}
			if fi, err := d.Info(); err == nil {
				in.SSHFiles = append(in.SSHFiles, File{filepath.Join(sshDir, d.Name()), fi.Mode().Perm()})
			}
		}
	}
	known := map[string]bool{}
	for _, k := range kr.Keys {
		for _, s := range k.SSH {
			known[s.Fingerprint] = true
		}
	}
	if sk, err := sshkey.ScanSK(sshDir); err == nil {
		for _, p := range sk {
			if !known[p.Fingerprint] {
				in.Untracked = append(in.Untracked, p)
			}
		}
	}

	if o.Client != nil {
		if rep, err := detect.Scan(context.Background(), o.Client, kr); err == nil {
			in.Connected = rep.Keys
		}
	}
	return in, nil
}

// lastPAMWrites returns, per PAM file, what yking wrote last (from the
// readable apply manifests) and the file's current hash.
func lastPAMWrites() []PAMWrite {
	h, err := plan.NewApplier().History() // newest first
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []PAMWrite
	for _, m := range h {
		for _, e := range m.Entries {
			if filepath.Dir(e.Path) != pam.EtcDir || seen[e.Path] {
				continue
			}
			seen[e.Path] = true
			if !m.Complete || m.RolledBack != nil {
				continue // newest action on this file was undone
			}
			w := PAMWrite{Path: e.Path, WrittenSHA256: e.WrittenSHA256}
			if b, err := os.ReadFile(e.Path); err == nil {
				w.CurrentSHA256 = fsutil.SHA256(b)
			} else if !errors.Is(err, fs.ErrNotExist) {
				continue
			}
			out = append(out, w)
		}
	}
	return out
}
