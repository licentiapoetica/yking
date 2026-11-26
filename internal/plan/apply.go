package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/fsutil"
	"github.com/licentiapoetica/yking/internal/keyring"
)

// DefaultBackupRoot holds one directory of backups per applied plan.
const DefaultBackupRoot = "/var/lib/yking/backups"

// Target is a directory yking may write into, with a content validator.
type Target struct {
	Dir      string
	Validate func(path string, content []byte) error
}

// DefaultTargets are the only places an elevated apply may write. Later
// milestones add /etc/pam.d, /etc/udev/rules.d, /etc/crypttab, … each with
// its own validator.
func DefaultTargets() []Target {
	return []Target{
		{Dir: "/etc/yking", Validate: validateYkingFile},
	}
}

func validateYkingFile(path string, content []byte) error {
	switch filepath.Base(path) {
	case "keyring.toml":
		_, err := keyring.Parse(content)
		return err
	default:
		return fmt.Errorf("unknown yking config file %s", filepath.Base(path))
	}
}

// Applier executes plans.
type Applier struct {
	BackupRoot string
	Targets    []Target
	Now        func() time.Time
}

// NewApplier returns the production applier.
func NewApplier() *Applier {
	return &Applier{BackupRoot: DefaultBackupRoot, Targets: DefaultTargets(), Now: time.Now}
}

var idRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$`)

// Check validates the plan and every precondition without changing anything.
func (a *Applier) Check(p *Plan) error {
	if p.Version != FormatVersion {
		return fmt.Errorf("unsupported plan version %d", p.Version)
	}
	if !idRe.MatchString(p.ID) {
		return fmt.Errorf("invalid plan id %q", p.ID)
	}
	if len(p.Steps) == 0 {
		return ErrNoChanges
	}
	seen := map[string]bool{}
	for i, s := range p.Steps {
		if err := a.checkStep(s); err != nil {
			return fmt.Errorf("step %d (%s): %w", i+1, s.Path, err)
		}
		if seen[s.Path] {
			return fmt.Errorf("step %d: %s written twice", i+1, s.Path)
		}
		seen[s.Path] = true
	}
	return nil
}

// stepData returns the bytes a step writes. For installs the source is
// read and must match the pinned hash.
func stepData(s Step) ([]byte, error) {
	switch s.Kind {
	case KindWriteFile:
		return []byte(s.Content), nil
	case KindInstall:
		if !filepath.IsAbs(s.Source) {
			return nil, errors.New("install source must be absolute")
		}
		b, err := os.ReadFile(s.Source)
		if err != nil {
			return nil, err
		}
		if fsutil.SHA256(b) != s.SHA256 {
			return nil, errors.New("install source changed since the plan was made")
		}
		return b, nil
	}
	return nil, fmt.Errorf("unknown step kind %q", s.Kind)
}

func (a *Applier) checkStep(s Step) error {
	data, err := stepData(s)
	if err != nil {
		return err
	}
	if s.Kind == KindInstall && s.Mode&^0o755 != 0 {
		return fmt.Errorf("mode %04o not allowed for an install", s.Mode)
	}
	if !filepath.IsAbs(s.Path) || filepath.Clean(s.Path) != s.Path {
		return errors.New("path must be absolute and clean")
	}
	if s.Mode&^0o777 != 0 || s.Mode&0o022 != 0 { // also: no setuid/setgid/sticky
		return fmt.Errorf("mode %04o not allowed (no group/other write, no special bits)", s.Mode)
	}
	t := a.target(s.Path)
	if t == nil {
		return errors.New("path outside yking's allowed directories")
	}
	if err := t.Validate(s.Path, data); err != nil {
		return fmt.Errorf("invalid content: %w", err)
	}
	fi, err := os.Lstat(s.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !s.ExpectAbsent {
			return errors.New("file was removed since the plan was made")
		}
		return nil
	case err != nil:
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("refusing to write: not a regular file (symlink?)")
	}
	if s.ExpectAbsent {
		return errors.New("file was created since the plan was made")
	}
	cur, err := os.ReadFile(s.Path)
	if err != nil {
		return err
	}
	if fsutil.SHA256(cur) != s.ExpectSHA256 {
		return errors.New("file changed since the plan was made; rebuild the plan")
	}
	return nil
}

func (a *Applier) target(path string) *Target {
	for i := range a.Targets {
		if filepath.Dir(path) == a.Targets[i].Dir {
			return &a.Targets[i]
		}
	}
	return nil
}

// Manifest records what an apply did, for rollback.
type Manifest struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	AppliedAt   time.Time  `json:"applied_at"`
	Complete    bool       `json:"complete"`
	RolledBack  *time.Time `json:"rolled_back,omitempty"`
	Entries     []Entry    `json:"entries"`
}

// Entry is one file touched by an apply.
type Entry struct {
	Path          string `json:"path"`
	Existed       bool   `json:"existed"`
	Mode          uint32 `json:"mode,omitempty"`
	Backup        string `json:"backup,omitempty"` // file name inside the backup dir
	WrittenSHA256 string `json:"written_sha256"`
}

// Apply checks the plan, backs up every target, then writes. If any write
// fails, files already written are restored before returning the error.
func (a *Applier) Apply(p *Plan) (*Manifest, error) {
	if err := a.Check(p); err != nil {
		return nil, err
	}
	dir := filepath.Join(a.BackupRoot, p.ID)
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("plan %s was already applied", p.ID)
	}
	// Plan dirs and manifests are world-readable (paths only, no content) so
	// history works without root; backup copies are root-only.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	// Read every step's bytes once; installs are verified against their hash
	// here, so what is written is exactly what was checked.
	data := make([][]byte, len(p.Steps))
	for i, s := range p.Steps {
		b, err := stepData(s)
		if err != nil {
			os.RemoveAll(dir)
			return nil, fmt.Errorf("step %d (%s): %w", i+1, s.Path, err)
		}
		data[i] = b
	}

	m := &Manifest{ID: p.ID, Description: p.Description, AppliedAt: a.Now().UTC().Truncate(time.Second)}
	for i, s := range p.Steps {
		e := Entry{Path: s.Path, WrittenSHA256: fsutil.SHA256(data[i])}
		if cur, err := os.ReadFile(s.Path); err == nil {
			fi, _ := os.Stat(s.Path)
			e.Existed = true
			e.Mode = uint32(fi.Mode().Perm())
			e.Backup = strconv.Itoa(i+1) + ".orig"
			if err := os.WriteFile(filepath.Join(dir, e.Backup), cur, 0o600); err != nil {
				return nil, fmt.Errorf("backup %s: %w", s.Path, err)
			}
		}
		m.Entries = append(m.Entries, e)
	}
	if err := writeManifest(dir, m); err != nil {
		return nil, err
	}

	for i, s := range p.Steps {
		if err := fsutil.WriteAtomic(s.Path, data[i], fs.FileMode(s.Mode)); err != nil {
			rerr := a.restore(dir, m.Entries[:i+1], true)
			if rerr != nil {
				return m, fmt.Errorf("write %s: %w; RESTORE ALSO FAILED: %v (backups in %s)", s.Path, err, rerr, dir)
			}
			now := a.Now().UTC().Truncate(time.Second)
			m.RolledBack = &now
			writeManifest(dir, m)
			return m, fmt.Errorf("write %s: %w (earlier changes restored)", s.Path, err)
		}
	}
	m.Complete = true
	return m, writeManifest(dir, m)
}

// Rollback restores the files touched by plan id. Unless force is set it
// refuses when a file was changed after yking wrote it.
func (a *Applier) Rollback(id string, force bool) (*Manifest, error) {
	if !idRe.MatchString(id) {
		return nil, fmt.Errorf("invalid plan id %q", id)
	}
	dir := filepath.Join(a.BackupRoot, id)
	m, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	if m.RolledBack != nil {
		return m, fmt.Errorf("plan %s was already rolled back at %s", id, m.RolledBack.Local().Format(time.DateTime))
	}
	if !force {
		for _, e := range m.Entries {
			cur, err := os.ReadFile(e.Path)
			if err != nil {
				return m, fmt.Errorf("%s: %w (use --force to restore anyway)", e.Path, err)
			}
			if fsutil.SHA256(cur) != e.WrittenSHA256 {
				return m, fmt.Errorf("%s changed after yking wrote it (use --force to restore anyway)", e.Path)
			}
		}
	}
	if err := a.restore(dir, m.Entries, force); err != nil {
		return m, err
	}
	now := a.Now().UTC().Truncate(time.Second)
	m.RolledBack = &now
	return m, writeManifest(dir, m)
}

func (a *Applier) restore(dir string, entries []Entry, ignoreMissing bool) error {
	var errs []error
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.Existed {
			b, err := os.ReadFile(filepath.Join(dir, e.Backup))
			if err == nil {
				err = fsutil.WriteAtomic(e.Path, b, fs.FileMode(e.Mode))
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("restore %s: %w", e.Path, err))
			}
			continue
		}
		if err := os.Remove(e.Path); err != nil && !(ignoreMissing && errors.Is(err, fs.ErrNotExist)) {
			errs = append(errs, fmt.Errorf("remove %s: %w", e.Path, err))
		}
	}
	return errors.Join(errs...)
}

// History lists applied plans, newest first.
func (a *Applier) History() ([]Manifest, error) {
	ents, err := os.ReadDir(a.BackupRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Manifest
	for _, d := range ents {
		if !d.IsDir() || !idRe.MatchString(d.Name()) {
			continue
		}
		m, err := readManifest(filepath.Join(a.BackupRoot, d.Name()))
		if err != nil {
			continue
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Latest returns the newest complete plan that was not rolled back.
func (a *Applier) Latest() (*Manifest, error) {
	h, err := a.History()
	if err != nil {
		return nil, err
	}
	for i := range h {
		if h[i].Complete && h[i].RolledBack == nil {
			return &h[i], nil
		}
	}
	return nil, errors.New("no applied plan to roll back")
}

func writeManifest(dir string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o644)
}

func readManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return &m, nil
}

// Describe renders a manifest for `yking history`.
func (m Manifest) Describe() string {
	state := "applied"
	switch {
	case m.RolledBack != nil:
		state = "rolled back"
	case !m.Complete:
		state = "INCOMPLETE"
	}
	var paths []string
	for _, e := range m.Entries {
		paths = append(paths, e.Path)
	}
	return fmt.Sprintf("%s  %-11s  %s  [%s]", m.ID, state, m.Description, strings.Join(paths, ", "))
}
