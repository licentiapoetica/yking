// Package plan implements yking's plan → review → apply model. The TUI (as
// the user) builds a Plan; the user reviews its diff; an elevated `yking
// apply` checks and executes it with backups, and `yking rollback` undoes it.
package plan

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"yking/internal/fsutil"
)

// FormatVersion is the plan file format version.
const FormatVersion = 1

// StepKind identifies a step type.
type StepKind string

const (
	// KindWriteFile replaces (or creates) a text file.
	KindWriteFile StepKind = "write_file"
	// KindInstall copies a (binary) file from Source; SHA256 pins exactly
	// which bytes may be installed.
	KindInstall StepKind = "install"
)

// Step is one change. Preconditions (ExpectAbsent / ExpectSHA256) pin the
// state the diff was reviewed against; apply refuses if the file changed.
type Step struct {
	Kind         StepKind `json:"kind"`
	Path         string   `json:"path"`
	Mode         uint32   `json:"mode"`
	Content      string   `json:"content"`
	Source       string   `json:"source,omitempty"` // KindInstall
	SHA256       string   `json:"sha256,omitempty"` // KindInstall: hash of Source
	ExpectAbsent bool     `json:"expect_absent,omitempty"`
	ExpectSHA256 string   `json:"expect_sha256,omitempty"`
}

// Plan is an ordered list of steps with a human description.
type Plan struct {
	Version     int       `json:"version"`
	ID          string    `json:"id"`
	Created     time.Time `json:"created"`
	Description string    `json:"description"`
	Steps       []Step    `json:"steps"`
}

// New starts an empty plan.
func New(description string, now time.Time) *Plan {
	var r [3]byte
	rand.Read(r[:])
	return &Plan{
		Version:     FormatVersion,
		ID:          now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(r[:]),
		Created:     now.UTC().Truncate(time.Second),
		Description: description,
	}
}

// ErrNoChanges is returned when a plan would change nothing.
var ErrNoChanges = errors.New("nothing to change")

// Base is a file's content at planning time. Build new content from
// Base.Data and pass the same Base to Replace, so the precondition matches
// exactly what the change was computed from.
type Base struct {
	Path   string
	Data   []byte
	Exists bool
}

// ReadBase reads path; a missing file is a valid, empty Base.
func ReadBase(path string) (Base, error) {
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Base{Path: path}, nil
	case err != nil:
		return Base{}, err
	}
	return Base{Path: path, Data: b, Exists: true}, nil
}

// Replace adds a step turning base into content. Identical content adds no
// step.
func (p *Plan) Replace(base Base, content []byte, mode fs.FileMode) {
	if base.Exists && string(base.Data) == string(content) {
		return
	}
	st := Step{Kind: KindWriteFile, Path: base.Path, Mode: uint32(mode.Perm()), Content: string(content)}
	if base.Exists {
		st.ExpectSHA256 = fsutil.SHA256(base.Data)
	} else {
		st.ExpectAbsent = true
	}
	p.Steps = append(p.Steps, st)
}

// WriteFile adds a step replacing path with content, using the file's
// current state as the precondition.
func (p *Plan) WriteFile(path string, content []byte, mode fs.FileMode) error {
	base, err := ReadBase(path)
	if err != nil {
		return err
	}
	p.Replace(base, content, mode)
	return nil
}

// Install adds a step copying source to path. If path already holds the
// same bytes, no step is added.
func (p *Plan) Install(path, source string, mode fs.FileMode) error {
	src, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	base, err := ReadBase(path)
	if err != nil {
		return err
	}
	sum := fsutil.SHA256(src)
	if base.Exists && fsutil.SHA256(base.Data) == sum {
		return nil
	}
	st := Step{Kind: KindInstall, Path: path, Mode: uint32(mode.Perm()), Source: source, SHA256: sum}
	if base.Exists {
		st.ExpectSHA256 = fsutil.SHA256(base.Data)
	} else {
		st.ExpectAbsent = true
	}
	p.Steps = append(p.Steps, st)
	return nil
}

// Empty reports whether the plan has no steps.
func (p *Plan) Empty() bool { return len(p.Steps) == 0 }

// Diff renders every step against the files as they are on disk now.
func (p *Plan) Diff() (string, error) {
	var b strings.Builder
	for _, s := range p.Steps {
		switch s.Kind {
		case KindInstall:
			verb := "install"
			if !s.ExpectAbsent {
				verb = "update"
			}
			fmt.Fprintf(&b, "=== %s %s\n    from %s\n    sha256 %s\n", verb, s.Path, s.Source, s.SHA256)
		case KindWriteFile:
			cur, err := os.ReadFile(s.Path)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
			from := s.Path
			if err != nil {
				from = "/dev/null"
			}
			b.WriteString(Unified(from, s.Path, string(cur), s.Content, 3))
		default:
			fmt.Fprintf(&b, "unknown step %q\n", s.Kind)
		}
	}
	return b.String(), nil
}

// Summary lists steps one per line.
func (p *Plan) Summary() string {
	var b strings.Builder
	for _, s := range p.Steps {
		verb := "modify"
		if s.ExpectAbsent {
			verb = "create"
		}
		if s.Kind == KindInstall {
			verb = "install"
		}
		fmt.Fprintf(&b, "  %s %s (mode %04o)\n", verb, s.Path, s.Mode)
	}
	return b.String()
}

// Save writes the plan as JSON, readable only by the owner.
func (p *Plan) Save(path string) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(path, append(b, '\n'), 0o600)
}

// Load reads a plan file.
func Load(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plan
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.Version != FormatVersion {
		return nil, fmt.Errorf("%s: unsupported plan version %d", path, p.Version)
	}
	return &p, nil
}
