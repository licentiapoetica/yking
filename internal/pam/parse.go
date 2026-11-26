// Package pam reads and writes PAM service files for pam_u2f. It is
// lockout-critical: every change goes through plan → review → apply with a
// dead-man switch (see cmd/yking apply).
package pam

import (
	"fmt"
	"strings"
)

// Line is one line of a PAM service file.
type Line struct {
	Raw      string
	Comment  bool // comment or blank
	Optional bool // leading "-" on the type (ignore if module missing)
	Type     string
	Control  string
	Module   string
	Args     []string
}

// IsU2F reports whether the line uses pam_u2f.
func (l Line) IsU2F() bool {
	return !l.Comment && (l.Module == "pam_u2f.so" || strings.HasSuffix(l.Module, "/pam_u2f.so"))
}

// IsAuth reports whether the line is an auth rule.
func (l Line) IsAuth() bool { return !l.Comment && l.Type == "auth" }

// IsInclude reports include/substack lines (Module holds the service).
func (l Line) IsInclude() bool {
	return !l.Comment && (l.Control == "include" || l.Control == "substack")
}

// Parse splits a PAM file into lines. It understands bracketed controls
// like "[success=1 default=ignore]" and leading "-".
func Parse(content string) ([]Line, error) {
	var out []Line
	for i, raw := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if content == "" {
			break
		}
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			out = append(out, Line{Raw: raw, Comment: true})
			continue
		}
		l, err := parseRule(t)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		l.Raw = raw
		out = append(out, l)
	}
	return out, nil
}

func parseRule(t string) (Line, error) {
	var l Line
	typ, rest, ok := cut(t)
	if !ok {
		return l, fmt.Errorf("incomplete rule %q", t)
	}
	if strings.HasPrefix(typ, "-") {
		l.Optional = true
		typ = typ[1:]
	}
	switch typ {
	case "auth", "account", "password", "session":
	default:
		return l, fmt.Errorf("unknown type %q", typ)
	}
	l.Type = typ

	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return l, fmt.Errorf("unterminated control in %q", t)
		}
		l.Control = rest[:end+1]
		rest = strings.TrimSpace(rest[end+1:])
	} else {
		var ok bool
		l.Control, rest, ok = cut(rest)
		if !ok {
			return l, fmt.Errorf("missing module in %q", t)
		}
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return l, fmt.Errorf("missing module in %q", t)
	}
	l.Module, l.Args = f[0], f[1:]
	return l, nil
}

func cut(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, "", false
	}
	return s[:i], strings.TrimSpace(s[i:]), true
}

// Render joins lines back into file content.
func Render(lines []Line) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Raw)
		b.WriteByte('\n')
	}
	return b.String()
}
