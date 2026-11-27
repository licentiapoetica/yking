package sshkey

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
)

// ~/.ssh/config is only ever changed by an explicit, per-host user action
// (deploy with "SSH config" ticked, or the SSH hosts screen), always as a
// reviewed plan. yking only touches its own marked blocks:
//
//	# yking-begin host.example — managed by yking; edits inside are replaced
//	Host host.example
//	    User alice
//	    # daily (11111111)
//	    IdentityFile ~/.ssh/yk-main-01
//	    IdentitiesOnly yes
//	# yking-end host.example
//
// Everything outside the markers is the user's and is never rewritten.

const (
	configBegin = "# yking-begin "
	configEnd   = "# yking-end "
	beginNote   = " — managed by yking; edits inside are replaced"
)

// ConfigPath is the user's ssh client config.
func ConfigPath(home string) string { return filepath.Join(home, ".ssh", "config") }

var hostRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._:-]*$`)

// SplitTarget splits "user@host" (user may be empty).
func SplitTarget(t string) (user, host string) {
	if i := strings.LastIndex(t, "@"); i >= 0 {
		return t[:i], t[i+1:]
	}
	return "", t
}

// HostKey is one SSH key deployed to a host.
type HostKey struct {
	Path        string
	Comment     string
	Fingerprint string
	Label       string // YubiKey label
	Serial      string
	Role        keyring.Role
	PIN         bool // verify-required
}

// HostEntry is everything yking knows about one host (the part after "@").
type HostEntry struct {
	Host    string
	Users   []string  // distinct logins recorded for the host ("" = none given)
	Keys    []HostKey // key files present on this machine, daily first
	Missing []HostKey // recorded, but the key file is not on this machine
}

// Hosts groups the keyring's deployed targets by host, sorted by name.
// exists reports whether a key file is present (nil: os.Stat).
func Hosts(kr *keyring.Keyring, exists func(string) bool) []HostEntry {
	if exists == nil {
		exists = func(p string) bool {
			fi, err := os.Stat(p)
			return err == nil && fi.Mode().IsRegular()
		}
	}
	byHost := map[string]*HostEntry{}
	var order []string
	for _, role := range keyring.Roles {
		for _, k := range kr.Keys {
			if k.Role != role {
				continue
			}
			for _, s := range k.SSH {
				for _, t := range s.Hosts {
					user, host := SplitTarget(t)
					if !hostRe.MatchString(host) {
						continue
					}
					e := byHost[host]
					if e == nil {
						e = &HostEntry{Host: host}
						byHost[host] = e
						order = append(order, host)
					}
					if !slices.Contains(e.Users, user) {
						e.Users = append(e.Users, user)
					}
					hk := HostKey{Path: s.Path, Comment: s.Comment, Fingerprint: s.Fingerprint, Label: k.Label, Serial: k.Serial, Role: k.Role, PIN: s.VerifyRequired}
					if slices.ContainsFunc(e.Keys, func(x HostKey) bool { return x.Path == hk.Path }) ||
						slices.ContainsFunc(e.Missing, func(x HostKey) bool { return x.Fingerprint == hk.Fingerprint }) {
						continue
					}
					if s.Path != "" && exists(s.Path) {
						e.Keys = append(e.Keys, hk)
					} else {
						e.Missing = append(e.Missing, hk)
					}
				}
			}
		}
	}
	slices.Sort(order)
	out := make([]HostEntry, 0, len(order))
	for _, h := range order {
		out = append(out, *byHost[h])
	}
	return out
}

// FindHost returns the entry for host, or an empty one.
func FindHost(entries []HostEntry, host string) HostEntry {
	for _, e := range entries {
		if e.Host == host {
			return e
		}
	}
	return HostEntry{Host: host}
}

// User is the login for the User line: only when exactly one is recorded.
func (e HostEntry) User() string {
	if len(e.Users) == 1 {
		return e.Users[0]
	}
	return ""
}

// Block renders the managed block, or "" when no key file is present (the
// block is then removed).
func (e HostEntry) Block(home string) (string, error) {
	if !hostRe.MatchString(e.Host) {
		return "", fmt.Errorf("invalid host %q", e.Host)
	}
	if len(e.Keys) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteString(configBegin + e.Host + beginNote + "\n")
	b.WriteString("Host " + e.Host + "\n")
	if u := e.User(); u != "" {
		if strings.ContainsAny(u, " \t\"#") {
			return "", fmt.Errorf("invalid user %q", u)
		}
		b.WriteString("    User " + u + "\n")
	} else if len(e.Users) > 1 {
		b.WriteString("    # several logins recorded; give the user on the command line\n")
	}
	for _, k := range e.Keys {
		p, err := configPath(k.Path, home)
		if err != nil {
			return "", err
		}
		b.WriteString(fmt.Sprintf("    # %s (%s)\n", oneLine(k.Label), k.Serial))
		b.WriteString("    IdentityFile " + p + "\n")
	}
	b.WriteString("    IdentitiesOnly yes\n")
	b.WriteString(configEnd + e.Host + "\n")
	return b.String(), nil
}

// oneLine replaces control characters so a label cannot break the block.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// configPath writes a key path the way ssh_config reads it: ~/ relative to
// home, quoted if it has spaces.
func configPath(p, home string) (string, error) {
	if !filepath.IsAbs(p) || strings.ContainsAny(p, "\"\n\r\t") {
		return "", fmt.Errorf("key path %q cannot be written to ssh config", p)
	}
	if rest, ok := strings.CutPrefix(p, home+"/"); ok && home != "" {
		p = "~/" + rest
	}
	if strings.Contains(p, " ") {
		p = `"` + p + `"`
	}
	return p, nil
}

// Managed is one yking block in a config file (line indexes, inclusive).
type Managed struct {
	Host       string
	Start, End int
}

// ParseManaged finds yking's blocks. Unbalanced or nested markers are an
// error: yking then refuses to touch the file.
func ParseManaged(cfg string) ([]Managed, error) {
	var out []Managed
	cur := -1
	host := ""
	for i, l := range splitLines(cfg) {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, configBegin):
			if cur >= 0 {
				return nil, fmt.Errorf("line %d: yking block for %s is not closed", cur+1, host)
			}
			cur, host = i, markerHost(t, configBegin)
			if !hostRe.MatchString(host) {
				return nil, fmt.Errorf("line %d: bad yking marker", i+1)
			}
		case strings.HasPrefix(t, configEnd):
			if cur < 0 || markerHost(t, configEnd) != host {
				return nil, fmt.Errorf("line %d: yking end marker without matching begin", i+1)
			}
			if slices.ContainsFunc(out, func(m Managed) bool { return m.Host == host }) {
				return nil, fmt.Errorf("line %d: two yking blocks for %s", i+1, host)
			}
			out = append(out, Managed{Host: host, Start: cur, End: i})
			cur = -1
		}
	}
	if cur >= 0 {
		return nil, fmt.Errorf("line %d: yking block for %s is not closed", cur+1, host)
	}
	return out, nil
}

func markerHost(t, prefix string) string {
	f := strings.Fields(strings.TrimPrefix(t, prefix))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// keyword returns the lower-cased ssh_config keyword of a line ("" for
// blank/comment lines). Both "Key value" and "Key=value" are accepted.
func keyword(l string) (kw, rest string) {
	t := strings.TrimSpace(l)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", ""
	}
	i := strings.IndexAny(t, " \t=")
	if i < 0 {
		return strings.ToLower(t), ""
	}
	rest = strings.TrimLeft(t[i:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	return strings.ToLower(t[:i]), rest
}

// SetBlock returns cfg with host's managed block replaced by block (""
// removes it). A new block goes before the first Host/Match section (so
// lines before it stay global, and it wins over later "Host *" catch-alls),
// or at the end if there is none.
func SetBlock(cfg, host, block string) (string, error) {
	blocks, err := ParseManaged(cfg)
	if err != nil {
		return "", err
	}
	lines := splitLines(cfg)
	var nb []string
	if block != "" {
		nb = splitLines(block)
	}
	for _, m := range blocks {
		if m.Host != host {
			continue
		}
		end := m.End + 1
		if block == "" && end < len(lines) && strings.TrimSpace(lines[end]) == "" {
			end++ // drop the blank line yking added after it
		}
		out := slices.Concat(lines[:m.Start], nb, lines[end:])
		return joinLines(out), nil
	}
	if block == "" {
		return cfg, nil
	}
	at := len(lines)
	inBlock := map[int]bool{}
	for _, m := range blocks {
		for i := m.Start; i <= m.End; i++ {
			inBlock[i] = true
		}
	}
	for i, l := range lines {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, configBegin) {
			at = i
			break
		}
		if kw, _ := keyword(l); (kw == "host" || kw == "match") && !inBlock[i] {
			at = i
			// keep comments that introduce that section attached to it
			for at > 0 && strings.HasPrefix(strings.TrimSpace(lines[at-1]), "#") && !inBlock[at-1] {
				at--
			}
			break
		}
	}
	var ins []string
	if at > 0 && strings.TrimSpace(lines[at-1]) != "" {
		ins = append(ins, "")
	}
	ins = append(ins, nb...)
	if at < len(lines) {
		ins = append(ins, "")
	}
	return joinLines(slices.Concat(lines[:at], ins, lines[at:])), nil
}

func joinLines(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return strings.Join(l, "\n") + "\n"
}

// OwnHostLines lists 1-based line numbers of the user's own (unmanaged)
// Host lines that name host literally.
func OwnHostLines(cfg, host string) []int {
	blocks, _ := ParseManaged(cfg)
	var out []int
lines:
	for i, l := range splitLines(cfg) {
		for _, m := range blocks {
			if i >= m.Start && i <= m.End {
				continue lines
			}
		}
		if kw, rest := keyword(l); kw == "host" && slices.Contains(strings.Fields(rest), host) {
			out = append(out, i+1)
		}
	}
	return out
}

// section is a user's own Host/Match section (line indexes, inclusive).
// Comment and blank lines at its end belong to whatever follows.
type section struct{ start, end int }

func ownSections(cfg string) ([]section, []string) {
	blocks, _ := ParseManaged(cfg)
	lines := splitLines(cfg)
	inBlock := make([]bool, len(lines))
	for _, m := range blocks {
		for i := m.Start; i <= m.End; i++ {
			inBlock[i] = true
		}
	}
	var out []section
	cur := -1
	closeAt := func(next int) {
		if cur < 0 {
			return
		}
		end := next - 1
		for end > cur {
			if kw, _ := keyword(lines[end]); kw != "" {
				break
			}
			end--
		}
		out = append(out, section{cur, end})
		cur = -1
	}
	for i, l := range lines {
		if inBlock[i] {
			closeAt(i)
			continue
		}
		if kw, _ := keyword(l); kw == "host" || kw == "match" {
			closeAt(i)
			cur = i
		}
	}
	closeAt(len(lines))
	return out, lines
}

// adoptable finds the user's own section for exactly e.Host that yking can
// replace without losing anything: only User (same as yking's),
// IdentityFile (all among yking's) and IdentitiesOnly. Comments go with it.
func adoptable(cfg string, e HostEntry, home string) (section, bool) {
	secs, lines := ownSections(cfg)
	var found []section
	for _, sc := range secs {
		if kw, rest := keyword(lines[sc.start]); kw == "host" && slices.Contains(strings.Fields(rest), e.Host) {
			found = append(found, sc)
		}
	}
	if len(found) != 1 {
		return section{}, false
	}
	sc := found[0]
	if _, rest := keyword(lines[sc.start]); rest != e.Host {
		return section{}, false // also matches other hosts
	}
	want := map[string]bool{}
	for _, k := range e.Keys {
		want[k.Path] = true
	}
	for _, l := range lines[sc.start+1 : sc.end+1] {
		kw, rest := keyword(l)
		switch kw {
		case "", "identitiesonly":
		case "user":
			if rest != e.User() {
				return section{}, false
			}
		case "identityfile":
			p := strings.Trim(rest, `"`)
			if r, ok := strings.CutPrefix(p, "~/"); ok {
				p = filepath.Join(home, r)
			}
			if !want[p] {
				return section{}, false
			}
		default:
			return section{}, false
		}
	}
	return sc, true
}

// allowedInBlock are the only keywords yking writes inside its blocks.
var allowedInBlock = map[string]bool{"host": true, "user": true, "identityfile": true, "identitiesonly": true}

// ValidateConfig is the plan validator for ~/.ssh/config: markers must be
// balanced and yking's blocks may only hold Host (its own host), User,
// IdentityFile and IdentitiesOnly.
func ValidateConfig(path string, content []byte) error {
	if filepath.Base(path) != "config" {
		return fmt.Errorf("yking does not write %s", path)
	}
	s := string(content)
	if strings.ContainsRune(s, 0) {
		return errors.New("NUL byte in config")
	}
	blocks, err := ParseManaged(s)
	if err != nil {
		return err
	}
	lines := splitLines(s)
	for _, m := range blocks {
		hostLines := 0
		for _, l := range lines[m.Start+1 : m.End] {
			kw, rest := keyword(l)
			if kw == "" {
				continue
			}
			if !allowedInBlock[kw] {
				return fmt.Errorf("yking block %s: %q not allowed", m.Host, kw)
			}
			if kw == "host" {
				if hostLines++; hostLines > 1 || rest != m.Host {
					return fmt.Errorf("yking block %s: unexpected Host line", m.Host)
				}
			}
		}
		if hostLines != 1 {
			return fmt.Errorf("yking block %s: missing Host line", m.Host)
		}
	}
	return nil
}

// ConfigPlan makes the plan bringing path's managed block for e.Host in
// line with e (removing it when e has no key files). Notes explain what the
// user should know before applying. Returns plan.ErrNoChanges when the
// file already matches.
func ConfigPlan(path, home string, e HostEntry, now time.Time) (*plan.Plan, []string, error) {
	base, err := plan.ReadBase(path)
	if err != nil {
		return nil, nil, err
	}
	if base.Exists {
		fi, err := os.Lstat(path)
		if err != nil {
			return nil, nil, err
		}
		if !fi.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("%s is not a regular file (symlink?); yking will not edit it", path)
		}
	}
	block, err := e.Block(home)
	if err != nil {
		return nil, nil, err
	}
	old := string(base.Data)
	managed, err := ParseManaged(old)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	hasBlock := slices.ContainsFunc(managed, func(m Managed) bool { return m.Host == e.Host })
	var content string
	adopted := -1
	if sc, ok := adoptable(old, e, home); ok && !hasBlock && block != "" {
		lines := splitLines(old)
		content = joinLines(slices.Concat(lines[:sc.start], splitLines(block), lines[sc.end+1:]))
		adopted = sc.start + 1
	} else if content, err = SetBlock(old, e.Host, block); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if content == string(base.Data) {
		return nil, nil, plan.ErrNoChanges
	}
	if err := ValidateConfig(path, []byte(content)); err != nil {
		return nil, nil, err
	}
	mode := fs.FileMode(0o600)
	if base.Exists {
		if fi, err := os.Stat(path); err == nil {
			mode = fi.Mode().Perm() &^ 0o022
		}
	}
	desc := "SSH config: Host " + e.Host
	if block == "" {
		desc = "SSH config: remove yking's Host " + e.Host + " (no key files left)"
	}
	p := plan.New(desc, now)
	p.Replace(base, []byte(content), mode)
	return p, configNotes(old, content, e, block != "", adopted), nil
}

func configNotes(old, content string, e HostEntry, adding bool, adopted int) []string {
	var n []string
	if !adding {
		return n
	}
	if adopted > 0 {
		n = append(n, fmt.Sprintf("Your own Host %s section (line %d) only had settings yking manages; it is replaced by yking's block, nothing is lost.", e.Host, adopted))
	}
	if len(e.Users) > 1 {
		n = append(n, "Several logins are recorded for "+e.Host+" ("+strings.Join(e.Users, ", ")+"), so no User line: use ssh user@"+e.Host+".")
	}
	for _, k := range e.Missing {
		n = append(n, fmt.Sprintf("%s (%s) is recorded for %s but its key file is not on this machine; left out.", or(k.Comment, k.Fingerprint), k.Label, e.Host))
	}
	if own := OwnHostLines(content, e.Host); len(own) > 0 {
		n = append(n, fmt.Sprintf("Your own Host %s section (now line %v) is kept: it has other settings or keys. Both apply; for each option ssh uses the first value, i.e. yking's, and IdentityFile lines add up.", e.Host, own))
	}
	if len(e.Keys) > 1 && slices.ContainsFunc(e.Keys, func(k HostKey) bool { return k.PIN }) {
		n = append(n, "With several keys listed, ssh may ask for a PIN naming another key's file: always type the PIN of the YubiKey that is plugged in (it only answers for its own key; the next file is tried).")
	}
	if w := VerifyConfig(content, e); len(w) > 0 {
		n = append(n, w...)
	}
	return n
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

var matchExecRe = regexp.MustCompile(`(?im)^\s*match\b.*\bexec\b`)

// VerifyConfig asks ssh how it would resolve the host with content as the
// config (`ssh -G`, no connection) and reports where that differs from
// what yking intends — e.g. an earlier Include or "Host *" overriding it.
// Skipped for configs with "Match exec" (ssh would run those commands).
func VerifyConfig(content string, e HostEntry) []string {
	if matchExecRe.MatchString(content) {
		return []string{"Not checked with ssh -G: your config uses Match exec."}
	}
	tmp, err := os.CreateTemp("", "yking-ssh-config-*")
	if err != nil {
		return nil
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(content)
	tmp.Close()
	target := e.Host
	if u := e.User(); u != "" {
		target = u + "@" + e.Host
	}
	out, err := exec.Command(SSHBinary, "-G", "-F", tmp.Name(), "--", target).Output()
	if err != nil {
		return []string{"ssh -G rejected the new config: " + err.Error()}
	}
	return checkResolved(string(out), e)
}

func checkResolved(out string, e HostEntry) []string {
	home, _ := os.UserHomeDir()
	expand := func(p string) string {
		p = strings.Trim(p, `"`)
		if rest, ok := strings.CutPrefix(p, "~/"); ok {
			return filepath.Join(home, rest)
		}
		return p
	}
	got := map[string]bool{}
	var w []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		kw, val, _ := strings.Cut(sc.Text(), " ")
		switch kw {
		case "identityfile":
			got[expand(val)] = true
		case "identitiesonly":
			if val != "yes" {
				w = append(w, "ssh resolves IdentitiesOnly="+val+" for "+e.Host+" (set earlier in your config); other keys will be offered too.")
			}
		case "user":
			if u := e.User(); u != "" && val != u {
				w = append(w, "ssh resolves User="+val+" for "+e.Host+" (set earlier in your config), not "+u+".")
			}
		}
	}
	for _, k := range e.Keys {
		if !got[k.Path] {
			w = append(w, "ssh does not pick up "+k.Path+" for "+e.Host+".")
		}
	}
	return w
}

// BlockState compares the config file with what yking would write.
type BlockState int

const (
	BlockAbsent  BlockState = iota // no yking block
	BlockCurrent                   // block matches
	BlockStale                     // block differs from the keyring
)

func (s BlockState) String() string {
	switch s {
	case BlockCurrent:
		return "up to date"
	case BlockStale:
		return "out of date (enter updates)"
	}
	return "no yking block (enter adds)"
}

// ConfigState reports each host's block state and the hosts that have a
// yking block but nothing in the keyring any more.
func ConfigState(cfg, home string, entries []HostEntry) (map[string]BlockState, []string, error) {
	blocks, err := ParseManaged(cfg)
	if err != nil {
		return nil, nil, err
	}
	lines := splitLines(cfg)
	have := map[string]string{}
	for _, m := range blocks {
		have[m.Host] = joinLines(lines[m.Start : m.End+1])
	}
	st := map[string]BlockState{}
	for _, e := range entries {
		cur, ok := have[e.Host]
		want, err := e.Block(home)
		switch {
		case err != nil:
			return nil, nil, err
		case !ok:
			st[e.Host] = BlockAbsent
		case cur == want:
			st[e.Host] = BlockCurrent
		default:
			st[e.Host] = BlockStale
		}
		delete(have, e.Host)
	}
	var orphans []string
	for h := range have {
		orphans = append(orphans, h)
	}
	slices.Sort(orphans)
	return st, orphans, nil
}

// LoginUser is the user ssh would log in as for host ("ssh -G", no
// connection): the User from the ssh config, else the local name. "" when
// unknown, or when an ssh config uses "Match exec" (resolving would run
// those commands).
func LoginUser(host string) string { return loginUser(host, "") }

// loginUser with configFile != "" reads only that file (ssh -F; tests).
func loginUser(host, configFile string) string {
	if strings.Contains(host, "@") || ValidTarget(host) != nil {
		return ""
	}
	var files []string
	if configFile != "" {
		files = []string{configFile}
	} else {
		home, _ := os.UserHomeDir()
		files = []string{ConfigPath(home), "/etc/ssh/ssh_config"}
		if more, err := filepath.Glob("/etc/ssh/ssh_config.d/*.conf"); err == nil {
			files = append(files, more...)
		}
	}
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && matchExecRe.Match(b) {
			return ""
		}
	}
	args := []string{"-G"}
	if configFile != "" {
		args = append(args, "-F", configFile)
	}
	out, err := exec.Command(SSHBinary, append(args, "--", host)...).Output()
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(out), "\n") {
		if u, ok := strings.CutPrefix(l, "user "); ok {
			return strings.TrimSpace(u)
		}
	}
	return ""
}
