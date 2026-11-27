// Package doctor checks the whole yking setup for problems. It only reads.
package doctor

import (
	"fmt"
	"github.com/licentiapoetica/yking/internal/deps"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/sshkey"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// Severity of a finding.
type Severity int

const (
	OK Severity = iota
	Info
	Warn
	Error
)

func (s Severity) String() string { return [...]string{"ok", "info", "warn", "error"}[s] }

// Finding is one result.
type Finding struct {
	Severity Severity
	Area     string // KEYS, PAM, SSH, EVENTS, FILES
	Message  string
	Fix      string // what to do, if anything
}

// File is a file's name and mode (for permission checks).
type File struct {
	Path string
	Mode fs.FileMode
}

// Events describes the plug/unplug installation.
type Events struct {
	Configured      bool
	LockOnRemove    bool
	BinaryInstalled bool
	BinaryCurrent   bool
	RuleExists      bool
	RuleCurrent     bool
	UnitExists      bool
	UnitCurrent     bool
}

// PAMWrite is the last yking write of a PAM file (from apply history).
type PAMWrite struct {
	Path          string
	WrittenSHA256 string
	CurrentSHA256 string // "" if the file is gone
}

// Inputs is everything the checks look at.
type Inputs struct {
	Now             time.Time
	User            string
	Keyring         *keyring.Keyring
	Mapping         *pam.Mapping
	MappingPath     string
	MappingMode     fs.FileMode // 0 if missing
	PAM             []pam.State
	PAMWrites       []PAMWrite
	ModuleInstalled bool
	Events          Events
	SSHDir          File
	SSHFiles        []File
	Untracked       []sshkey.PubKey
	Connected       []detect.KeyReport
	Tests           map[string]time.Time // serial → last key test
	BootPending     string               // id of an interrupted boot change
	PolkitAsksRoot  bool
	Deps            []deps.Problem // missing tools and services
}

// TestEvery is how often every key — especially the one in the drawer —
// should be tested.
const TestEvery = 90 * 24 * time.Hour

// Run performs every check. Findings are sorted most severe first.
func Run(in Inputs) []Finding {
	var f []Finding
	add := func(sev Severity, area, msg, fix string) {
		f = append(f, Finding{sev, area, msg, fix})
	}
	kr := in.Keyring
	if kr == nil {
		kr = keyring.New()
	}
	cov := pam.Coverage(kr, in.Mapping, in.User)

	// --- tools
	for _, p := range in.Deps {
		sev := Warn
		if p.Required {
			sev = Error
		}
		add(sev, "TOOLS", p.What+" — "+p.For, p.Fix)
	}
	if len(in.Deps) == 0 {
		add(OK, "TOOLS", "tools and services present", "")
	}

	// --- keys
	switch n := len(kr.Keys); {
	case n == 0:
		add(Error, "KEYS", "no key registered", "register your keys (e)")
	case n == 1:
		add(Warn, "KEYS", "only one key registered — losing it would lock you out of everything set to use the key", "register a second key (e)")
	default:
		add(OK, "KEYS", fmt.Sprintf("%d keys registered", n), "")
	}
	roles := map[keyring.Role]bool{}
	for _, k := range kr.Keys {
		roles[k.Role] = true
	}
	if len(kr.Keys) >= 2 && !roles[keyring.RoleOffsite] {
		add(Info, "KEYS", "no key has the offsite role — a fire or burglary could take all keys at once", "")
	}
	for _, k := range kr.Keys {
		last, tested := in.Tests[k.Serial]
		switch {
		case !tested:
			add(Info, "KEYS", fmt.Sprintf("%q has never been tested with yking", k.Label), "plug it in alone and press t")
		case in.Now.Sub(last) > TestEvery:
			sev := Info
			if k.Role != keyring.RoleDaily {
				sev = Warn // the one in the drawer is the one that silently breaks
			}
			add(sev, "KEYS", fmt.Sprintf("%q last tested %s (%d days ago)", k.Label, last.Local().Format("2006-01-02"), int(in.Now.Sub(last).Hours()/24)), "plug it in alone and press t")
		}
	}
	for _, c := range in.Connected {
		if c.FIDO == nil {
			continue
		}
		name := c.Serial
		if c.Known != nil {
			name = c.Known.Label
		}
		switch {
		case c.FIDO.PINBlocked:
			add(Error, "KEYS", fmt.Sprintf("%q: FIDO2 PIN is BLOCKED", name), "only a FIDO reset helps, which wipes the key's registrations — yking never does that")
		case c.FIDO.PINSet && c.FIDO.PINRetries >= 0 && c.FIDO.PINRetries < ykman.MinPINRetriesToPrompt:
			add(Error, "KEYS", fmt.Sprintf("%q: only %d PIN tries left", name, c.FIDO.PINRetries), "enter the correct PIN once anywhere (e.g. sudo) to reset the counter to 8")
		case c.FIDO.PINSet && c.FIDO.PINRetries >= 0 && c.FIDO.PINRetries < 8:
			add(Warn, "KEYS", fmt.Sprintf("%q: %d of 8 PIN tries left (a wrong PIN was entered)", name, c.FIDO.PINRetries), "one correct PIN entry resets it to 8")
		}
	}

	// --- pam
	keyServices := []string{}
	for _, st := range in.PAM {
		if st.Custom != "" {
			add(Warn, "PAM", fmt.Sprintf("%s: pam_u2f setup yking does not understand (%s)", st.Service.Name, st.Custom), "check "+st.Path+" by hand")
		}
		if st.Current.Mode == pam.ModeOnly || st.Current.Mode == pam.ModeAnd {
			keyServices = append(keyServices, st.Service.Name)
		}
		if st.Current.Mode != pam.ModeOff && !st.Managed && st.Custom == "" {
			add(Info, "PAM", st.Service.Name+": hand-written pam_u2f line", "take it over on the PAM screen (p)")
		}
	}
	if len(in.PAM) > 0 {
		anyOn := false
		for _, st := range in.PAM {
			if st.Current.Mode != pam.ModeOff {
				anyOn = true
			}
		}
		if anyOn && !in.ModuleInstalled {
			add(Error, "PAM", "pam_u2f.so is not installed but PAM services use it", "install pam-u2f")
		}
	}
	if len(keyServices) > 0 {
		var conf []string
		for _, k := range kr.Keys {
			if cov[k.Serial] {
				conf = append(conf, k.Label)
			}
		}
		switch {
		case len(conf) == 0:
			add(Error, "PAM", fmt.Sprintf("%s need the key, but NO key is confirmed to work", strings.Join(keyServices, ", ")), "check each key (c)")
		case len(conf) < 2:
			add(Warn, "PAM", fmt.Sprintf("%s need the key; only %s is confirmed", strings.Join(keyServices, ", "), strings.Join(conf, ", ")), "check your other keys (c)")
		default:
			add(OK, "PAM", fmt.Sprintf("key-only services work with %d keys: %s", len(conf), strings.Join(conf, ", ")), "")
		}
		passwordDoor := false
		for _, st := range in.PAM {
			if st.Service.LoginPath && st.Current.Mode.PasswordWorks() {
				passwordDoor = true
			}
		}
		if !passwordDoor {
			add(Error, "PAM", "no login path accepts the password alone any more", "set the text console to \"key or password\" (p)")
		}
	}
	for _, w := range in.PAMWrites {
		switch {
		case w.CurrentSHA256 == "":
			add(Warn, "PAM", w.Path+" was removed after yking wrote it", "")
		case w.CurrentSHA256 != w.WrittenSHA256:
			add(Warn, "PAM", w.Path+" was changed after yking wrote it (package update or hand edit)", "review it on the PAM screen (p)")
		}
	}

	// --- mapping
	if in.MappingMode != 0 && in.MappingMode&0o022 != 0 {
		add(Error, "FILES", fmt.Sprintf("%s is writable by others (%04o) — anyone could add a key", in.MappingPath, in.MappingMode.Perm()), "chmod 644 "+in.MappingPath)
	}
	if in.Mapping != nil {
		recorded := map[string]string{}
		for _, k := range kr.Keys {
			for _, c := range k.U2F {
				if c.User == in.User {
					recorded[c.KeyHandle] = k.Label
				}
			}
		}
		inMap := map[string]bool{}
		for i, c := range in.Mapping.Creds(in.User) {
			inMap[c.KeyHandle] = true
			if _, ok := recorded[c.KeyHandle]; !ok {
				add(Warn, "PAM", fmt.Sprintf("PAM credential #%d belongs to no registered key", i+1), "check each key (c); if none owns it, a lost or unknown key does — remove it with revoke (x)")
			}
		}
		for h, label := range recorded {
			if !inMap[h] {
				add(Warn, "PAM", fmt.Sprintf("a credential recorded for %q is no longer in the mapping", label), "check the key (c) and add one if needed")
			}
		}
	}

	// --- ssh
	if in.SSHDir.Mode != 0 && in.SSHDir.Mode&0o022 != 0 {
		add(Error, "FILES", fmt.Sprintf("%s is writable by others (%04o)", in.SSHDir.Path, in.SSHDir.Mode.Perm()), "chmod 700 "+in.SSHDir.Path)
	}
	for _, file := range in.SSHFiles {
		name := file.Path
		switch {
		case strings.HasSuffix(name, ".pub") || strings.HasSuffix(name, "/known_hosts") || strings.HasSuffix(name, "/config"):
			if file.Mode&0o022 != 0 {
				add(Warn, "FILES", fmt.Sprintf("%s is writable by others (%04o)", name, file.Mode.Perm()), "chmod 644 "+name)
			}
		case strings.HasSuffix(name, "/authorized_keys"):
			if file.Mode&0o022 != 0 {
				add(Error, "FILES", fmt.Sprintf("%s is writable by others (%04o) — anyone could add a login key", name, file.Mode.Perm()), "chmod 600 "+name)
			}
		default: // private keys and handles
			if file.Mode&0o077 != 0 {
				add(Warn, "FILES", fmt.Sprintf("%s is readable by others (%04o)", name, file.Mode.Perm()), "chmod 600 "+name)
			}
		}
	}
	for _, p := range in.Untracked {
		add(Info, "SSH", fmt.Sprintf("%s comes from a security key but is not linked to a registered key", p.Path), "select its key and press l")
	}
	hostKeys := map[string][]string{}
	for _, k := range kr.Keys {
		for _, s := range k.SSH {
			for _, h := range s.Hosts {
				if !contains(hostKeys[h], k.Label) {
					hostKeys[h] = append(hostKeys[h], k.Label)
				}
			}
		}
	}
	var hosts []string
	for h := range hostKeys {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		if len(hostKeys[h]) < 2 {
			add(Warn, "SSH", fmt.Sprintf("%s accepts only %q (as far as yking knows)", h, hostKeys[h][0]), "deploy another key's SSH key there (d)")
		}
	}
	for _, r := range kr.Revoked {
		for _, l := range r.Leftovers {
			add(Warn, "SSH", fmt.Sprintf("revoked key %q: %s is still on %s", r.Label, l.Comment, l.Host), "remove that line from the server's authorized_keys")
		}
	}

	// --- interrupted boot change
	if in.BootPending != "" {
		add(Error, "BOOT", "boot change "+in.BootPending+" was interrupted before the images were rebuilt and verified", "sudo yking luks repair — before rebooting")
	}

	// --- polkit asks root, but polkit is key-only
	if in.PolkitAsksRoot {
		for _, st := range in.PAM {
			if st.Service.Name == "polkit-1" && (st.Current.Mode == pam.ModeOnly || st.Current.Mode == pam.ModeAnd) {
				add(Error, "PAM", "admin prompts (polkit) ask for ROOT, who has no key credential — they fail instantly (e.g. Flatpak installs)",
					"add yourself to wheel (sudo usermod -aG wheel $USER, log in again) or set polkit to \"key or password\" (p)")
			}
		}
	}

	// --- lock screen lockout
	for _, st := range in.PAM {
		if !st.LockoutRisk() {
			continue
		}
		sev, msg := Warn, st.Service.Desc+" fails at once when the key is not plugged in (no pam_u2f \"interactive\")"
		if in.Events.Configured && in.Events.LockOnRemove {
			sev, msg = Error, st.Service.Desc+" + \"lock when the key is pulled\" = you cannot unlock after pulling the key (the lock screen never prompts again)"
		}
		add(sev, "PAM", msg, "PAM screen (p) → Enter → apply: yking adds \"interactive\". Way out meanwhile: Ctrl+Alt+F2, log in, loginctl unlock-sessions")
	}
	for _, st := range in.PAM {
		if st.Service.LockScreen && st.Current.Mode == pam.ModeOnly && !st.LockoutRisk() {
			add(Info, "PAM", st.Service.Desc+" is key only", "if it ever refuses: Ctrl+Alt+F2, log in, loginctl unlock-sessions")
		}
	}

	// --- events
	if e := in.Events; e.Configured {
		switch {
		case !e.BinaryInstalled:
			add(Error, "EVENTS", "plug/unplug actions are configured but /usr/local/bin/yking is missing", "re-apply on the plug/unplug screen (u)")
		case !e.BinaryCurrent:
			add(Warn, "EVENTS", "/usr/local/bin/yking is older than this yking", "re-apply on the plug/unplug screen (u)")
		}
		if !e.RuleExists || !e.UnitExists {
			add(Error, "EVENTS", "udev rule or systemd unit missing — plug/unplug actions will not run", "re-apply (u)")
		} else if !e.RuleCurrent || !e.UnitCurrent {
			add(Warn, "EVENTS", "udev rule or systemd unit differs from what yking generates", "re-apply (u)")
		}
	}

	sort.SliceStable(f, func(i, j int) bool { return f[i].Severity > f[j].Severity })
	return f
}

// Row is one key in the coverage table.
type Row struct {
	Label, Role, Serial string
	PAM                 bool
	SSHKeys             int
	Hosts               []string
	Connected           bool
	LastTest            time.Time
}

// Coverage builds the per-key table.
func Coverage(in Inputs) []Row {
	kr := in.Keyring
	if kr == nil {
		return nil
	}
	cov := pam.Coverage(kr, in.Mapping, in.User)
	conn := map[string]bool{}
	for _, c := range in.Connected {
		conn[c.Serial] = true
	}
	var rows []Row
	for _, k := range kr.Keys {
		r := Row{Label: k.Label, Role: string(k.Role), Serial: k.Serial, PAM: cov[k.Serial], SSHKeys: len(k.SSH), Connected: conn[k.Serial], LastTest: in.Tests[k.Serial]}
		for _, s := range k.SSH {
			for _, h := range s.Hosts {
				if !contains(r.Hosts, h) {
					r.Hosts = append(r.Hosts, h)
				}
			}
		}
		rows = append(rows, r)
	}
	return rows
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Worst returns the highest severity.
func Worst(f []Finding) Severity {
	w := OK
	for _, x := range f {
		if x.Severity > w {
			w = x.Severity
		}
	}
	return w
}
