package tui

import (
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
)

type pamScreen struct {
	states    []pam.State
	desired   []pam.Config
	takeover  bool // replace hand-written pam_u2f lines with yking ones
	cursor    int
	facts     pam.Facts
	mapping   string
	confirmed []string // labels of keys with a confirmed credential
	blocks    []string
	warns     []string
	err       string
}

// newPAMScreen reads the PAM services and the keyring fresh from disk, so
// the safety facts never depend on an earlier (possibly unfinished) scan.
func newPAMScreen(krPath string) pamScreen {
	s := pamScreen{takeover: true}
	registeredKeys, confirmed := 0, 0
	if kr, err := keyring.Load(krPath); err != nil {
		s.err = "reading keyring: " + err.Error()
	} else {
		registeredKeys = len(kr.Keys)
		if mp, _, err := readMapping(); err == nil {
			for _, k := range kr.Keys {
				if pam.Coverage(kr, mp, currentUser())[k.Serial] {
					confirmed++
					s.confirmed = append(s.confirmed, k.Label)
				}
			}
		}
	}
	sts, err := pam.Discover(pam.EtcDir, pam.VendorDir)
	if err != nil {
		s.err = err.Error()
		return s
	}
	s.states = sts
	// Services that are off start with the unlock the others already use.
	counts := map[pam.Unlock]int{}
	for _, st := range sts {
		if st.Current.Mode != pam.ModeOff {
			counts[st.Current.Unlock]++
		}
	}
	common := pam.UnlockPINTouch
	for _, u := range pam.Unlocks {
		if counts[u] > counts[common] {
			common = u
		}
	}
	for _, st := range sts {
		d := st.Current
		if d.Mode == pam.ModeOff {
			d.Unlock = common
		}
		s.desired = append(s.desired, d)
	}
	home, _ := os.UserHomeDir()
	s.mapping = pam.DefaultMappingPath(home)
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	creds, err := pam.CountCredentials(s.mapping, uname)
	if err != nil {
		s.err = "reading " + s.mapping + ": " + err.Error()
	}
	s.facts = pam.Facts{ModuleInstalled: pam.ModuleExists("pam_u2f.so"), Credentials: creds, RegisteredKeys: registeredKeys, ConfirmedKeys: confirmed}
	s.recheck()
	return s
}

// changes lists what differs from the current state.
func (s pamScreen) changes() []pam.Change {
	var out []pam.Change
	for i, st := range s.states {
		if st.Custom != "" {
			continue
		}
		want, cur := s.desired[i], st.Current
		// A lock screen without "interactive" is always fixed (lockout risk).
		differs := !sameBehaviour(want, cur) || (st.LockoutRisk() && want.Mode != pam.ModeOff)
		adopt := s.takeover && !st.Managed && cur.Mode != pam.ModeOff && want.Mode != pam.ModeOff
		if differs || adopt {
			out = append(out, pam.Change{Service: st.Service.Name, To: want})
		}
	}
	return out
}

func (s *pamScreen) recheck() {
	s.blocks, s.warns = pam.Check(s.states, s.changes(), s.facts)
}

func (m model) updatePAM(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	s := &m.pam
	if len(s.states) == 0 {
		if key.String() == "esc" || key.String() == "q" {
			m.mode = modeKeys
		}
		return m, nil
	}
	st := s.states[s.cursor]
	d := &s.desired[s.cursor]
	switch key.String() {
	case "esc", "q":
		m.mode = modeKeys
		return m, nil
	case "up", "k":
		s.cursor = max(s.cursor-1, 0)
	case "down", "j":
		s.cursor = min(s.cursor+1, len(s.states)-1)
	case "right", "l":
		if st.Custom == "" {
			d.Mode = pam.Modes[(int(d.Mode)+1)%len(pam.Modes)]
		}
	case "left", "h":
		if st.Custom == "" {
			n := len(pam.Modes)
			d.Mode = pam.Modes[(int(d.Mode)+n-1)%n]
		}
	case "u":
		if st.Custom == "" {
			d.Unlock = pam.Unlocks[(int(d.Unlock)+1)%len(pam.Unlocks)]
		}
	case "t":
		s.takeover = !s.takeover
	case "r": // reset this service to its current state
		*d = st.Current
	case "enter":
		return m.buildPAMPlan()
	}
	s.recheck()
	return m, nil
}

func (m model) buildPAMPlan() (tea.Model, tea.Cmd) {
	s := &m.pam
	s.err = ""
	if len(s.blocks) > 0 {
		s.err = "Fix the blocking problems first."
		return m, nil
	}
	ch := s.changes()
	if len(ch) == 0 {
		s.err = "Nothing to change."
		return m, nil
	}
	// Re-read from disk so the plan's preconditions are exact.
	fresh, err := pam.Discover(pam.EtcDir, pam.VendorDir)
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	if b, _ := pam.Check(fresh, ch, s.facts); len(b) > 0 {
		s.err = "PAM files changed on disk; press esc and reopen (p)."
		return m, nil
	}
	p, err := pam.BuildPlan(fresh, ch, time.Now())
	if err == nil {
		m.review, err = newReview(p)
	}
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	m.review.note = "PAM change: after applying, yking tests sudo and waits for you to type keep (3 min). Otherwise it rolls back by itself."
	m.reviewBack = modePAM
	m.mode = modeReview
	return m, nil
}

func (s pamScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("PAM — where the YubiKey can be used") + "\n")
	b.WriteString(dimStyle.Render("Host-side only (/etc/pam.d). Nothing is written to a key.") + "\n\n")
	if len(s.states) == 0 {
		b.WriteString(errStyle.Render("No PAM services found. "+s.err) + "\n")
		return b.String()
	}

	fmt.Fprintf(&b, "  %s %s %s\n", dimStyle.Render(pad("Service", 40)), dimStyle.Render(pad("Now", 32)), dimStyle.Render("New"))
	for i, st := range s.states {
		cur := st.Current.String()
		next := s.desired[i].String()
		tag := ""
		switch {
		case st.Custom != "":
			cur, next = "custom", errStyle.Render("not managed: "+st.Custom)
		case st.LockoutRisk() && s.desired[i].Mode != pam.ModeOff:
			next = warnStyle.Render(next + " + waits for the key")
			tag = errStyle.Render(" ← fixes a lockout risk")
		case sameBehaviour(s.desired[i], st.Current):
			next = dimStyle.Render(next + " (unchanged)")
			if s.takeover && !st.Managed && st.Current.Mode != pam.ModeOff {
				tag = warnStyle.Render(" (hand-written → taken over)")
			}
		default:
			next = selStyle.Render(next)
		}
		if !st.Managed && st.Current.Mode != pam.ModeOff && st.Custom == "" {
			cur += " *"
		}
		line := pad(st.Service.Desc, 40) + " " + pad(cur, 32) + " " + next + tag
		if i == s.cursor {
			b.WriteString(selStyle.Render("▸ ") + line + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	b.WriteString(dimStyle.Render("  * = hand-written line") + "\n\n")

	cur := s.states[s.cursor]
	b.WriteString(dimStyle.Render(fmt.Sprintf("%s → %s", cur.Service.Name, cur.Path)))
	if cur.Source != cur.Path {
		b.WriteString(dimStyle.Render(" (now from " + cur.Source + ")"))
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(modeHelp(s.desired[s.cursor].Mode)) + "\n")
	if cur.Service.LockScreen && s.desired[s.cursor].Mode != pam.ModeOff {
		b.WriteString(dimStyle.Render("Lock screen: yking adds pam_u2f \"interactive\" — it asks \"Insert your FIDO authenticator, then press ENTER\"\n"+
			"instead of failing at once when the key is not plugged in (otherwise KDE never prompts again).") + "\n")
	}
	if cur.Service.LockScreen && s.desired[s.cursor].Mode == pam.ModeOnly {
		b.WriteString(dimStyle.Render("Emergency exit if the lock screen ever refuses: Ctrl+Alt+F2, log in, `loginctl unlock-sessions`.") + "\n")
	}
	b.WriteString("\n")

	take := "yes"
	if !s.takeover {
		take = "no"
	}
	conf := "none — check each key on the main screen (c)"
	if len(s.confirmed) > 0 {
		conf = strings.Join(s.confirmed, ", ")
	}
	b.WriteString(dimStyle.Render(fmt.Sprintf("Mapping %s: %d credential(s) · keyring: %d key(s) registered · take over hand-written lines: %s",
		tildePath(s.mapping), s.facts.Credentials, s.facts.RegisteredKeys, take)) + "\n")
	b.WriteString(dimStyle.Render("Keys confirmed to work with PAM: "+conf) + "\n")

	for _, w := range s.warns {
		b.WriteString("\n" + warnStyle.Render("! "+w) + "\n")
	}
	for _, e := range s.blocks {
		b.WriteString("\n" + errStyle.Render("✗ "+e) + "\n")
	}
	if s.err != "" {
		b.WriteString(errStyle.Render(s.err) + "\n")
	}
	return b.String()
}

func modeHelp(m pam.Mode) string {
	switch m {
	case pam.ModeOr:
		return "key or password: use the key, or type the password if the key is not there."
	case pam.ModeAnd:
		return "password + key: type the password AND use the key (two-factor)."
	case pam.ModeOnly:
		return "key only: the password is never asked. Losing the key locks you out of this service."
	default:
		return "off: password only, as without yking."
	}
}

// sameBehaviour compares what a config does (Extra args are carried over).
func sameBehaviour(a, b pam.Config) bool {
	if a.Mode == pam.ModeOff && b.Mode == pam.ModeOff {
		return true
	}
	return a.Mode == b.Mode && a.Unlock == b.Unlock
}

// pad pads or truncates plain text to n display columns.
func pad(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s + strings.Repeat(" ", n-len(r))
}
