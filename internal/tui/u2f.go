package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pam"
	"github.com/licentiapoetica/yking/internal/plan"
)

// u2fScreen checks whether a key has a PAM credential in the user's
// mapping (silent probe: no touch, no PIN) and can add one (pamu2fcfg,
// one touch).
type u2fScreen struct {
	key    detect.KeyReport
	busy   string
	res    *u2fResult
	err    string
	notice string
}

type u2fResult struct {
	user      string
	total     int      // credentials of user in the mapping
	matched   []int    // 1-based positions that are on this key
	handles   []string // their key handles
	recorded  bool     // all matches already recorded in the keyring
	otherKeys []int    // positions recorded on other registered keys
}

type u2fCheckMsg struct {
	res *u2fResult
	err error
}

type u2fRegDoneMsg struct {
	out []byte
	err error
}

type u2fVerifiedMsg struct {
	cred pam.Cred
	err  error
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func mappingPath() string {
	home, _ := os.UserHomeDir()
	return pam.DefaultMappingPath(home)
}

func readMapping() (*pam.Mapping, plan.Base, error) {
	base, err := plan.ReadBase(mappingPath())
	if err != nil {
		return nil, base, err
	}
	m, err := pam.ParseMapping(string(base.Data))
	return m, base, err
}

// singleKeyDevice makes sure exactly one FIDO device is connected and it is
// serial; returns its /dev path.
func (m model) singleKeyDevice(ctx context.Context, serial string) (string, error) {
	devs, err := fido.Devices(fido.DefaultSysRoot)
	if err != nil {
		return "", err
	}
	serials, err := m.cfg.Client.ListSerials(ctx)
	if err != nil {
		return "", err
	}
	all, err := m.cfg.Client.ListDevices(ctx)
	if err != nil {
		return "", err
	}
	if len(devs) != 1 || len(serials) != 1 || serials[0] != serial || len(all) != 1 {
		return "", fmt.Errorf("plug in ONLY key %s (now: %d FIDO device(s), serials %v) — with several keys yking cannot tell which one answered", serial, len(devs), serials)
	}
	return devs[0], nil
}

func (m model) u2fCheck(serial string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		dev, err := m.singleKeyDevice(ctx, serial)
		if err != nil {
			return u2fCheckMsg{err: err}
		}
		mp, _, err := readMapping()
		if err != nil {
			return u2fCheckMsg{err: fmt.Errorf("%s: %w", tildePath(mappingPath()), err)}
		}
		origin, err := pam.Origin()
		if err != nil {
			return u2fCheckMsg{err: err}
		}
		kr, err := keyring.Load(m.cfg.KeyringPath)
		if err != nil {
			return u2fCheckMsg{err: err}
		}
		res := &u2fResult{user: currentUser()}
		creds := mp.Creds(res.user)
		res.total = len(creds)
		owner := map[string]string{} // handle → serial recorded
		for _, k := range kr.Keys {
			for _, c := range k.U2F {
				if c.User == res.user {
					owner[c.KeyHandle] = k.Serial
				}
			}
		}
		for i, c := range creds {
			err := fido.Probe(ctx, dev, origin, c.KeyHandle)
			switch {
			case err == nil:
				res.matched = append(res.matched, i+1)
				res.handles = append(res.handles, c.KeyHandle)
			case errors.Is(err, fido.ErrNotThisKey):
				if s, ok := owner[c.KeyHandle]; ok && s != serial {
					res.otherKeys = append(res.otherKeys, i+1)
				}
			default:
				return u2fCheckMsg{err: err}
			}
		}
		res.recorded = len(res.handles) > 0
		for _, h := range res.handles {
			if owner[h] != serial {
				res.recorded = false
			}
		}
		return u2fCheckMsg{res: res}
	}
}

func (m model) updateU2F(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.u2f
	switch msg := msg.(type) {
	case u2fCheckMsg:
		s.busy = ""
		s.res, s.err = msg.res, ""
		if msg.err != nil {
			s.err = msg.err.Error()
		}
		return m, nil
	case u2fRegDoneMsg:
		if msg.err != nil {
			s.busy = ""
			s.err = "pamu2fcfg did not finish: " + msg.err.Error() + ". Nothing was changed."
			return m, nil
		}
		cred, err := pam.ParseRegisterOutput(msg.out)
		if err != nil {
			s.busy = ""
			s.err = err.Error()
			return m, nil
		}
		s.busy = "Verifying the new credential on the key…"
		return m, m.u2fVerify(s.key.Serial, cred)
	case u2fVerifiedMsg:
		s.busy = ""
		if msg.err != nil {
			s.err = "new credential could not be verified, nothing was changed: " + msg.err.Error()
			return m, nil
		}
		return m.u2fAddPlans(msg.cred)
	case tea.KeyMsg:
		if s.busy != "" {
			return m, nil
		}
		switch msg.String() {
		case "esc", "q":
			m.mode = modeKeys
			return m, nil
		case "r":
			s.busy, s.err = "Checking…", ""
			return m, m.u2fCheck(s.key.Serial)
		case "enter":
			if s.res != nil && len(s.res.handles) > 0 && !s.res.recorded {
				return m.u2fRecordPlan()
			}
		case "a":
			if s.res != nil && len(s.res.matched) == 0 {
				return m.u2fRegister()
			}
		}
	}
	return m, nil
}

func (m model) u2fRecordPlan() (tea.Model, tea.Cmd) {
	s := &m.u2f
	p, err := pam.RecordCredsPlan(m.cfg.KeyringPath, s.key.Serial, s.res.user, s.res.handles, time.Now())
	if errors.Is(err, plan.ErrNoChanges) {
		s.res.recorded = true
		return m, nil
	}
	if err == nil {
		m.review, err = newReview(p)
	}
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	m.reviewBack = modeU2F
	m.mode = modeReview
	return m, nil
}

func (m model) u2fRegister() (tea.Model, tea.Cmd) {
	s := &m.u2f
	if f := s.key.FIDO; f != nil && f.PINSet {
		if ok, why := f.PINPromptAllowed(); !ok {
			s.err = "not adding a credential: " + why
			return m, nil
		}
	}
	origin, err := pam.Origin()
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	var out bytes.Buffer
	run := &introExec{
		cmd:     pam.RegisterCommand(origin),
		capture: &out,
		intro: fmt.Sprintf("\nyking: creating a PAM credential on key %q (%s) for %s.\n"+
			"yking: touch the key when it blinks. If a PIN is asked, enter it ONCE;\n"+
			"yking: if it is rejected, press Ctrl+C instead of retrying.\n\n", s.key.Known.Label, s.key.Serial, origin),
	}
	s.busy = "Waiting for pamu2fcfg…"
	return m, tea.Exec(run, func(err error) tea.Msg {
		return u2fRegDoneMsg{out: out.Bytes(), err: withTail(err, run)}
	})
}

// u2fVerify re-checks that only the expected key is connected and that the
// new credential really is on it, before anything is written.
func (m model) u2fVerify(serial string, c pam.Cred) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		dev, err := m.singleKeyDevice(ctx, serial)
		if err != nil {
			return u2fVerifiedMsg{err: err}
		}
		origin, err := pam.Origin()
		if err != nil {
			return u2fVerifiedMsg{err: err}
		}
		return u2fVerifiedMsg{cred: c, err: fido.Probe(ctx, dev, origin, c.KeyHandle)}
	}
}

func (m model) u2fAddPlans(c pam.Cred) (tea.Model, tea.Cmd) {
	s := &m.u2f
	mp, base, err := readMapping()
	if err == nil {
		err = mp.Append(s.res.user, c)
	}
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	now := time.Now()
	userPlan := plan.New(fmt.Sprintf("add PAM credential of key %q to %s", s.key.Known.Label, tildePath(base.Path)), now)
	userPlan.Replace(base, []byte(mp.String()), 0o644)
	if base.Exists {
		if fi, err := os.Stat(base.Path); err == nil {
			userPlan.Steps[0].Mode = uint32(fi.Mode().Perm())
		}
	}
	rootPlan, err := pam.RecordCredsPlan(m.cfg.KeyringPath, s.key.Serial, s.res.user, []string{c.KeyHandle}, now)
	if err != nil && !errors.Is(err, plan.ErrNoChanges) {
		s.err = err.Error()
		return m, nil
	}
	m.review, err = newReviewPair(userPlan, rootPlan)
	if err != nil {
		s.err = err.Error()
		return m, nil
	}
	m.review.note = "The credential is already on the key (nothing stored there). Applying adds it to your mapping, then records it in the keyring."
	m.reviewBack = modeU2F
	m.mode = modeReview
	return m, nil
}

func (s u2fScreen) view() string {
	var b strings.Builder
	k := s.key
	b.WriteString(titleStyle.Render(fmt.Sprintf("PAM credential of %q (%s)", k.Known.Label, k.Serial)) + "\n")
	b.WriteString("\n")
	if s.busy != "" {
		b.WriteString(s.busy + "\n")
	}
	if r := s.res; r != nil {
		switch {
		case len(r.matched) > 0:
			b.WriteString(okStyle.Render(fmt.Sprintf("✓ This key owns credential %s of %d.", joinInts(r.matched), r.total)) + "\n")
			b.WriteString(dimStyle.Render("  It works for every service set to use the key.") + "\n")
			if r.recorded {
				b.WriteString(dimStyle.Render("  Already recorded in the keyring.") + "\n")
			} else {
				b.WriteString("\n" + selStyle.Render("Press Enter to record this in the keyring") + dimStyle.Render(" (so yking knows even when the key is away)") + "\n")
			}
		default:
			b.WriteString(errStyle.Render(fmt.Sprintf("✗ None of your %d credential(s) belongs to this key.", r.total)) + "\n")
			b.WriteString(warnStyle.Render("  Services set to \"key only\" will NOT accept this key.") + "\n\n")
			b.WriteString(selStyle.Render("a to add a credential") + "\n")
		}
		if len(r.otherKeys) > 0 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  Credential(s) %s are recorded on your other keys.", joinInts(r.otherKeys))) + "\n")
		}
	}
	if s.notice != "" {
		b.WriteString("\n" + s.notice + "\n")
	}
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}

func joinInts(n []int) string {
	var s []string
	for _, i := range n {
		s = append(s, fmt.Sprintf("#%d", i))
	}
	return strings.Join(s, ", ")
}
