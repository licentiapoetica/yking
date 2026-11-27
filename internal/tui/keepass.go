package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/chalresp"
	"github.com/licentiapoetica/yking/internal/fido"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
	"github.com/licentiapoetica/yking/internal/ykman"
)

// kpScreen writes one HMAC-SHA1 challenge-response secret into OTP slot 2
// of each YubiKey, one plugged-in key at a time, so any of them opens the
// same KeePassXC database. The secret exists only in this screen's memory.

type kpInput int

const (
	kpInputNone kpInput = iota
	kpInputConfirm
	kpInputSecret
	kpInputClear // type the label to clear slot 2
)

type kpPlugged struct {
	serial string
	slot2  ykman.SlotState
	err    string
}

type kpScreen struct {
	kr      *keyring.Keyring
	secret  []byte
	set     string
	touch   bool
	plugged []kpPlugged
	sel     string // serial of the plugged key the actions apply to
	written map[string]keyring.HMACSlot
	busy    string
	err     string
	note    string
	paper   bool
	leave   bool            // waiting for y/n: keys still lack the secret
	otp     string          // why the OTP interface is unusable ("" = fine)
	unsure  map[string]bool // written, but the test challenge failed
	foreign map[string]bool // c found another secret in slot 2: x may clear it
	gen     int             // poll generation: stale ticks from an earlier visit stop

	input    textinput.Model
	inputFor kpInput
}

// kpGen numbers screen visits so ticks of an earlier visit die out.
var kpGen int

type (
	kpTickMsg struct{ gen int }
	kpPollMsg struct {
		gen     int
		plugged []kpPlugged
		otp     string
		err     error
	}
	kpWriteMsg struct {
		serial   string
		check    bool // only verified
		written  bool // the secret is in the slot (even if the test failed)
		mismatch bool // the slot answered with another secret
		err      error
	}
	kpClearMsg struct {
		serial string
		err    error
	}
)

func (m model) openKeePass() (tea.Model, tea.Cmd) {
	s := kpScreen{touch: true, written: map[string]keyring.HMACSlot{}, unsure: map[string]bool{}, foreign: map[string]bool{}}
	kr, err := keyring.Load(m.cfg.KeyringPath)
	if err != nil {
		s.err = err.Error()
	}
	s.kr = kr
	if kr != nil && len(chalresp.Sets(kr)) == 0 {
		if s.secret, err = chalresp.NewSecret(); err != nil {
			s.err = err.Error()
		}
		s.set = chalresp.SetID(s.secret)
	}
	m.kp, m.mode, m.status = s, modeKeePass, ""
	return m, nil // polling starts on entering the mode (Update)
}

// otpCheck is otpAccess on this machine (tests replace it).
var otpCheck = func() string { return otpAccess(fido.DefaultSysRoot, "/dev") }

// otpAccess says why the YubiKey OTP interface cannot be used ("" = ok):
// ykman computes challenge-response over USB only there.
func otpAccess(sysRoot, devRoot string) string {
	nodes, err := fido.YubicoOTPNodes(sysRoot)
	switch {
	case err != nil:
		return err.Error()
	case len(nodes) == 0:
		return "no YubiKey OTP interface found"
	}
	for _, n := range nodes {
		if syscall.Access(filepath.Join(devRoot, n), 6) != nil { // read+write
			return "OTP interface not accessible (/dev/" + n + ")"
		}
	}
	return ""
}

// kpRead re-reads the plugged keys (they are swapped while this screen is
// open); never while a write runs.
func (m model) kpRead() tea.Cmd {
	client, gen := m.cfg.Client, m.kp.gen
	return func() tea.Msg {
		if client == nil {
			return kpPollMsg{gen: gen}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		serials, err := client.ListSerials(ctx)
		if err != nil {
			return kpPollMsg{err: err}
		}
		var out []kpPlugged
		for _, s := range serials {
			p := kpPlugged{serial: s}
			if info, err := client.OTPInfo(ctx, s); err != nil {
				p.err = err.Error()
			} else {
				p.slot2 = info.Slot2
			}
			out = append(out, p)
		}
		return kpPollMsg{gen: gen, plugged: out, otp: otpCheck()}
	}
}

// kpPollEvery is how often the plugged keys are re-read (tests shorten it).
var kpPollEvery = 1500 * time.Millisecond

func kpTick(gen int) tea.Cmd {
	return tea.Tick(kpPollEvery, func(time.Time) tea.Msg { return kpTickMsg{gen} })
}

// order is the plugged keys as listed: registered ones in keyring order,
// then unknown ones.
func (s kpScreen) order() []kpPlugged {
	var out []kpPlugged
	for _, k := range s.kr.Keys {
		for _, p := range s.plugged {
			if p.serial == k.Serial {
				out = append(out, p)
			}
		}
	}
	for _, p := range s.plugged {
		if s.kr.Find(p.serial) == nil {
			out = append(out, p)
		}
	}
	return out
}

// selected is the plugged key the actions apply to.
func (s kpScreen) selected() (kpPlugged, bool) {
	ord := s.order()
	for _, p := range ord {
		if p.serial == s.sel {
			return p, true
		}
	}
	if len(ord) > 0 {
		return ord[0], true
	}
	return kpPlugged{}, false
}

func (s *kpScreen) move(d int) {
	ord := s.order()
	cur, _ := s.selected()
	for i, p := range ord {
		if p.serial == cur.serial && i+d >= 0 && i+d < len(ord) {
			s.sel = ord[i+d].serial
			return
		}
	}
}

func (s kpScreen) target() (kpPlugged, *keyring.Key, string) {
	p, ok := s.selected()
	switch {
	case s.secret == nil:
		return kpPlugged{}, nil, "No secret yet: i enters the existing one, n makes a new one."
	case !ok:
		return kpPlugged{}, nil, "Plug in a YubiKey."
	}
	k := s.kr.Find(p.serial)
	switch {
	case p.err != "":
		return p, k, "OTP unreadable: " + p.err
	case k == nil:
		return p, nil, "Register this key first (e on the main screen)."
	}
	return p, k, ""
}

func (m model) updateKeePass(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.kp
	switch msg := msg.(type) {
	case kpTickMsg:
		switch {
		case m.mode != modeKeePass || msg.gen != s.gen:
			return m, nil // left the screen: stop polling
		case s.busy != "":
			return m, kpTick(s.gen)
		}
		return m, m.kpRead()
	case kpPollMsg:
		if m.mode != modeKeePass || msg.gen != s.gen {
			return m, nil
		}
		if msg.err == nil && s.busy == "" {
			s.plugged = msg.plugged
			s.otp = ""
			if len(msg.plugged) > 0 {
				s.otp = msg.otp
			}
		}
		return m, kpTick(s.gen)
	case kpWriteMsg:
		s.busy = ""
		k := s.kr.Find(msg.serial)
		name := msg.serial
		if k != nil {
			name = k.Label
		}
		if msg.written || (msg.check && msg.err == nil && (k == nil || k.HMAC == nil || k.HMAC.Set != s.set)) {
			if _, ok := s.written[msg.serial]; !ok {
				s.written[msg.serial] = keyring.HMACSlot{Slot: 2, Touch: s.touch, Set: s.set,
					ProgrammedAt: time.Now().UTC().Truncate(time.Second)}
			}
			for i := range s.plugged {
				if s.plugged[i].serial == msg.serial {
					s.plugged[i].slot2 = ykman.SlotProgrammed
				}
			}
		}
		switch {
		case msg.err != nil && msg.written:
			s.unsure[msg.serial] = true
			s.err = name + ": written, but the test failed: " + msg.err.Error()
		case msg.err != nil:
			s.err = name + ": " + msg.err.Error()
			if msg.check && msg.mismatch {
				s.foreign[msg.serial] = true
				s.err = name + " holds another secret — x clears slot 2."
			}
		case msg.check:
			delete(s.unsure, msg.serial)
			s.note = name + " answers with this secret."
		default:
			s.note = name + " written and verified."
			if rest := s.missing(); len(rest) > 0 {
				s.note += " Next: " + strings.Join(rest, ", ") + "."
			}
		}
		return m, nil
	case kpClearMsg:
		s.busy = ""
		if msg.err != nil {
			s.err = "Clearing failed: " + msg.err.Error()
			return m, nil
		}
		delete(s.foreign, msg.serial)
		for i := range s.plugged {
			if s.plugged[i].serial == msg.serial {
				s.plugged[i].slot2 = ykman.SlotEmpty
			}
		}
		s.note = "Slot 2 cleared. w writes."
		return m, nil
	case tea.KeyMsg:
		if s.busy != "" {
			return m, nil
		}
		if s.inputFor != kpInputNone {
			return m.kpInputKey(msg)
		}
		if s.leave {
			s.leave = false
			if msg.String() == "y" {
				return m.kpFinish()
			}
			return m, nil
		}
		s.err, s.note = "", ""
		switch msg.String() {
		case "up", "k":
			s.move(-1)
		case "down", "j":
			s.move(1)
		case "esc", "q":
			if len(s.missing()) > 0 && s.secret != nil && len(s.written) > 0 {
				s.leave = true
				return m, nil
			}
			return m.kpFinish()
		case "t":
			if len(s.written) > 0 {
				s.err = "Touch is fixed once a key was written."
				return m, nil
			}
			s.touch = !s.touch
		case "p":
			if s.secret != nil {
				s.paper = !s.paper
			}
		case "n":
			if len(s.written) > 0 {
				s.err = "Keys were written with this secret already."
				return m, nil
			}
			sec, err := chalresp.NewSecret()
			if err != nil {
				s.err = err.Error()
				return m, nil
			}
			s.secret, s.set, s.paper = sec, chalresp.SetID(sec), false
			if len(chalresp.Sets(s.kr)) > 0 {
				s.note = "New secret: databases made with the old one need the old keys."
			}
		case "i":
			s.input = textinput.New()
			s.input.EchoMode = textinput.EchoPassword
			s.input.EchoCharacter = '•'
			s.input.CharLimit = 60
			s.input.Width = 50
			s.input.Focus()
			s.inputFor = kpInputSecret
			return m, textinput.Blink
		case "u":
			p, err := chalresp.RulePlan(time.Now())
			if err == nil {
				m.review, err = newReview(p)
			}
			if errors.Is(err, plan.ErrNoChanges) {
				s.err = "The rule is installed; re-plug the key."
				return m, nil
			}
			if err != nil {
				s.err = err.Error()
				return m, nil
			}
			m.reviewBack, m.mode = modeKeePass, modeReview
			return m, nil
		case "w":
			p, k, why := s.target()
			switch {
			case why != "":
				s.err = why
			case s.otp != "":
				s.err = s.otp + " — u adds a udev rule."
			case s.written[p.serial] != (keyring.HMACSlot{}):
				s.err = k.Label + " already has this secret."
			case p.slot2 != ykman.SlotEmpty:
				s.err = "Slot 2 of " + k.Label + " is in use; yking never overwrites it."
			case k.Protected:
				s.input = textinput.New()
				s.input.CharLimit = 40
				s.input.Focus()
				s.inputFor = kpInputConfirm
				return m, textinput.Blink
			default:
				return m.kpWrite(p.serial, false)
			}
		case "x":
			p, _, why := s.target()
			switch {
			case why != "" && p.serial == "":
				s.err = why
			case !s.foreign[p.serial]:
				s.err = "x only clears a slot that just failed c."
			default:
				s.input = textinput.New()
				s.input.CharLimit = 40
				s.input.Focus()
				s.inputFor = kpInputClear
				return m, textinput.Blink
			}
		case "c":
			p, k, why := s.target()
			switch {
			case why != "":
				s.err = why
			case s.otp != "":
				s.err = s.otp + " — u adds a udev rule."
			case p.slot2 != ykman.SlotProgrammed:
				s.err = "Slot 2 of " + k.Label + " is empty."
			default:
				return m.kpWrite(p.serial, true)
			}
		}
	}
	return m, nil
}

func (m model) kpInputKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := &m.kp
	switch key.String() {
	case "esc":
		s.inputFor = kpInputNone
		return m, nil
	case "enter":
		v := s.input.Value()
		s.input.SetValue("")
		kind := s.inputFor
		s.inputFor = kpInputNone
		switch kind {
		case kpInputConfirm:
			p, k, why := s.target()
			if why != "" || k == nil {
				s.err = why
				return m, nil
			}
			if strings.TrimSpace(v) != k.Label {
				s.err = fmt.Sprintf("Type %q to confirm.", k.Label)
				return m, nil
			}
			return m.kpWrite(p.serial, false)
		case kpInputClear:
			p, k, _ := s.target()
			if k == nil || !s.foreign[p.serial] || strings.TrimSpace(v) != k.Label {
				s.err = "Not cleared."
				return m, nil
			}
			s.busy = "Clearing slot 2 of " + k.Label + "…"
			client, serial := m.cfg.Client, p.serial
			return m, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				return kpClearMsg{serial: serial, err: client.ClearChalResp(ctx, serial)}
			}
		case kpInputSecret:
			sec, err := chalresp.ParsePaper(v)
			if err != nil {
				s.err = err.Error()
				return m, nil
			}
			id := chalresp.SetID(sec)
			if sets := chalresp.Sets(s.kr); len(sets) > 0 && sets[id] == nil {
				s.err = "This secret matches no key in the keyring."
				return m, nil
			}
			s.secret, s.set, s.written = sec, id, map[string]keyring.HMACSlot{}
			s.note = "Secret accepted."
		}
		return m, nil
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(key)
	return m, cmd
}

// kpWrite programs (or with check only verifies) the plugged key, then
// sends a random challenge and compares the answer with the secret's.
func (m model) kpWrite(serial string, check bool) (tea.Model, tea.Cmd) {
	s := &m.kp
	k := s.kr.Find(serial)
	s.busy = "Writing to " + k.Label + "…"
	if check {
		s.busy = "Checking " + k.Label + "…"
	}
	touch := s.touch
	if check && k.HMAC != nil {
		touch = k.HMAC.Touch
	}
	if touch {
		s.busy += " touch it when it blinks"
	}
	client, secret := m.cfg.Client, bytes.Clone(s.secret)
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if client == nil {
			return kpWriteMsg{serial: serial, check: check, err: errors.New("no ykman")}
		}
		var werr error
		if !check {
			werr = client.ProgramChalResp(ctx, serial, secret, touch)
			if errors.Is(werr, ykman.ErrSlotNotEmpty) {
				return kpWriteMsg{serial: serial, err: werr}
			}
		}
		msg := kpWriteMsg{serial: serial, check: check, written: !check && werr == nil}
		ch, err := chalresp.Challenge()
		if err != nil {
			msg.err = err
			return msg
		}
		got, err := client.Calculate(ctx, serial, ch)
		switch {
		case err != nil:
			msg.err = fmt.Errorf("test challenge: %w", err)
		case !bytes.Equal(got, chalresp.Response(secret, ch)):
			msg.err, msg.mismatch = errors.New("holds a different secret"), true
		case werr != nil: // ykman said the write failed, yet the slot answers right
			msg.written = true
		}
		if werr != nil && !msg.written {
			// The write failed: report that; a slot left with another secret
			// may be cleared (x), as after c.
			msg.check, msg.err = true, fmt.Errorf("write failed: %w", werr)
		}
		return msg
	}
}

// missing lists registered keys that hold neither this secret nor any.
func (s kpScreen) missing() []string {
	var out []string
	if s.kr == nil {
		return nil
	}
	for _, k := range s.kr.Keys {
		if _, ok := s.written[k.Serial]; ok {
			continue
		}
		if k.HMAC != nil && k.HMAC.Set == s.set {
			continue
		}
		out = append(out, k.Label)
	}
	return out
}

// kpFinish forgets the secret and records what was written.
func (m model) kpFinish() (tea.Model, tea.Cmd) {
	s := &m.kp
	clear(s.secret)
	written := s.written
	m.kp = kpScreen{}
	m.mode = modeKeys
	if len(written) == 0 {
		return m, nil
	}
	p, err := chalresp.RecordPlan(m.cfg.KeyringPath, written, time.Now())
	if err == nil {
		m.review, err = newReview(p)
	}
	if err != nil {
		m.status = errStyle.Render("Written, but recording failed: " + err.Error())
		return m, nil
	}
	m.status = okStyle.Render("Challenge-response written. Apply to record it.")
	m.reviewBack, m.mode = modeKeys, modeReview
	return m, nil
}

func (s kpScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("KeePassXC challenge-response") + "\n\n")
	if s.err != "" && s.kr == nil {
		return b.String() + errStyle.Render(s.err) + "\n"
	}
	touch := "off"
	if s.touch {
		touch = "on"
	}
	if s.secret != nil {
		b.WriteString(fmt.Sprintf("Secret  %s  %s\n", s.set, dimStyle.Render("· in memory only · touch "+touch)))
	} else {
		b.WriteString(warnStyle.Render("Secret  none — i enter existing · n new") + "\n")
	}
	if s.paper && s.secret != nil {
		b.WriteString("\n  " + selStyle.Render(chalresp.Paper(s.secret)) + "\n")
		b.WriteString(warnStyle.Render("  ! with your password this opens the database") + "\n")
	}

	b.WriteString("\n")
	plugged := map[string]kpPlugged{}
	for _, p := range s.plugged {
		plugged[p.serial] = p
	}
	for _, k := range s.kr.Keys {
		state := dimStyle.Render("not plugged")
		p, in := plugged[k.Serial]
		_, done := s.written[k.Serial]
		switch {
		case done && s.unsure[k.Serial]:
			state = warnStyle.Render("written, not tested — c tests")
		case done:
			state = okStyle.Render("✓ written")
		case k.HMAC != nil && k.HMAC.Set == s.set && s.secret != nil:
			state = okStyle.Render("✓ has this secret")
		case in && p.err != "":
			state = errStyle.Render(p.err)
		case in && p.slot2 == ykman.SlotEmpty:
			state = selStyle.Render("slot 2 empty — w writes")
		case in && p.slot2 == ykman.SlotProgrammed && k.HMAC != nil:
			state = dimStyle.Render("set " + k.HMAC.Set + " — c checks")
		case in && p.slot2 == ykman.SlotProgrammed && s.secret != nil:
			state = warnStyle.Render("slot 2 in use — c tests for this secret")
		case in && p.slot2 == ykman.SlotProgrammed:
			state = warnStyle.Render("slot 2 in use")
		case k.HMAC != nil:
			state = dimStyle.Render("set " + k.HMAC.Set)
		}
		mark := "  "
		if in {
			mark = dimStyle.Render("● ")
		}
		if cur, ok := s.selected(); ok && in && cur.serial == k.Serial {
			mark = selStyle.Render("▸ ")
		}
		b.WriteString(fmt.Sprintf("%s%-12s %s  %s\n", mark, k.Label, dimStyle.Render(k.Serial), state))
	}
	for _, p := range s.plugged {
		if s.kr.Find(p.serial) == nil {
			mark := dimStyle.Render("● ")
			if cur, ok := s.selected(); ok && cur.serial == p.serial {
				mark = selStyle.Render("▸ ")
			}
			b.WriteString(fmt.Sprintf("%s%-12s %s  %s\n", mark, "?", dimStyle.Render(p.serial), warnStyle.Render("not registered")))
		}
	}

	if s.otp != "" {
		b.WriteString("\n" + warnStyle.Render("! "+s.otp+" — u adds a udev rule") + "\n")
	}
	if rest := s.missing(); s.secret != nil && len(rest) > 0 && len(rest) < len(s.kr.Keys) {
		b.WriteString("\n" + dimStyle.Render("Still without it: "+strings.Join(rest, ", ")) + "\n")
	}
	switch s.inputFor {
	case kpInputConfirm:
		_, k, _ := s.target()
		label := ""
		if k != nil {
			label = k.Label
		}
		b.WriteString("\nProtected key: type " + label + "  " + s.input.View() + "\n")
	case kpInputSecret:
		b.WriteString("\nSecret (40 hex)  " + s.input.View() + "\n")
	case kpInputClear:
		_, k, _ := s.target()
		label := ""
		if k != nil {
			label = k.Label
		}
		b.WriteString("\n" + warnStyle.Render("! a database made with the old secret can't be opened with "+label+" any more") + "\n")
		b.WriteString("Clear slot 2: type " + label + "  " + s.input.View() + "\n")
	}
	if s.leave {
		b.WriteString("\n" + warnStyle.Render("! "+strings.Join(s.missing(), ", ")+" can't get this secret later without the paper copy") + "\n")
		b.WriteString("Leave?  " + selStyle.Render("y") + " yes  " + selStyle.Render("n") + " no\n")
	}
	if s.busy != "" {
		b.WriteString("\n" + selStyle.Render(s.busy) + "\n")
	}
	if s.note != "" {
		b.WriteString("\n" + okStyle.Render(s.note) + "\n")
	}
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}

// kpHelp is the help line for the KeePassXC screen.
func (s kpScreen) help() string {
	switch {
	case s.inputFor != kpInputNone:
		return "enter ok · esc cancel"
	case s.leave:
		return "y leave · n stay"
	}
	h := []string{"w write", "c test", "p paper copy", "i enter secret", "n new secret"}
	if s.otp != "" {
		h = append([]string{"u udev rule"}, h...)
	}
	if p, ok := s.selected(); ok && s.foreign[p.serial] {
		h = append([]string{"x clear slot 2"}, h...)
	}
	if len(s.plugged) > 1 {
		h = append([]string{"↑↓ key"}, h...)
	}
	if len(s.written) == 0 {
		h = slices.Insert(h, 2, "t touch")
	}
	return strings.Join(append(h, "esc done"), " · ")
}
