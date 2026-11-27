// Package tui is yking's interactive interface: key inventory, enrollment,
// and the plan review/apply flow. It always runs as the user; applying a
// plan hands the terminal to `sudo yking apply`.
package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/licentiapoetica/yking/internal/deps"
	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/elevate"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pgp"
	"github.com/licentiapoetica/yking/internal/sshkey"
	"github.com/licentiapoetica/yking/internal/ykman"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	selStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	hunkStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	paneStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("8")).Padding(0, 1)
)

// Config is what the TUI needs from main.
type Config struct {
	Client      *ykman.Client
	KeyringPath string
}

type mode int

const (
	modeKeys mode = iota
	modeEnroll
	modeReview
	modeSSH
	modeDeploy
	modePAM
	modeU2F
	modeRevoke
	modeLink
	modeEvents
	modeDoctor
	modeLUKS
	modeImport
	modeHosts
	modePGP
	modeKeePass
	modeRun
)

type depsDoneMsg struct{ err error }

type scanDoneMsg struct {
	rep      *detect.Report
	kr       *keyring.Keyring
	sshKeys  []sshkey.PubKey
	coverage map[string]bool
	stale    string // /usr/local/bin/yking differs from this build: both times
	deps     []deps.Problem
	err      error
}

type model struct {
	cfg      Config
	mode     mode
	scanning bool
	rep      *detect.Report
	kr       *keyring.Keyring
	err      error
	cursor   int
	width    int
	height   int
	status   string // one-line result of the last action
	scroll   int    // first body line shown when the screen is taller than the window
	helpOpen bool   // "?": the full key list replaces the screen
	free     bool   // scrolled by wheel/PgUp/PgDn: do not snap back to the ▸ cursor

	enroll     enrollForm
	review     review
	reviewBack mode // where esc in review returns to
	ssh        sshForm
	deploy     deployForm
	pam        pamScreen
	u2f        u2fScreen
	revoke     revokeScreen
	link       linkScreen
	events     eventsScreen
	doctor     doctorScreen
	luks       luksScreen
	imp        importScreen
	hosts      hostsScreen
	pgp        pgpScreen
	kp         kpScreen
	run        runner
	// pendingArchive: revoked key files to move once the plan applied.
	pendingArchive []string
	coverage       map[string]bool // serial → PAM credential confirmed
	sshKeys        []sshkey.PubKey // security-key pubkeys in ~/.ssh
	stale          string          // installed yking differs from this build: both times
	deps           []deps.Problem  // missing tools and services

	// loading screen
	scanCh  <-chan tea.Msg    // the scan whose steps scanLog shows
	scanLog []detect.Progress // steps of the running scan
	frame   int               // animation frame
	ticking bool              // the frame clock is running
}

// Run starts the TUI.
func Run(cfg Config) error {
	_, err := tea.NewProgram(model{cfg: cfg, scanning: true}, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
	return err
}

func (m model) Init() tea.Cmd { return m.scan() }

func (m model) selected() (detect.KeyReport, bool) {
	if m.rep == nil || m.cursor >= len(m.rep.Keys) {
		return detect.KeyReport{}, false
	}
	return m.rep.Keys[m.cursor], true
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ms, ok := msg.(tea.MouseMsg); ok {
		return m.wheel(ms)
	}
	if k, ok := msg.(tea.KeyMsg); ok && !strings.HasPrefix(k.String(), "pg") {
		m.free = false // a key may move the cursor: show it again
	}
	if k, ok := msg.(tea.KeyMsg); ok && m.helpOpen {
		switch k.String() {
		case "?", "esc", "q":
			m.helpOpen, m.scroll = false, 0
		case "pgup", "up":
			m = m.scrollBy(-max(m.layout().avail-2, 1))
		case "pgdown", "down":
			m = m.scrollBy(max(m.layout().avail-2, 1))
		case "ctrl+c":
			return m.update(msg)
		}
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "?" && !m.typing() {
		m.helpOpen, m.scroll = true, 0
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok && !m.pagesOwnScroll() {
		switch k.String() {
		case "pgup":
			return m.scrollBy(-max(m.layout().avail-2, 1)), nil
		case "pgdown":
			return m.scrollBy(max(m.layout().avail-2, 1)), nil
		}
	}
	next, cmd := m.update(msg)
	n := next.(model)
	if n.mode != m.mode {
		n.scroll = 0
	}
	if n.mode == modeKeePass && m.mode != modeKeePass { // (re)entered: poll the plugged keys
		kpGen++
		n.kp.gen = kpGen
		cmd = tea.Batch(cmd, n.kpRead())
	}
	return n.keepAnimating(cmd)
}

func (m model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case animTickMsg:
		return m.onTick()
	case scanProgressMsg:
		return m.onProgress(msg)
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case scanDoneMsg:
		m.scanning = false
		m.rep, m.kr, m.sshKeys, m.coverage, m.err = msg.rep, msg.kr, msg.sshKeys, msg.coverage, msg.err
		m.stale, m.deps = msg.stale, msg.deps
		if m.rep != nil && m.cursor >= len(m.rep.Keys) {
			m.cursor = 0
		}
		return m, nil
	case depsDoneMsg:
		if msg.err != nil {
			m.status = errStyle.Render("Install: " + msg.err.Error())
		} else {
			m.status = okStyle.Render("Installed.")
		}
		m.scanning = true
		return m, m.scan()
	case keyTestMsg:
		style := okStyle
		head := "Key test passed"
		if msg.err != nil {
			m.status = errStyle.Render("Key test: " + msg.err.Error())
			return m, nil
		}
		if !msg.ok {
			style, head = errStyle, "Key test FAILED"
		}
		m.status = style.Render(head+":") + "\n  " + strings.Join(msg.lines, "\n  ")
		return m, nil
	case applyDoneMsg:
		m.mode = modeKeys
		var reload tea.Cmd
		switch m.reviewBack {
		case modePGP:
			pgp.GPG{}.Kill("scdaemon") // picks up a changed scdaemon.conf
			m.mode, m.pgp.loading, reload = modePGP, true, m.loadPGP()
		case modeKeePass: // the udev rule: back to the screen, secret kept
			m.mode = modeKeePass
		}
		var parts []string
		if msg.userID != "" {
			parts = append(parts, "your file updated (undo: yking rollback --user "+msg.userID+")")
		}
		switch {
		case msg.id == "":
		case msg.err != nil:
			parts = append(parts, "system part failed or was cancelled: "+msg.err.Error()+" — `yking history` shows what was applied")
		case m.reviewBack == modePAM:
			parts = append(parts, "PAM change kept ("+msg.id+", undo: yking rollback "+msg.id+")")
		default:
			parts = append(parts, "applied "+msg.id+" (undo: yking rollback "+msg.id+")")
		}
		style := okStyle
		if msg.err != nil {
			style = errStyle
		}
		if len(m.pendingArchive) > 0 {
			if msg.err == nil && msg.id != "" {
				parts = append(parts, strings.TrimSpace(archivePending(m.pendingArchive)))
			}
			m.pendingArchive = nil
		}
		m.status = style.Render(strings.ToUpper(strings.Join(parts, "; ")[:1]) + strings.Join(parts, "; ")[1:] + ".")
		m.scanning = true
		return m, tea.Batch(m.scan(), reload)
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			if m.mode == modeRun && m.run.job.noCancel && m.run.phase == phaseRunning {
				// Never walk away from a running apply (e.g. a PAM change
				// waiting for "keep"): quitting would roll it back at best.
				if m.run.prompt != nil {
					m.run.prompt.Refuse()
					m.run.prompt = nil
				}
				m.run.note = "Ctrl+C: the open question was answered with no (cancel / roll back). The apply finishes by itself; quit after that."
				return m, nil
			}
			if m.mode == modeRun {
				m.run.stop(errCancelled) // never leave a detached ssh behind
			}
			return m, tea.Quit
		}
	}

	switch m.mode {
	case modeEnroll:
		return m.updateEnroll(msg)
	case modeReview:
		return m.updateReview(msg)
	case modeSSH:
		return m.updateSSH(msg)
	case modeDeploy:
		return m.updateDeploy(msg)
	case modePAM:
		return m.updatePAM(msg)
	case modeU2F:
		return m.updateU2F(msg)
	case modeRevoke:
		return m.updateRevoke(msg)
	case modeLink:
		return m.updateLink(msg)
	case modeEvents:
		return m.updateEvents(msg)
	case modeDoctor:
		return m.updateDoctor(msg)
	case modeLUKS:
		return m.updateLUKS(msg)
	case modeImport:
		return m.updateImport(msg)
	case modeHosts:
		return m.updateHosts(msg)
	case modePGP:
		return m.updatePGP(msg)
	case modeKeePass:
		return m.updateKeePass(msg)
	case modeRun:
		return m.updateRun(msg)
	default:
		return m.updateKeys(msg)
	}
}

func (m model) updateKeys(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "q", "esc":
		return m, tea.Quit
	case "r":
		if !m.scanning {
			m.scanning = true
			m.status = ""
			return m, m.scan()
		}
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.rep != nil && m.cursor < len(m.rep.Keys)-1 {
			m.cursor++
		}
	case "e":
		k, ok := m.selected()
		switch {
		case m.scanning || !ok:
		case k.Known != nil:
			m.status = warnStyle.Render(fmt.Sprintf("Key %s is already registered as %q.", k.Serial, k.Known.Label))
		default:
			m.enroll = newEnrollForm(k, m.kr)
			m.mode = modeEnroll
			m.status = ""
			return m, m.enroll.focusCmd()
		}
	case "s":
		k, ok := m.selected()
		switch {
		case m.scanning || !ok:
		case k.Known == nil:
			m.status = warnStyle.Render("Register this key first (e).")
		default:
			m.ssh = newSSHForm(k)
			m.mode = modeSSH
			m.status = ""
			return m, textinput.Blink
		}
	case "c":
		k, ok := m.selected()
		switch {
		case m.scanning || !ok:
		case k.Known == nil:
			m.status = warnStyle.Render("Register this key first (e).")
		default:
			m.u2f = u2fScreen{key: k, busy: "Checking (silent, no touch)…"}
			m.mode = modeU2F
			m.status = ""
			return m, m.u2fCheck(k.Serial)
		}
	case "U":
		if m.stale != "" {
			return m.updateInstalled()
		}
	case "i":
		m.imp = newImportScreen(m.cfg.KeyringPath)
		m.mode = modeImport
		m.status = ""
		return m, nil
	case "o":
		m.hosts = newHostsScreen(m.cfg.KeyringPath)
		m.mode = modeHosts
		m.status = ""
		return m, nil
	case "b":
		m.luks = newLUKSScreen(m.cfg.KeyringPath)
		m.mode = modeLUKS
		m.status = ""
		return m, nil
	case "h":
		m.doctor = doctorScreen{}
		m.mode = modeDoctor
		m.status = ""
		return m, m.runDoctor()
	case "t":
		k, ok := m.selected()
		switch {
		case m.scanning || !ok:
		case k.Known == nil:
			m.status = warnStyle.Render("Register this key first (e).")
		default:
			m.status = dimStyle.Render("Testing " + k.Known.Label + " (silent, no touch)…")
			return m, m.keyTest(*k.Known)
		}
	case "I":
		if pkgs, units := deps.Actions(m.deps); len(pkgs)+len(units) == 0 {
			return m, nil
		}
		cmd, err := elevate.SelfTUI("deps", "install", "--tui", sockArg)
		if err != nil {
			m.status = errStyle.Render(err.Error())
			return m, nil
		}
		return m.startRun(runJob{
			title:    "Install missing tools",
			cmd:      cmd,
			key:      m.onlyKey(),
			noCancel: true, // never cut off a package manager
			hold:     true,
			outLines: 12,
			back:     modeKeys,
			done:     func(r runResult) tea.Msg { return depsDoneMsg{err: r.err} },
		})
	case "g":
		return m.openPGP()
	case "v":
		if !m.scanning {
			return m.openKeePass()
		}
	case "u":
		m.events = newEventsScreen(m.cfg.KeyringPath)
		m.mode = modeEvents
		m.status = ""
		return m, nil
	case "l":
		k, ok := m.selected()
		switch {
		case m.scanning || !ok:
		case k.Known == nil:
			m.status = warnStyle.Render("Register this key first (e).")
		default:
			m.link = newLinkScreen(k, m.untrackedSSH())
			m.mode = modeLink
			m.status = ""
			return m, nil
		}
	case "x":
		if m.scanning {
			return m, nil
		}
		connected := map[string]bool{}
		pre := ""
		if m.rep != nil {
			for _, k := range m.rep.Keys {
				connected[k.Serial] = true
			}
		}
		if k, ok := m.selected(); ok {
			pre = k.Serial
		}
		m.revoke = newRevokeScreen(m.cfg.KeyringPath, connected, pre)
		m.mode = modeRevoke
		m.status = ""
		return m, nil
	case "p":
		m.pam = newPAMScreen(m.cfg.KeyringPath)
		m.mode = modePAM
		m.status = ""
		return m, nil
	case "d":
		k, ok := m.selected()
		switch {
		case m.scanning || !ok:
		case k.Known == nil || len(k.Known.SSH) == 0:
			m.status = warnStyle.Render("No SSH key yet (s).")
		default:
			var keys []keyring.Key
			if m.kr != nil {
				keys = m.kr.Keys
			}
			m.deploy = newDeployForm(k, keys, connectedSerials(m))
			m.mode = modeDeploy
			m.status = ""
			return m, textinput.Blink
		}
	}
	return m, nil
}

// screen renders the current mode's content and its help line. height is
// the room the content gets (screens that page use it).
func (m model) screen(height int) (string, string) {
	var b strings.Builder
	var help string
	switch m.mode {
	case modeEnroll:
		b.WriteString(m.enroll.view())
		help = "tab field · ←→ role · space toggle · enter review · esc cancel"
	case modeReview:
		b.WriteString(m.review.view(height))
		help = "↑↓ scroll · a apply · esc back"
	case modeRun:
		b.WriteString(m.viewRun())
		help = m.runHelp()
	case modeKeePass:
		b.WriteString(m.kp.view())
		help = m.kp.help()
	case modePGP:
		b.WriteString(m.pgp.view())
		help = "↑↓ identity · n new · a sign key · w to card · b backup · g git · x card-only · f fix gpg · r reload · esc back"
		switch {
		case m.pgp.inputFor != pgpInputNone:
			help = "enter ok · esc cancel"
		case m.pgp.askOnly:
			help = "y yes · n no"
		}
	case modeHosts:
		b.WriteString(m.hosts.view())
		help = "↑↓ host · enter review · r reload · esc back"
	case modeImport:
		b.WriteString(m.imp.view())
		help = "1 keys · p PAM · u plug actions · b disk · D done · esc back"
	case modeLUKS:
		b.WriteString(m.luks.view())
		help = "e enroll · ←→ unlock · m switch boot · P remove passphrase · H header backup · s status · R repair · esc back"
		if m.luks.asking {
			help = "enter back up · esc cancel"
		}
	case modeDoctor:
		b.WriteString(m.doctor.view(height))
		help = "↑↓ scroll · r recheck · esc back"
	case modeEvents:
		b.WriteString(m.events.view())
		help = "↑↓ item · space toggle · enter review · esc back"
	case modeLink:
		b.WriteString(m.link.view())
		help = "↑↓ key · tab hosts · enter test · esc back"
	case modeRevoke:
		b.WriteString(m.revoke.view())
		help = "↑↓ choose · enter next · esc back"
		if m.revoke.a != nil {
			help = "↑↓ item · space toggle · ←→ login · enter run · esc back"
		}
	case modeU2F:
		b.WriteString(m.u2f.view())
		help = "enter record · a add · r recheck · esc back"
	case modePAM:
		b.WriteString(m.pam.view())
		help = "↑↓ service · ←→ mode · u PIN/touch · t take-over · r reset · enter review · esc back"
	case modeDeploy:
		b.WriteString(m.deploy.view())
		help = "tab field · ←→ choose · enter deploy · esc cancel"
	case modeSSH:
		b.WriteString(m.ssh.view())
		help = "tab field · ←→ choose · enter create · esc cancel"
	default:
		switch {
		case m.scanning:
			b.WriteString(m.viewLoading())
		case m.err != nil:
			b.WriteString(depsView(m.deps))
			b.WriteString(errStyle.Render("Error: "+m.err.Error()) + "\n")
		default:
			if len(m.deps) > 0 {
				b.WriteString(depsView(m.deps) + "\n")
			}
			if m.stale != "" {
				b.WriteString(warnStyle.Render("! installed yking is outdated ("+m.stale+") — U to update") + "\n\n")
			}
			b.WriteString(m.viewKeys())
		}
		if m.scanning {
			help = "q quit"
			break
		}
		if pkgs, units := deps.Actions(m.deps); len(pkgs)+len(units) > 0 {
			help = "I install missing · "
		}
		help += "↑↓ select · e enroll · t test · c PAM check · s SSH key · l link · d deploy · o ssh config · p PAM · g PGP · v KeePassXC · b disk · u plug actions · x revoke · i import · h doctor · r rescan · q quit"
	}
	return b.String(), help
}

func (m model) viewKeys() string {
	rep := m.rep
	var b strings.Builder
	if len(rep.Keys) == 0 {
		b.WriteString(warnStyle.Render("No YubiKey with a readable serial is connected.") + "\n")
	}

	var list strings.Builder
	list.WriteString(titleStyle.Render("Connected") + "\n")
	for i, k := range rep.Keys {
		line := fmt.Sprintf("%s  %s", k.Serial, keyName(k))
		if i == m.cursor {
			list.WriteString(selStyle.Render("▸ "+line) + "\n")
		} else {
			list.WriteString("  " + line + "\n")
		}
	}
	if len(rep.Missing) > 0 {
		list.WriteString("\n" + titleStyle.Render("Registered, not connected") + "\n")
		for _, k := range rep.Missing {
			list.WriteString(dimStyle.Render(fmt.Sprintf("  %s  %s (%s)", k.Serial, k.Label, k.Role)) + "\n")
		}
	}
	if un := m.untrackedSSH(); len(un) > 0 {
		list.WriteString("\n" + titleStyle.Render("SSH keys from a security key, not linked") + "\n")
		for _, p := range un {
			list.WriteString(dimStyle.Render("  ~/.ssh/"+filepath.Base(p.Path)+"  "+p.Comment) + "\n")
		}
		list.WriteString(dimStyle.Render("  l on its key to link") + "\n")
	}
	if m.kr != nil {
		for _, r := range m.kr.Revoked {
			for _, l := range r.Leftovers {
				list.WriteString("\n" + warnStyle.Render(fmt.Sprintf("  ! revoked %q: %s still on %s", r.Label, l.Comment, l.Host)) + "\n")
			}
		}
	}
	for _, d := range rep.Unidentified {
		list.WriteString("\n" + warnStyle.Render("  ? "+d+" — no serial, cannot be tracked") + "\n")
	}
	if m.kr != nil && len(m.kr.Keys) > 0 && !m.kr.MeetsMinimumKeys() {
		list.WriteString("\n" + warnStyle.Render("! only 1 key registered — add a backup") + "\n")
	}

	left := fitPane(strings.TrimRight(list.String(), "\n"), m.width)
	if len(rep.Keys) == 0 {
		return b.String() + left + "\n"
	}
	right := fitPane(detail(rep.Keys[m.cursor], m.coverage), m.width)
	if m.width > 0 && lipgloss.Width(left)+lipgloss.Width(right)+1 > m.width {
		return b.String() + left + "\n" + right + "\n"
	}
	return b.String() + lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right) + "\n"
}

func keyName(k detect.KeyReport) string {
	if k.Known != nil {
		return fmt.Sprintf("%s (%s)", k.Known.Label, k.Known.Role)
	}
	if k.Info.DeviceType != "" {
		return k.Info.DeviceType + " " + dimStyle.Render("(new)")
	}
	return dimStyle.Render("(new)")
}

func detail(k detect.KeyReport, coverage map[string]bool) string {
	var b strings.Builder
	row := func(label, val string) {
		b.WriteString(dimStyle.Render(fmt.Sprintf("%-14s", label)) + " " + val + "\n")
	}

	row("Model", or(k.Info.DeviceType, "?"))
	row("Serial", k.Serial)
	row("Firmware", or(k.Info.Firmware, "?"))
	row("Form factor", or(k.Info.FormFactor, "?"))
	if k.Known != nil {
		prot := "no"
		if k.Known.Protected {
			prot = "yes"
		}
		row("Label", k.Known.Label)
		row("Role", string(k.Known.Role))
		row("Protected", prot)
	}

	b.WriteString("\n")
	if f := k.FIDO; f != nil {
		switch {
		case f.PINBlocked:
			row("FIDO2 PIN", errStyle.Render("BLOCKED"))
		case !f.PINSet:
			row("FIDO2 PIN", warnStyle.Render("not set"))
		case f.PINRetries >= ykman.MinPINRetriesToPrompt:
			row("FIDO2 PIN", okStyle.Render(fmt.Sprintf("set, %d tries left", f.PINRetries)))
		default:
			row("FIDO2 PIN", errStyle.Render(fmt.Sprintf("set, %d tries left", f.PINRetries)))
		}
		if f.CredsRemaining >= 0 {
			row("Resident free", fmt.Sprintf("%d slots", f.CredsRemaining))
		}
	} else {
		row("FIDO2", dimStyle.Render("unavailable"))
	}
	if o := k.OTP; o != nil {
		row("OTP slot 1", o.Slot1.String())
		row("OTP slot 2", o.Slot2.String())
	}

	if w := k.Warnings(); len(w) > 0 {
		b.WriteString("\n")
		for _, s := range w {
			b.WriteString(warnStyle.Render("! "+s) + "\n")
		}
	}
	for _, e := range k.Errors {
		b.WriteString(errStyle.Render("✗ "+e) + "\n")
	}
	if k.Known != nil {
		b.WriteString("\n")
		if coverage[k.Serial] {
			row("PAM", okStyle.Render("✓ credential confirmed"))
		} else {
			row("PAM", warnStyle.Render("not confirmed (c)"))
		}
		if len(k.Known.SSH) == 0 {
			row("SSH keys", dimStyle.Render("none (s)"))
		}
		for i, s := range k.Known.SSH {
			label := ""
			if i == 0 {
				label = "SSH keys"
			}
			name := filepath.Base(s.Path)
			if name == "." || name == "" {
				name = s.Comment
			}
			extra := ""
			switch {
			case s.NoTouchRequired:
				extra = " PIN only"
			case s.VerifyRequired:
				extra = " PIN+touch"
			default:
				extra = " touch"
			}
			row(label, name+dimStyle.Render(extra+" "+s.Fingerprint[:min(len(s.Fingerprint), 19)]+"…"))
			if len(s.Hosts) > 0 {
				row("", dimStyle.Render("  on: "+strings.Join(s.Hosts, ", ")))
			}
		}
	} else {
		b.WriteString("\n" + selStyle.Render("e to register") + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// untrackedSSH lists security-key pubkeys in ~/.ssh that no keyring entry
// knows about.
func (m model) untrackedSSH() []sshkey.PubKey {
	known := map[string]bool{}
	if m.kr != nil {
		for _, k := range m.kr.Keys {
			for _, s := range k.SSH {
				known[s.Fingerprint] = true
			}
		}
	}
	var out []sshkey.PubKey
	for _, p := range m.sshKeys {
		if !known[p.Fingerprint] {
			out = append(out, p)
		}
	}
	return out
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
