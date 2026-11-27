package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/licentiapoetica/yking/internal/elevate"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/luks"
)

// luksScreen: disk encryption. Shows what is readable without root (LUKS
// volumes via lsblk, boot unlock method, keys enrolled per the keyring);
// every action runs `sudo yking luks …` in the terminal, which prompts,
// shows diffs and verifies by itself.

type luksScreen struct {
	vols    []luks.Volume
	root    *luks.Volume
	boot    luks.Boot
	keys    []keyring.Key
	pending string
	snap    *luks.Snapshot // slot lists as root last read them
	touch   bool           // enroll with touch only (else PIN + touch)
	err     string
	// backup: the folder field for a header copy off this disk
	asking bool
	input  textinput.Model
}

// removableDir is the one mounted stick under /run/media/USER, if exactly
// one (a header copy belongs off the encrypted disk).
func removableDir() string {
	dirs, _ := filepath.Glob(filepath.Join("/run/media", currentUser(), "*"))
	if len(dirs) == 1 {
		return dirs[0]
	}
	return ""
}

func (m model) luksBackup(dir string) (tea.Model, tea.Cmd) {
	args := []string{"--keyring", m.cfg.KeyringPath, "luks", "backup"}
	if dir != "" {
		args = append(args, "--out", dir)
	}
	cmd, err := elevate.SelfTUI(args...)
	if err != nil {
		m.luks.err = err.Error()
		return m, nil
	}
	return m.startRun(runJob{
		title:    "Back up the LUKS header",
		cmd:      cmd,
		key:      m.onlyKey(),
		hold:     true,
		outLines: 6,
		back:     modeLUKS,
		done: func(r runResult) tea.Msg {
			return luksDoneMsg{what: "back up the LUKS header", err: r.err}
		},
	})
}

type luksDoneMsg struct {
	what string
	err  error
}

var (
	luksVolumes      = luks.Volumes
	luksDiscoverBoot = luks.DiscoverBoot
	luksPending      = luks.Pending
	luksSnapshot     = luks.ReadSnapshot
	luksNow          = time.Now
)

func newLUKSScreen(krPath string) luksScreen {
	var s luksScreen
	vols, err := luksVolumes()
	if err != nil {
		s.err = err.Error()
	}
	s.vols = vols
	for i := range vols {
		if vols[i].Root {
			s.root = &vols[i]
		}
	}
	s.boot = luksDiscoverBoot()
	s.pending = luksPending()
	s.snap, _ = luksSnapshot()
	if kr, err := keyring.Load(krPath); err == nil {
		s.keys = kr.Keys
	} else if s.err == "" {
		s.err = err.Error()
	}
	return s
}

// enrolled returns the keyring's slot record for key on the root volume.
func (s luksScreen) enrolled(k keyring.Key) *keyring.LUKSSlot {
	if s.root == nil {
		return nil
	}
	for i := range k.LUKS {
		if k.LUKS[i].DeviceUUID == s.root.UUID {
			return &k.LUKS[i]
		}
	}
	return nil
}

func (s luksScreen) enrolledCount() int {
	n := 0
	for _, k := range s.keys {
		if s.enrolled(k) != nil {
			n++
		}
	}
	return n
}

func (m model) luksRun(what string, pause bool, args ...string) (tea.Model, tea.Cmd) {
	cmd, err := elevate.Self(append([]string{"--keyring", m.cfg.KeyringPath, "luks"}, args...)...)
	if err != nil {
		m.luks.err = err.Error()
		return m, nil
	}
	run := &introExec{cmd: cmd, pauseAlways: pause, intro: "\nyking: " + what + " (asks for sudo first)\n\n"}
	return m, tea.Exec(run, func(err error) tea.Msg { return luksDoneMsg{what: what, err: withTail(err, run)} })
}

func (m model) updateLUKS(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := &m.luks
	switch msg := msg.(type) {
	case luksDoneMsg:
		fresh := newLUKSScreen(m.cfg.KeyringPath)
		fresh.touch = s.touch
		m.luks = fresh
		if msg.err != nil {
			m.luks.err = msg.what + ": " + msg.err.Error()
		} else {
			m.status = okStyle.Render(msg.what + ": done.")
		}
		return m, nil
	case tea.KeyMsg:
		if s.asking {
			switch msg.String() {
			case "esc":
				s.asking = false
			case "enter":
				s.asking = false
				return m.luksBackup(strings.TrimSpace(s.input.Value()))
			default:
				var cmd tea.Cmd
				s.input, cmd = s.input.Update(msg)
				return m, cmd
			}
			return m, nil
		}
		switch msg.String() {
		case "esc", "q":
			m.mode = modeKeys
		case "left", "right":
			s.touch = !s.touch
		case "e":
			if s.root == nil || s.root.Version != 2 {
				s.err = "no LUKS2 root volume found"
				return m, nil
			}
			unlock := "pin+touch"
			if s.touch {
				unlock = "touch"
			}
			cmd, err := elevate.SelfTUI("--keyring", m.cfg.KeyringPath, "luks", "enroll", "--unlock", unlock, "--tui", sockArg)
			if err != nil {
				s.err = err.Error()
				return m, nil
			}
			return m.startRun(runJob{
				title:    "Enroll a key into the root volume",
				lines:    []string{"the new key alone, or next to an enrolled key"},
				cmd:      cmd,
				key:      m.onlyKey(),
				noCancel: true,
				hold:     true,
				outLines: 8,
				back:     modeLUKS,
				done: func(r runResult) tea.Msg {
					return luksDoneMsg{what: "enroll a key", err: r.err}
				},
			})
		case "m":
			switch {
			case s.boot.Method != "encrypt":
				s.err = "boot does not use the old \"encrypt\" hook; nothing to switch"
				return m, nil
			case s.enrolledCount() == 0:
				s.err = "enroll at least one key first (e) — otherwise the switch only adds a key prompt nobody can answer"
				return m, nil
			}
			return m.luksRun("switch boot to the systemd initramfs (FIDO2 unlock)", true, "migrate")
		case "P":
			switch {
			case s.boot.Method != "sd-encrypt":
				s.err = "boot does not unlock with a key yet (m)"
				return m, nil
			case s.enrolledCount() < 2:
				s.err = "enroll at least two keys first (e)"
				return m, nil
			}
			cmd, err := elevate.SelfTUI("--keyring", m.cfg.KeyringPath, "luks", "passphrase", "remove", "--tui", sockArg)
			if err != nil {
				s.err = err.Error()
				return m, nil
			}
			return m.startRun(runJob{
				title:    "Remove the disk passphrase",
				cmd:      cmd,
				key:      m.onlyKey(),
				noCancel: true, // esc answers an open question with "cancel"; the wipe itself is never cut off
				hold:     true,
				outLines: 8,
				back:     modeLUKS,
				done: func(r runResult) tea.Msg {
					return luksDoneMsg{what: "remove the disk passphrase", err: r.err}
				},
			})
		case "H":
			if s.root == nil {
				s.err = "no LUKS root volume found"
				return m, nil
			}
			s.input = textinput.New()
			s.input.CharLimit = 200
			s.input.Width = 50
			s.input.SetValue(removableDir())
			s.input.Focus()
			s.asking = true
			return m, textinput.Blink
		case "s":
			cmd, err := elevate.SelfTUI("--keyring", m.cfg.KeyringPath, "luks", "status")
			if err != nil {
				s.err = err.Error()
				return m, nil
			}
			return m.startRun(runJob{
				title:    "Read the LUKS headers",
				cmd:      cmd,
				key:      m.onlyKey(),
				hold:     true,
				outLines: 40,
				back:     modeLUKS,
				done: func(r runResult) tea.Msg {
					return luksDoneMsg{what: "read the LUKS headers", err: r.err}
				},
			})
		case "R":
			return m.luksRun("repair boot images and GRUB menu", true, "repair")
		}
	}
	return m, nil
}

func (s luksScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Disk encryption (LUKS)") + "\n")
	b.WriteString("\n")

	if s.pending != "" {
		b.WriteString(errStyle.Render("! A boot change ("+s.pending+") was interrupted before it was rebuilt and verified.\n  Press R to repair BEFORE rebooting.") + "\n\n")
	}
	if s.root == nil {
		b.WriteString(warnStyle.Render("The root filesystem is not on a LUKS volume yking can see.") + "\n")
	} else {
		lvm := ""
		if s.root.RootLV {
			lvm = " → LVM"
		}
		fmt.Fprintf(&b, "Root volume:  %s · LUKS%d · %s%s\n", s.root.Device, s.root.Version, s.root.Mapper, lvm)
	}
	switch s.boot.Method {
	case "encrypt":
		b.WriteString("Boot unlock:  " + warnStyle.Render("old \"encrypt\" hook — enrolled keys are IGNORED at boot (passphrase only)") + "\n")
	case "sd-encrypt":
		b.WriteString("Boot unlock:  " + okStyle.Render("systemd (sd-encrypt) — key (PIN, then touch) or passphrase") + "\n")
	default:
		b.WriteString("Boot unlock:  " + dimStyle.Render("unknown") + "\n")
	}
	if _, err := os.Stat(luks.GrubFallback); err == nil {
		b.WriteString(dimStyle.Render("              GRUB has the \"yking fallback\" entry (old initramfs, passphrase)") + "\n")
	}
	for _, p := range s.boot.Problems {
		b.WriteString(warnStyle.Render("  ! "+p) + "\n")
	}

	if sv := s.snap.Volume(s.rootUUID()); sv != nil {
		b.WriteString(s.slotTable(sv))
	} else {
		b.WriteString("\n" + dimStyle.Render("Keyslots unknown — s reads them (sudo)") + "\n")
		b.WriteString("\nKeys on the root volume (per yking's keyring):\n")
		for _, k := range s.keys {
			if e := s.enrolled(k); e != nil {
				mode := "PIN + touch"
				if !e.PINRequired {
					mode = "touch"
				}
				b.WriteString(okStyle.Render(fmt.Sprintf("  ✓ %-12s slot %d · %s", k.Label, e.Keyslot, mode)) + "\n")
			} else {
				b.WriteString(dimStyle.Render(fmt.Sprintf("  · %-12s not enrolled", k.Label)) + "\n")
			}
		}
	}
	if n := s.enrolledCount(); n == 1 {
		b.WriteString(warnStyle.Render("  ! only one key enrolled — add a second") + "\n")
	}
	others := false
	for _, v := range s.vols {
		if v.Root {
			continue
		}
		if !others {
			b.WriteString("\nOther volumes " + dimStyle.Render("(not handled yet)") + "\n")
			others = true
		}
		line := fmt.Sprintf("  %s · LUKS%d", v.Device, v.Version)
		if sv := s.snap.Volume(v.UUID); sv != nil && sv.Err == "" {
			if sv.Cipher != "" {
				line += " · " + sv.Cipher
			}
			line += " · " + slotSummary(sv.Slots)
		}
		if v.Version != 2 {
			line += " · FIDO2 needs LUKS2"
		}
		b.WriteString(dimStyle.Render(line) + "\n")
	}

	unlock := "◂ PIN + touch ▸"
	if s.touch {
		unlock = "◂ touch only ▸"
	}
	b.WriteString("\n" + selStyle.Render("e") + " enroll a key (alone, or next to an enrolled key)   unlock at boot: " + unlock + "\n")
	if s.boot.Method == "encrypt" {
		b.WriteString(selStyle.Render("m") + " switch boot to FIDO2 unlock (keeps a fallback entry)\n")
	}
	if s.boot.Method == "sd-encrypt" && s.enrolledCount() >= 2 {
		b.WriteString(selStyle.Render("P") + " remove the passphrase (recovery key or key-only)\n")
	}
	b.WriteString(selStyle.Render("H") + " back up the header   " + selStyle.Render("s") + " full status   " + selStyle.Render("R") + " repair boot images\n")
	if s.asking {
		b.WriteString("\nCopy to folder " + s.input.View() + "\n")
		b.WriteString(dimStyle.Render("  off this disk (USB stick); empty = only /var/lib/yking/luks") + "\n")
	}
	b.WriteString(dimStyle.Render("\nboot fails? unplug the key → passphrase or recovery key, or GRUB \"yking fallback\"") + "\n")
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}

func (s luksScreen) rootUUID() string {
	if s.root == nil {
		return ""
	}
	return s.root.UUID
}

// owner is the registered key recorded for keyslot id on the root volume.
func (s luksScreen) owner(id int) string {
	for _, k := range s.keys {
		for _, l := range k.LUKS {
			if l.DeviceUUID == s.rootUUID() && l.Keyslot == id {
				return k.Label
			}
		}
	}
	return ""
}

// slotTable shows the root volume's keyslots as root last read them.
func (s luksScreen) slotTable(sv *luks.SnapVolume) string {
	var b strings.Builder
	if sv.Err != "" {
		return "\n" + errStyle.Render("Keyslots: "+sv.Err) + "\n"
	}
	pass, rec := 0, 0
	for _, sl := range sv.Slots {
		switch sl.Kind {
		case luks.KindPassphrase:
			pass++
		case luks.KindRecovery:
			rec++
		}
	}
	yes := func(n int, set string) string {
		if n == 0 {
			return dimStyle.Render("none")
		}
		return okStyle.Render(set)
	}
	if sv.Cipher != "" {
		fmt.Fprintf(&b, "Cipher:       %s\n", sv.Cipher)
	}
	fmt.Fprintf(&b, "Passphrase:   %s   Recovery key: %s\n", yes(pass, "set"), yes(rec, "set"))
	b.WriteString("\nKeyslots " + dimStyle.Render("read "+ago(luksNow().Sub(s.snap.ReadAt))+" · s rereads") + "\n")
	onDisk := map[int]bool{}
	for _, sl := range sv.Slots {
		onDisk[sl.ID] = true
		var what string
		switch sl.Kind {
		case luks.KindPassphrase:
			what = "passphrase"
		case luks.KindRecovery:
			what = "recovery key"
		case luks.KindFIDO2:
			who := s.owner(sl.ID)
			mode := "PIN + touch"
			switch {
			case sl.PIN && !sl.Touch:
				mode = "PIN only"
			case !sl.PIN:
				mode = "touch only"
			}
			if who == "" {
				what = fmt.Sprintf("FIDO2  %-12s %s", warnStyle.Render("unknown key"), dimStyle.Render(mode))
			} else {
				what = fmt.Sprintf("FIDO2  %-12s %s", who, dimStyle.Render(mode))
			}
		default:
			what = sl.Kind
		}
		fmt.Fprintf(&b, "  %2d  %s  %s\n", sl.ID, what, dimStyle.Render(sl.KDF))
	}
	var missing []string
	for _, k := range s.keys {
		for _, l := range k.LUKS {
			if l.DeviceUUID == s.rootUUID() && !onDisk[l.Keyslot] {
				missing = append(missing, fmt.Sprintf("%s (slot %d)", k.Label, l.Keyslot))
			}
		}
	}
	if len(missing) > 0 {
		b.WriteString(warnStyle.Render("  ! recorded but not on the disk: "+strings.Join(missing, ", ")) + "\n")
	}
	var none []string
	for _, k := range s.keys {
		if s.enrolled(k) == nil {
			none = append(none, k.Label)
		}
	}
	if len(none) > 0 {
		b.WriteString(dimStyle.Render("  not enrolled: "+strings.Join(none, ", ")) + "\n")
	}
	return b.String()
}

// slotSummary is "2 passphrase, 1 FIDO2".
func slotSummary(slots []luks.SnapSlot) string {
	n := map[string]int{}
	var order []string
	for _, sl := range slots {
		if n[sl.Kind] == 0 {
			order = append(order, sl.Kind)
		}
		n[sl.Kind]++
	}
	if len(order) == 0 {
		return "no slots"
	}
	var parts []string
	for _, k := range order {
		name := map[string]string{luks.KindPassphrase: "passphrase", luks.KindFIDO2: "FIDO2", luks.KindRecovery: "recovery"}[k]
		if name == "" {
			name = k
		}
		parts = append(parts, fmt.Sprintf("%d %s", n[k], name))
	}
	return strings.Join(parts, ", ")
}

// ago renders an age: "just now", "3 min ago", …
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}
