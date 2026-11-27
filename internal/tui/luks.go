package tui

import (
	"fmt"
	"os"
	"strings"

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
	touch   bool // enroll with touch only (else PIN + touch)
	err     string
}

type luksDoneMsg struct {
	what string
	err  error
}

var (
	luksVolumes      = luks.Volumes
	luksDiscoverBoot = luks.DiscoverBoot
	luksPending      = luks.Pending
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
			return m.luksRun("enroll the plugged-in key into the root volume", true, "enroll", "--unlock", unlock)
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
		case "s":
			return m.luksRun("LUKS status", true, "status")
		case "R":
			return m.luksRun("repair boot images and GRUB menu", true, "repair")
		}
	}
	return m, nil
}

func (s luksScreen) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Disk encryption (LUKS)") + "\n")
	b.WriteString(dimStyle.Render("The passphrase slot always stays. Keys are added as extra slots; nothing is stored on the key.") + "\n\n")

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
	if n := s.enrolledCount(); n == 1 {
		b.WriteString(warnStyle.Render("  ! only one key enrolled — enroll a second one (the passphrase still works either way)") + "\n")
	}
	for _, v := range s.vols {
		if v.Root {
			continue
		}
		note := ""
		if v.Version != 2 {
			note = " (LUKS1: FIDO2 needs LUKS2)"
		}
		b.WriteString(dimStyle.Render(fmt.Sprintf("  other volume %s · LUKS%d%s — not handled yet", v.Device, v.Version, note)) + "\n")
	}

	unlock := "◂ PIN + touch ▸"
	if s.touch {
		unlock = "◂ touch only ▸"
	}
	b.WriteString("\n" + selStyle.Render("e") + " enroll the plugged-in key   unlock at boot: " + unlock + dimStyle.Render("  (PIN only is impossible: the YubiKey insists on a touch)") + "\n")
	if s.boot.Method == "encrypt" {
		b.WriteString(selStyle.Render("m") + " switch boot to FIDO2 unlocking (keeps a fallback GRUB entry with the old way)\n")
	}
	b.WriteString(selStyle.Render("s") + " full status incl. keyslots (sudo)   " + selStyle.Render("R") + " repair boot images\n")
	b.WriteString(dimStyle.Render("\nAt boot: enter the PIN, then touch the blinking key. If it fails with the key plugged in,\nunplug it and reboot (passphrase after ~30 s) or pick \"yking fallback\" in GRUB.") + "\n")
	if s.err != "" {
		b.WriteString("\n" + errStyle.Render(s.err) + "\n")
	}
	return b.String()
}
