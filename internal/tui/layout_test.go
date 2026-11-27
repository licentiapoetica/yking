package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/licentiapoetica/yking/internal/detect"
	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pgp"
	"github.com/licentiapoetica/yking/internal/ykman"
)

func keysModel(t *testing.T, w, h int) model {
	kr := keyring.New()
	k, _ := kr.Add("11111111", "daily", keyring.RoleDaily, t0())
	kr.Add("22222222", "home-backup", keyring.RoleHomeBackup, t0())
	rep := &detect.Report{Keys: []detect.KeyReport{{Serial: "11111111", Known: k, Info: ykman.DeviceInfo{Firmware: "5.7.1", DeviceType: "YubiKey 5 NFC"}}},
		Missing: []keyring.Key{kr.Keys[1]}}
	return send(t, model{width: w, height: h}, scanDoneMsg{rep: rep, kr: kr})
}

func checkFits(t *testing.T, v string, w, h int) {
	t.Helper()
	lines := strings.Split(v, "\n")
	if len(lines) > h {
		t.Errorf("%dx%d: %d lines:\n%s", w, h, len(lines), v)
	}
	for _, l := range lines {
		if ansi.StringWidth(l) > w {
			t.Errorf("%dx%d: line wider than %d: %q", w, h, w, ansi.Strip(l))
		}
	}
}

func TestLayoutFitsEverySize(t *testing.T) {
	for _, sz := range [][2]int{{30, 10}, {45, 16}, {60, 24}, {80, 20}, {120, 40}} {
		w, h := sz[0], sz[1]
		m := keysModel(t, w, h)
		m.status = errStyle.Render("Key test FAILED: a rather long explanation that certainly needs wrapping at small widths")
		checkFits(t, m.View(), w, h)
		if v := ansi.Strip(m.View()); !strings.Contains(v, "quit") && !strings.Contains(v, "all keys") {
			t.Errorf("%dx%d: help bar lost", w, h)
		}
		o := send(t, m, keyMsg("?"))
		checkFits(t, o.View(), w, h)
		if !o.helpOpen || !strings.Contains(ansi.Strip(o.View()), "enroll") {
			t.Errorf("%dx%d: ? does not list the keys:\n%s", w, h, o.View())
		}
		if o = send(t, o, keyMsg("?")); o.helpOpen {
			t.Error("? does not close")
		}
	}
}

func TestLayoutFollowsCursor(t *testing.T) {
	_, s := pgpFixture()
	for i := range 30 {
		s.ids = append(s.ids, pgp.Identity{Fingerprint: fmt.Sprintf("%040d", i), UIDs: []string{fmt.Sprintf("Test %02d <t%02d@example.com>", i, i)}})
	}
	m := model{width: 70, height: 16, mode: modePGP, pgp: s}
	m.pgp.cursor = 25
	v := m.View()
	checkFits(t, v, 70, 16)
	if !strings.Contains(v, "▸") || !strings.Contains(v, "Test 24") || !strings.Contains(v, "↑ more") {
		t.Fatalf("cursor not followed:\n%s", v)
	}
	// PgUp/PgDn scroll when nothing pins the view.
	m.pgp.cursor = 0
	if v := m.View(); !strings.Contains(v, "↓ more") || strings.Contains(v, "↑ more") {
		t.Fatalf("top:\n%s", v)
	}
}

func TestWrappedLinesCarryTheirColour(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	defer lipgloss.SetColorProfile(termenv.Ascii)
	lines := fitLines("  "+errStyle.Render("one two three four five six seven eight"), 14)
	if len(lines) < 3 {
		t.Fatalf("%q", lines)
	}
	for _, l := range lines[1:] {
		if !strings.HasPrefix(ansi.Strip(l), "  ") || !strings.Contains(l, "\x1b[") || !strings.HasSuffix(l, "\x1b[0m") {
			t.Errorf("continuation %q", l)
		}
	}
}

func TestTooSmall(t *testing.T) {
	m := keysModel(t, 20, 8)
	if !strings.Contains(m.View(), "too small") {
		t.Fatal(m.View())
	}
}

func TestWrapKeepsHyphenatedWords(t *testing.T) {
	got := fitLines("Alice Example  AAAA…1111  until 2029-11-06", 36)
	if len(got) != 2 || got[1] != "2029-11-06" && !strings.HasSuffix(got[1], "2029-11-06") {
		t.Fatalf("%q", got)
	}
}

func TestMouseWheelScrolls(t *testing.T) {
	_, s := pgpFixture()
	for i := range 30 {
		s.ids = append(s.ids, pgp.Identity{Fingerprint: fmt.Sprintf("%040d", i), UIDs: []string{fmt.Sprintf("Test %02d <t%02d@example.com>", i, i)}})
	}
	m := model{width: 70, height: 16, mode: modePGP, pgp: s}
	down := tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown}
	m = send(t, m, down, down)
	v := m.View()
	if !strings.Contains(v, "↑ more") || strings.Contains(v, "▸") {
		t.Fatalf("wheel did not scroll away from the cursor:\n%s", v)
	}
	m = send(t, m, keyMsg("down")) // a key brings the cursor back into view
	if v := m.View(); !strings.Contains(v, "▸") {
		t.Fatalf("cursor not shown after a key:\n%s", v)
	}
	m = send(t, m, tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if m.mode != modePGP {
		t.Fatal("click changed the screen")
	}
}
