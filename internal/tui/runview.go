package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
)

func (m model) viewRun() string {
	r := m.run
	var b strings.Builder
	b.WriteString(titleStyle.Render(r.job.title) + "\n")
	for _, l := range r.job.lines {
		b.WriteString(dimStyle.Render("  "+l) + "\n")
	}
	for i, st := range r.stages {
		mark := okStyle.Render("✓")
		if i == len(r.stages)-1 && r.phase != phaseDone {
			mark = selStyle.Render("▸")
		}
		b.WriteString("  " + mark + " " + st + "\n")
	}
	b.WriteString("\n")
	spin := selStyle.Render(spinner[m.frame%len(spinner)])

	switch {
	case r.phase == phaseDone:
		if r.result.err == nil {
			b.WriteString("  " + okStyle.Bold(true).Render("✓ done") + "\n")
		} else {
			b.WriteString("  " + errStyle.Bold(true).Render("✗ "+r.result.err.Error()) + "\n")
		}

	case r.prompt != nil && r.kind == promptChoice:
		b.WriteString(paneStyle.Render(strings.TrimSpace(r.prompt.Prompt)) + "\n\n")
		var opts []string
		for _, o := range r.prompt.Options {
			opts = append(opts, selStyle.Render(o.Key)+" "+o.Label)
		}
		b.WriteString("  " + strings.Join(opts, "   ") + "\n")
		if d := r.prompt.Deadline; !d.IsZero() {
			left := max(time.Until(d).Round(time.Second), 0)
			b.WriteString("\n  " + warnStyle.Render(fmt.Sprintf("▶ automatic roll back in %d:%02d", int(left.Minutes()), int(left.Seconds())%60)) + "\n")
		}

	case r.phase == phaseWaiting:
		k := r.job.need
		b.WriteString(drawKey(m.frame, k.Label, false) + "\n")
		b.WriteString("  " + warnStyle.Render("Plug in ") + keyName2(k) + "\n")
		b.WriteString(dimStyle.Render("  "+r.job.needWhy) + "\n\n")
		b.WriteString("  " + spin + dimStyle.Render(" waiting…") + "\n")
		if r.waitNote != "" {
			b.WriteString(dimStyle.Render("  "+r.waitNote) + "\n")
		}

	case r.prompt != nil && r.kind == promptPIN:
		k := r.promptKey
		if k != nil {
			b.WriteString(drawKey(m.frame, k.Label, false) + "\n")
			tries := ""
			if f := m.fidoOf(k.Serial); f != nil && f.PINRetries >= 0 {
				tries = fmt.Sprintf(" — %d tries left", f.PINRetries)
			}
			b.WriteString("  FIDO2 PIN of " + keyName2(k) + dimStyle.Render(tries) + "\n")
			if r.promptFile != "" {
				b.WriteString(dimStyle.Render("  for SSH key "+r.promptFile) + "\n")
			}
		} else {
			b.WriteString("  FIDO2 PIN\n" + dimStyle.Render("  "+r.prompt.Prompt) + "\n")
		}
		b.WriteString(dimStyle.Render("  asked once") + "\n\n")
		b.WriteString("  PIN " + r.input.View() + "\n")

	case r.prompt != nil && r.kind == promptYesNo:
		b.WriteString(paneStyle.Render(strings.TrimSpace(r.prompt.Prompt)) + "\n\n")
		b.WriteString("  " + selStyle.Render("y") + " yes   " + selStyle.Render("n") + " no\n")

	case r.prompt != nil:
		b.WriteString("  " + selStyle.Render(strings.TrimSuffix(strings.TrimSpace(r.prompt.Prompt), ":")) + "\n")
		b.WriteString("\n")
		b.WriteString("  " + r.input.View() + "\n")

	case r.touching:
		k := r.touchKey
		if k != nil {
			b.WriteString(drawKey(m.frame, k.Label, true) + "\n")
			b.WriteString("  " + okStyle.Bold(true).Render("Touch ") + keyName2(k) + okStyle.Bold(true).Render(" now") + "\n")
			if r.touchFile != "" {
				b.WriteString(dimStyle.Render("  SSH key "+r.touchFile) + "\n")
			}
		} else {
			b.WriteString(drawKey(m.frame, "touch", true) + "\n")
			b.WriteString("  " + okStyle.Bold(true).Render("Touch the blinking YubiKey now") + "\n")
			if r.touch != nil {
				b.WriteString(dimStyle.Render("  "+r.touch.Prompt) + "\n")
			}
		}

	default:
		b.WriteString("  " + spin + " working…\n")
	}

	if r.note != "" {
		b.WriteString("\n  " + warnStyle.Render(r.note) + "\n")
	}
	if len(r.lines) > 0 {
		n := r.job.outLines
		if n == 0 {
			n = 3
		}
		if r.phase == phaseDone {
			n = max(n, 12)
		}
		b.WriteString("\n")
		for _, l := range lastN(r.lines, n) {
			b.WriteString(dimStyle.Render("  │ "+l) + "\n")
		}
	}
	return b.String()
}

// keyName2 is how a YubiKey is named in run panels: label, then serial.
func keyName2(k *keyring.Key) string {
	return selStyle.Render(fmt.Sprintf("%q", k.Label)) + dimStyle.Render(" (serial "+k.Serial+")")
}

func lastN(l []string, n int) []string {
	if len(l) > n {
		return l[len(l)-n:]
	}
	return l
}

func (m model) runHelp() string {
	r := m.run
	switch {
	case r.phase == phaseDone:
		return "enter continue"
	case r.prompt != nil && r.kind == promptChoice:
		var o []string
		for _, x := range r.prompt.Options {
			o = append(o, x.Key+" "+x.Label)
		}
		return strings.Join(o, " · ")
	case r.job.noCancel && r.prompt == nil:
		return "running…"
	case r.phase == phaseWaiting:
		return "s skip · esc cancel"
	case r.prompt != nil && r.kind == promptYesNo:
		return "y yes · n no"
	case r.prompt != nil:
		return "enter send · esc cancel"
	}
	return "esc cancel"
}
