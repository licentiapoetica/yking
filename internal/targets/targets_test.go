package targets

import (
	"os"
	"strings"
	"testing"
	"time"

	"yking/internal/events"
	"yking/internal/plan"
)

// A plan built like the TUI builds it must pass the real elevated check
// (real target dirs, strict validators). Nothing is written.
func TestEventsPlanPassesElevatedCheck(t *testing.T) {
	self, _ := os.Executable() // an ELF binary
	cfg := events.Config{Version: 1, Users: []string{"alice"}, Triggers: []string{"11111111"}, OnRemove: events.Remove{Lock: true}}
	conf, _ := cfg.Encode()
	p := plan.New("events", time.Now())
	if err := p.Install(events.BinaryPath, self, 0o755); err != nil {
		t.Fatal(err)
	}
	p.WriteFile(events.ConfigPath, conf, 0o644)
	p.WriteFile(events.RulePath, []byte(events.Rule), 0o644)
	p.WriteFile(events.UnitPath, []byte(events.Unit), 0o644)
	if err := Applier().Check(p); err != nil {
		t.Fatalf("elevated check refused yking's own plan: %v", err)
	}

	// Tampering with any piece is refused.
	for name, mod := range map[string]func(*plan.Plan){
		"rule":   func(q *plan.Plan) { q.Steps[2].Content += "RUN+=\"/bin/sh\"\n" },
		"unit":   func(q *plan.Plan) { q.Steps[3].Content = strings.Replace(q.Steps[3].Content, events.BinaryPath, "/tmp/x", 1) },
		"config": func(q *plan.Plan) { q.Steps[1].Content = "version = 1\nusers = [\"root\"]\n" },
		"path":   func(q *plan.Plan) { q.Steps[2].Path = "/etc/udev/rules.d/99-evil.rules" },
		"bin":    func(q *plan.Plan) { q.Steps[0].Path = "/usr/local/bin/sudo" },
	} {
		q := *p
		q.Steps = append([]plan.Step(nil), p.Steps...)
		mod(&q)
		if err := Applier().Check(&q); err == nil {
			t.Errorf("tampered %s accepted", name)
		}
	}
}

func TestReloads(t *testing.T) {
	r := Reloads([]string{events.RulePath, events.UnitPath, "/etc/yking/events.toml"})
	if len(r) != 2 || r[0][0] != "udevadm" || r[1][0] != "systemctl" {
		t.Errorf("reloads = %v", r)
	}
	if len(Reloads([]string{"/etc/pam.d/sudo"})) != 0 {
		t.Error("PAM change triggered a reload")
	}
}
