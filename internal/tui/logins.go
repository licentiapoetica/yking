package tui

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/sshkey"
)

// loginKey is a key file offered for logging in to a server, with the
// YubiKey it needs (a yk-main file is only a handle for one YubiKey).
type loginKey struct {
	path  string
	owner *keyring.Key    // nil: not a registered YubiKey key (e.g. a legacy key)
	entry *keyring.SSHKey // owner's record of this file
}

func describeLogin(keys []keyring.Key, path string) loginKey {
	l := loginKey{path: path}
	if path == "" {
		return l
	}
	for i := range keys {
		for j := range keys[i].SSH {
			if keys[i].SSH[j].Path == path {
				l.owner, l.entry = &keys[i], &keys[i].SSH[j]
				return l
			}
		}
	}
	return l
}

// onHost reports whether the key is recorded as deployed to target's host
// (any login).
func (l loginKey) onHost(target string) bool {
	if l.entry == nil {
		return false
	}
	_, host := sshkey.SplitTarget(target)
	return slices.ContainsFunc(l.entry.Hosts, func(h string) bool {
		_, hh := sshkey.SplitTarget(h)
		return hh == host
	})
}

// hint describes the choice: which YubiKey, whether it is plugged in and
// (with a target) whether the server knows the key.
func (l loginKey) hint(connected map[string]bool, target string) string {
	if l.path == "" {
		return dimStyle.Render("ssh default")
	}
	name := selStyle.Render(filepath.Base(l.path))
	if l.owner == nil {
		return name + dimStyle.Render(" · regular key")
	}
	parts := []string{dimStyle.Render(" · " + l.owner.Label)}
	if connected[l.owner.Serial] {
		parts = append(parts, okStyle.Render("plugged in"))
	} else {
		parts = append(parts, warnStyle.Render("not plugged in"))
	}
	if _, host := sshkey.SplitTarget(target); host != "" && sshkey.ValidTarget(target) == nil {
		if l.onHost(target) {
			parts = append(parts, okStyle.Render("on this server"))
		} else {
			parts = append(parts, warnStyle.Render("not on this server"))
		}
	}
	return name + strings.Join(parts, dimStyle.Render(" · "))
}

// serialPresent asks ykman (read-only, no touch) whether serial is
// connected. Without a client (tests) it reports present.
func (m model) serialPresent(serial string) (bool, error) {
	if m.cfg.Client == nil {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serials, err := m.cfg.Client.ListSerials(ctx)
	if err != nil {
		return false, err
	}
	return slices.Contains(serials, serial), nil
}

func connectedSerials(m model) map[string]bool {
	c := map[string]bool{}
	if m.rep != nil {
		for _, k := range m.rep.Keys {
			c[k.Serial] = true
		}
	}
	return c
}
