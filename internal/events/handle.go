package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

// Session is a logind session of a configured user.
type Session struct {
	ID     string
	User   string
	Locked bool
	Type   string // x11, wayland, tty
}

// Deps are the side effects, swappable for tests.
type Deps struct {
	Serials  func() ([]string, error) // connected YubiKeys
	Sessions func(users []string) ([]Session, error)
	Lock     func(id string) error
	// LockBlocked returns why locking now would lock the user out (a lock
	// screen that cannot prompt for an absent key); "" = safe. Nil = safe.
	LockBlocked func() string
	Wake        func(user string) error
	SudoReset   func(user string) error
	StatePath   string
	Log         func(format string, args ...any)
	SettleWait  time.Duration // before scanning on add (device still appearing)
}

// Result reports what Handle did (also logged).
type Result struct {
	Added, Removed []string
	Actions        []string
}

// Handle processes one add/remove event.
func Handle(action string, cfg *Config, registered []string, d Deps) (*Result, error) {
	if action != "add" && action != "remove" {
		return nil, fmt.Errorf("unknown action %q", action)
	}
	if action == "add" && d.SettleWait > 0 {
		time.Sleep(d.SettleWait)
	}
	now, err := d.Serials()
	if err != nil {
		return nil, fmt.Errorf("listing keys: %w", err)
	}
	sort.Strings(now)
	prev, known := readState(d.StatePath)
	if err := writeState(d.StatePath, now); err != nil {
		d.Log("warning: cannot save state: %v", err)
	}

	r := &Result{}
	for _, s := range now {
		if !slices.Contains(prev, s) {
			r.Added = append(r.Added, s)
		}
	}
	for _, s := range prev {
		if !slices.Contains(now, s) {
			r.Removed = append(r.Removed, s)
		}
	}

	switch action {
	case "remove":
		// Act when the last trigger key is gone: a trigger key still
		// plugged in means the user is still there (e.g. swapping keys).
		// Without state (first event since boot) a trigger key need not
		// be seen leaving.
		trigger := !known
		for _, s := range r.Removed {
			if cfg.IsTrigger(s, registered) {
				trigger = true
			}
		}
		for _, s := range now {
			if cfg.IsTrigger(s, registered) {
				trigger = false
			}
		}
		if !trigger {
			d.Log("remove: a trigger key is still connected or none was removed (removed %v, still connected %v); nothing to do", r.Removed, now)
			return r, nil
		}
		if cfg.OnRemove.SudoReset {
			for _, u := range cfg.Users {
				if err := d.SudoReset(u); err != nil {
					d.Log("sudo reset for %s failed: %v", u, err)
				} else {
					r.Actions = append(r.Actions, "sudo-reset "+u)
				}
			}
		}
		lock := cfg.OnRemove.Lock
		if lock && d.LockBlocked != nil {
			if why := d.LockBlocked(); why != "" {
				d.Log("remove: not locking: %s", why)
				r.Actions = append(r.Actions, "lock-skipped")
				lock = false
			}
		}
		if lock {
			ss, err := d.Sessions(cfg.Users)
			if err != nil {
				return r, fmt.Errorf("listing sessions: %w", err)
			}
			for _, s := range ss {
				if s.Locked || (s.Type != "x11" && s.Type != "wayland") {
					continue
				}
				if err := d.Lock(s.ID); err != nil {
					d.Log("locking session %s failed: %v", s.ID, err)
				} else {
					r.Actions = append(r.Actions, "lock "+s.ID)
				}
			}
		}
	case "add":
		if !cfg.OnInsert.Wake || len(r.Added) == 0 {
			return r, nil
		}
		registeredAdded := false
		for _, s := range r.Added {
			if slices.Contains(registered, s) {
				registeredAdded = true
			}
		}
		if !registeredAdded {
			d.Log("add: no registered key added (%v); nothing to do", r.Added)
			return r, nil
		}
		ss, err := d.Sessions(cfg.Users)
		if err != nil {
			return r, fmt.Errorf("listing sessions: %w", err)
		}
		woken := map[string]bool{}
		for _, s := range ss {
			if s.Locked && !woken[s.User] {
				if err := d.Wake(s.User); err != nil {
					d.Log("waking %s failed: %v", s.User, err)
				} else {
					woken[s.User] = true
					r.Actions = append(r.Actions, "wake "+s.User)
				}
			}
		}
	}
	d.Log("%s: added %v removed %v → %v", action, r.Added, r.Removed, r.Actions)
	return r, nil
}

func readState(path string) ([]string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var s []string
	if json.Unmarshal(b, &s) != nil {
		return nil, false
	}
	return s, true
}

func writeState(path string, serials []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if serials == nil {
		serials = []string{}
	}
	b, _ := json.Marshal(serials)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SudoTimestampDir is where sudo keeps cached authentication per user.
var SudoTimestampDir = "/run/sudo/ts"

// ResetSudo removes user's sudo timestamp file (like `sudo -K` for them).
func ResetSudo(user string) error {
	if !userRe.MatchString(user) {
		return fmt.Errorf("invalid user %q", user)
	}
	err := os.Remove(filepath.Join(SudoTimestampDir, user))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
