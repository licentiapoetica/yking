package events

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// System implementations of Deps (root, inside the systemd unit).

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return out, fmt.Errorf("%s: %v %s", name, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return out, err
	}
	return out, nil
}

// LoginctlSessions lists sessions of users via loginctl.
func LoginctlSessions(users []string) ([]Session, error) {
	out, err := run(context.Background(), "loginctl", "list-sessions", "--json=short")
	if err != nil {
		return nil, err
	}
	var list []struct {
		Session string `json:"session"`
		User    string `json:"user"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parsing loginctl output: %w", err)
	}
	var res []Session
	for _, s := range list {
		if !slices.Contains(users, s.User) || !sessionIDRe.MatchString(s.Session) {
			continue
		}
		props, err := run(context.Background(), "loginctl", "show-session", s.Session, "-p", "LockedHint", "-p", "Type")
		if err != nil {
			continue
		}
		ses := Session{ID: s.Session, User: s.User}
		for _, l := range strings.Split(string(props), "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
			switch k {
			case "LockedHint":
				ses.Locked = v == "yes"
			case "Type":
				ses.Type = v
			}
		}
		res = append(res, ses)
	}
	return res, nil
}

// LoginctlLock locks one session.
func LoginctlLock(id string) error {
	if !sessionIDRe.MatchString(id) {
		return fmt.Errorf("bad session id %q", id)
	}
	_, err := run(context.Background(), "loginctl", "lock-session", id)
	return err
}

// WakeScreen asks the user's screensaver (on their session bus) to treat
// this as user activity, which turns the screen on and shows the unlock
// prompt. It does NOT unlock.
func WakeScreen(username string) error {
	if !userRe.MatchString(username) {
		return fmt.Errorf("invalid user %q", username)
	}
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	rt := fmt.Sprintf("/run/user/%d", uid)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "busctl", "--user", "call",
		"org.freedesktop.ScreenSaver", "/ScreenSaver", "org.freedesktop.ScreenSaver", "SimulateUserActivity")
	cmd.Env = []string{"XDG_RUNTIME_DIR=" + rt, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + rt + "/bus", "PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("busctl: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Logf logs to stderr (the journal, inside the unit).
func Logf(format string, args ...any) { fmt.Fprintf(os.Stderr, "yking-event: "+format+"\n", args...) }
