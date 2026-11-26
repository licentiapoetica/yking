package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"yking/internal/elevate"
	"yking/internal/events"
	"yking/internal/keyring"
	"yking/internal/ykman"
)

// cmdEvent: yking event add|remove|status
func cmdEvent(c *ykman.Client, krPath string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: yking event add|remove|status")
	}
	b, err := os.ReadFile(events.ConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		if args[0] == "status" {
			fmt.Println("Plug/unplug actions are not set up (no " + events.ConfigPath + "). Set them up in the TUI (u).")
		}
		return nil // not configured: events do nothing
	}
	if err != nil {
		return err
	}
	cfg, err := events.Parse(b)
	if err != nil {
		return fmt.Errorf("%s: %w", events.ConfigPath, err)
	}
	kr, err := keyring.Load(krPath)
	if err != nil {
		return err
	}
	var registered []string
	for _, k := range kr.Keys {
		registered = append(registered, k.Serial)
	}

	if args[0] == "status" {
		fmt.Printf("Config %s: users %v, triggers %v (empty = any registered key)\n", events.ConfigPath, cfg.Users, cfg.Triggers)
		fmt.Printf("  on remove: lock=%v sudo_reset=%v · on insert: wake=%v\n", cfg.OnRemove.Lock, cfg.OnRemove.SudoReset, cfg.OnInsert.Wake)
		if st, err := os.ReadFile(filepath.Join(events.StateDir, "connected.json")); err == nil {
			fmt.Printf("  last seen connected: %s\n", st)
		}
		fmt.Println("  log: journalctl -u 'yking-event@*'")
		return nil
	}
	if !elevate.IsRoot() {
		return errors.New("yking event add|remove runs as root from yking-event@.service")
	}
	_, err = events.Handle(args[0], cfg, registered, events.Deps{
		Serials:    func() ([]string, error) { return c.ListSerials(context.Background()) },
		Sessions:   events.LoginctlSessions,
		Lock:       events.LoginctlLock,
		Wake:       events.WakeScreen,
		SudoReset:  events.ResetSudo,
		StatePath:  filepath.Join(events.StateDir, "connected.json"),
		Log:        events.Logf,
		SettleWait: 1500 * time.Millisecond,
	})
	return err
}
