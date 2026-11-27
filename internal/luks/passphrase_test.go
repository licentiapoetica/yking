package luks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
)

const twoKeys = `{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"},"2":{"type":"luks2"}},
 "tokens":{"0":{"type":"systemd-fido2","keyslots":["1"]},"1":{"type":"systemd-fido2","keyslots":["2"]}}}`

func removalState(t *testing.T) RemovalState {
	h, err := ParseHeader([]byte(twoKeys))
	if err != nil {
		t.Fatal(err)
	}
	uuid := "11111111-2222-3333-4444-555555555555"
	return RemovalState{
		Volume: Volume{Device: "/dev/vda2", UUID: uuid, Version: 2, Root: true},
		Header: h,
		Boot:   Boot{Method: "sd-encrypt"},
		Keys: []keyring.Key{
			{Label: "daily", LUKS: []keyring.LUKSSlot{{DeviceUUID: uuid, Keyslot: 1}}},
			{Label: "offsite", LUKS: []keyring.LUKSSlot{{DeviceUUID: uuid, Keyslot: 2}}},
		},
	}
}

func TestRemovalBlocked(t *testing.T) {
	if why := RemovalBlocked(removalState(t)); why != "" {
		t.Fatal(why)
	}
	for name, mod := range map[string]func(*RemovalState){
		"not root":    func(s *RemovalState) { s.Volume.Root = false },
		"LUKS2":       func(s *RemovalState) { s.Volume.Version = 1 },
		"interrupted": func(s *RemovalState) { s.Pending = "20260101-000000-abcdef" },
		"FIDO2":       func(s *RemovalState) { s.Boot.Method = "encrypt" },
		"problems":    func(s *RemovalState) { s.Boot.Problems = []string{"x"} },
		"2 registered": func(s *RemovalState) {
			s.Keys = s.Keys[:1]
		},
		"slot gone": func(s *RemovalState) { // keyring says slot 2, header lacks it
			s.Keys[1].LUKS[0].Keyslot = 7
		},
	} {
		st := removalState(t)
		mod(&st)
		if RemovalBlocked(st) == "" {
			t.Errorf("%s: not blocked", name)
		}
	}
}

func TestParseRecoveryKey(t *testing.T) {
	key := strings.Repeat("cbdefghi-", 7) + "jklnrtuv"
	out := "A secret recovery key has been generated for this volume:\n\n    🔐 " + key + "\n\nPlease save this secret recovery key at a secure location.\nNew recovery key enrolled as key slot 3.\n"
	got, err := ParseRecoveryKey([]byte(out))
	if err != nil || string(got) != key {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := ParseRecoveryKey([]byte("nothing here")); err == nil {
		t.Fatal("no key accepted")
	}
}

func TestWipeNeedsPassphraseOrRecovery(t *testing.T) {
	keyOnly := `{"keyslots":{"1":{},"2":{}},"tokens":{"0":{"type":"systemd-fido2","keyslots":["1"]},"1":{"type":"systemd-fido2","keyslots":["2"]}}}`
	h, _ := ParseHeader([]byte(keyOnly))
	if _, err := WipeSelection(h, "1", nil, false); err == nil {
		t.Fatal("key-only volume: wipe allowed")
	}
	withRecovery := `{"keyslots":{"1":{},"2":{},"3":{}},"tokens":{"0":{"type":"systemd-fido2","keyslots":["1"]},"1":{"type":"systemd-fido2","keyslots":["2"]},"2":{"type":"systemd-recovery","keyslots":["3"]}}}`
	h, _ = ParseHeader([]byte(withRecovery))
	if got, err := WipeSelection(h, "1", nil, false); err != nil || len(got) != 1 {
		t.Fatalf("recovery key volume: %v %v", got, err)
	}
}

func TestCopyHeaderBackup(t *testing.T) {
	src := filepath.Join(t.TempDir(), "11111111-2222-3333-4444-555555555555-20260101-000000.img")
	os.WriteFile(src, []byte("header bytes"), 0o600)
	dir := t.TempDir()
	dst, err := CopyHeaderBackup(src, dir, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "header bytes" {
		t.Fatal("content")
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if _, err := CopyHeaderBackup(src, dir, -1, -1); err == nil {
		t.Fatal("existing file replaced")
	}
	if _, err := CopyHeaderBackup(src, "relative", -1, -1); err == nil {
		t.Fatal("relative folder accepted")
	}
	if !SameFilesystem(dir, dir) {
		t.Fatal("same fs")
	}
}

// An enrolled key unlocks, the new key enrolls: two PIN requests, answered
// in order; a third (a wrong PIN asked again) kills.
func TestAgentAnswersTwoPINsInOrder(t *testing.T) {
	dir := withAskDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	killed := make(chan bool, 1)
	done := make(chan error, 1)
	go func() {
		done <- AnswerPINs(ctx, 4242, [][]byte{[]byte("111111"), []byte("222222")}, func() { killed <- true })
	}()
	for i, want := range []string{"+111111", "+222222"} {
		select {
		case v := <-fakeAsk(t, dir, 4242, fmt.Sprint(i), "Please enter security token PIN:"):
			if v != want {
				t.Fatalf("request %d got %q", i, v)
			}
		case <-ctx.Done():
			t.Fatalf("request %d not answered", i)
		}
	}
	fakeAsk(t, dir, 4242, "x", "Please enter security token PIN:")
	if err := <-done; !errors.Is(err, ErrSecondRequest) || !<-killed {
		t.Fatalf("third request: %v", err)
	}
}

func TestEnrollWithKeyArgs(t *testing.T) {
	args, err := EnrollWithKeyArgs("/dev/vda2", "/dev/hidraw3", "/dev/hidraw5", UnlockPINTouch)
	if err != nil || args[0] != "--unlock-fido2-device=/dev/hidraw3" || !slices.Contains(args, "--fido2-device=/dev/hidraw5") {
		t.Fatalf("%v %v", args, err)
	}
	if _, err := EnrollWithKeyArgs("/dev/vda2", "/dev/hidraw3", "/dev/hidraw3", UnlockPINTouch); err == nil {
		t.Fatal("same device for unlock and enroll")
	}
}

func TestWipeWithKeyKeepsItsOwnSlot(t *testing.T) {
	keyOnly := `{"keyslots":{"1":{},"2":{},"3":{}},"tokens":{"0":{"type":"systemd-fido2","keyslots":["1"]},"1":{"type":"systemd-fido2","keyslots":["2"]},"2":{"type":"systemd-fido2","keyslots":["3"]}}}`
	h, _ := ParseHeader([]byte(keyOnly))
	if got, err := WipeSelectionWithKey(h, "3", nil, false, 1); err != nil || len(got) != 1 {
		t.Fatalf("lost key's slot: %v %v", got, err)
	}
	if _, err := WipeSelectionWithKey(h, "1", nil, false, 1); err == nil {
		t.Fatal("removed the opening key's own slot")
	}
	if _, err := WipeSelectionWithKey(h, "1,2,3", nil, false, 9); err == nil {
		t.Fatal("removed every FIDO2 slot")
	}
}

func TestSnapshot(t *testing.T) {
	h, err := ParseHeader([]byte(`{"keyslots":{"0":{"kdf":{"type":"argon2id"}},"4":{"kdf":{"type":"pbkdf2"}},"7":{"kdf":{"type":"argon2id"}}},
	 "tokens":{"0":{"type":"systemd-fido2","keyslots":["4"],"fido2-clientPin-required":true,"fido2-up-required":true},"1":{"type":"systemd-recovery","keyslots":["7"]}},
	 "segments":{"0":{"encryption":"aes-xts-plain64"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := SnapSlots(h)
	want := []SnapSlot{{ID: 0, Kind: KindPassphrase, KDF: "argon2id"}, {ID: 4, Kind: KindFIDO2, KDF: "pbkdf2", PIN: true, Touch: true}, {ID: 7, Kind: KindRecovery, KDF: "argon2id"}}
	if h.Cipher != "aes-xts-plain64" || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("%s %+v", h.Cipher, got)
	}
	cipher, slots := ParseLUKS1Dump([]byte("LUKS header information for /dev/sdx\n\nVersion:       \t1\nCipher name:   \taes\nCipher mode:   \txts-plain64\n\nKey Slot 0: ENABLED\n\tIterations: 1\nKey Slot 1: DISABLED\nKey Slot 2: ENABLED\n"))
	if cipher != "aes-xts-plain64" || len(slots) != 2 || slots[1].ID != 2 {
		t.Fatalf("%s %+v", cipher, slots)
	}

	SnapshotPath = filepath.Join(t.TempDir(), "luks-slots.json")
	if s, err := ReadSnapshot(); s != nil || err != nil {
		t.Fatal("missing snapshot should be nil, nil")
	}
	if err := TakeSnapshot(nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(SnapshotPath); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
}
