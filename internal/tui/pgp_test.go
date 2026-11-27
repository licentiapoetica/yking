package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/pgp"
	"github.com/licentiapoetica/yking/internal/ykman"
)

const (
	pgpPrimary = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"
	pgpEnc     = "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222"
	pgpSig     = "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333"
)

func pgpFixture() (pgp.Identity, pgpScreen) {
	id := pgp.Identity{Fingerprint: pgpPrimary, UIDs: []string{"Alice Example <alice@example.com>"}, Where: pgp.WhereDisk,
		Subkeys: []pgp.Subkey{
			{Fingerprint: pgpEnc, Usage: "e", Algo: "cv25519", Where: pgp.WhereDisk, Created: time.Unix(1, 0)},
			{Fingerprint: pgpSig, Usage: "s", Algo: "ed25519", Where: pgp.WhereDisk, Created: time.Unix(2, 0)},
		}}
	card := pgpCard{key: keyring.Key{Serial: "11111111", Label: "offsite", Role: keyring.RoleOffsite},
		info:  ykman.OpenPGPInfo{AdminPINTries: 3, PINTries: 3},
		slots: map[string]ykman.PGPSlot{"sig": {Empty: true}, "dec": {Empty: true}, "aut": {Empty: true}}}
	kr := &keyring.Keyring{Version: 1, Keys: []keyring.Key{card.key}}
	return id, pgpScreen{ids: []pgp.Identity{id}, cards: []pgpCard{card}, kr: kr, scdOK: true}
}

func TestPGPTarget(t *testing.T) {
	id, s := pgpFixture()
	if _, why := s.target(id); why != "" {
		t.Fatal(why)
	}
	s.others = 1
	if _, why := s.target(id); !strings.Contains(why, "only one") {
		t.Fatalf("two keys plugged: %q", why)
	}
	s.others = 0
	s.cards[0].slots["dec"] = ykman.PGPSlot{Fingerprint: "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"}
	if _, why := s.target(id); !strings.Contains(why, "another key") {
		t.Fatalf("occupied slot: %q", why)
	}
	s.cards[0].slots["dec"] = ykman.PGPSlot{Fingerprint: pgpEnc} // same key: fine
	if _, why := s.target(id); why != "" {
		t.Fatal(why)
	}
	s.cards[0].info.AdminPINTries = 1
	if _, why := s.target(id); why == "" {
		t.Fatal("1 Admin PIN try left must block")
	}
}

func TestPGPCardOnlyNeedsCopyAndCard(t *testing.T) {
	id, s := pgpFixture()
	if why := s.cardOnlyBlocked(id); !strings.Contains(why, "Copy") {
		t.Fatalf("%q", why)
	}
	k := &s.kr.Keys[0]
	k.PGP = []keyring.PGPKey{{Primary: pgpPrimary, Fingerprint: pgpSig, Slot: "sig"}, {Primary: pgpPrimary, Fingerprint: pgpEnc, Slot: "dec"}}
	if why := s.cardOnlyBlocked(id); why != "" {
		t.Fatal(why)
	}
	s.cards = nil
	if why := s.cardOnlyBlocked(id); !strings.Contains(why, "Plug in") {
		t.Fatalf("%q", why)
	}
	s.scdOK = false
	if why := s.cardOnlyBlocked(id); !strings.Contains(why, "(f)") {
		t.Fatalf("%q", why)
	}
	s.askOnly = true
	if v := s.view(); !strings.Contains(v, "only on one YubiKey") || !strings.Contains(v, "on: offsite") {
		t.Fatalf("view:\n%s", v)
	}
}
