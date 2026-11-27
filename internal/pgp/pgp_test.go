package pgp

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

const (
	primary = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"
	encSub  = "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222"
	sigSub  = "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333"
	aid     = "D2760001240100000006111111110000" // serial 11111111
)

const listing = `sec:u:255:22:AAAA1111AAAA1111:1700000000:1900000000::u:::cESC:::+::ed25519:::0:
fpr:::::::::AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111:
grp:::::::::0000000000000000000000000000000000000001:
uid:u::::1700000000::HASH::Alice Example \x3calice@example.com\x3e::::::::::0:
uid:r::::1700000000::HASH::Old Alice <old@example.com>::::::::::0:
ssb:u:255:18:BBBB2222BBBB2222:1700000000:1900000000:::::e:::+::cv25519::
fpr:::::::::BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222:
grp:::::::::0000000000000000000000000000000000000002:
ssb:u:255:22:CCCC3333CCCC3333:1700000100:1900000000:::::s:::D2760001240100000006111111110000::ed25519::
fpr:::::::::CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333:
grp:::::::::0000000000000000000000000000000000000003:
ssb:e:255:22:DDDD4444DDDD4444:1600000000:1650000000:::::s:::#::ed25519::
fpr:::::::::DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444:
sec:u:255:22:EEEE5555EEEE5555:1700000000:::u:::scESC:::#::ed25519:::0:
fpr:::::::::EEEE5555EEEE5555EEEE5555EEEE5555EEEE5555:
uid:u::::1700000000::HASH::Bob Example <bob@example.com>::::::::::0:
`

func TestParseSecret(t *testing.T) {
	ids := ParseSecret([]byte(listing))
	if len(ids) != 2 {
		t.Fatalf("got %d identities", len(ids))
	}
	a := ids[0]
	if a.Fingerprint != primary || a.Name() != "Alice Example <alice@example.com>" || len(a.UIDs) != 1 || a.Where != WhereDisk {
		t.Fatalf("%+v", a)
	}
	if len(a.Subkeys) != 3 {
		t.Fatalf("subkeys %+v", a.Subkeys)
	}
	e := a.ForSlot("dec")
	if e == nil || e.Fingerprint != encSub || e.Keygrip != "0000000000000000000000000000000000000002" || e.Where != WhereDisk || e.Algo != "cv25519" {
		t.Fatalf("dec %+v", e)
	}
	s := a.ForSlot("sig") // the expired one is skipped
	if s == nil || s.Fingerprint != sigSub || s.Where != WhereCard || s.Card != aid {
		t.Fatalf("sig %+v", s)
	}
	if a.ForSlot("aut") != nil {
		t.Fatal("no auth subkey expected")
	}
	if ids[1].Where != WhereNone || !ids[1].Expires.IsZero() {
		t.Fatalf("%+v", ids[1])
	}
}

func TestAIDSerial(t *testing.T) {
	for in, want := range map[string]string{
		aid:                                "11111111",
		"D2760001240100000006012345670000": "1234567",
		"D2760001240100000006":             "",
		"A0000006472F0001000000000000000F": "",
	} {
		if got := aidSerial(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

// fakeGPG replays a gpg dialog: script lines are status lines; after each
// GET_* it reads yking's answer and appends it to answers.
func runDialog(t *testing.T, script []string, onStatus func(string, []string), h handler) ([]string, error) {
	t.Helper()
	stR, stW := io.Pipe()
	cmR, cmW := io.Pipe()
	var answers []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		rd := bufio.NewReader(cmR)
		for _, l := range script {
			if _, err := io.WriteString(stW, "[GNUPG:] "+l+"\n"); err != nil {
				return
			}
			if strings.HasPrefix(l, "GET_") {
				a, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				answers = append(answers, strings.TrimSuffix(a, "\n"))
			}
		}
		stW.Close()
	}()
	err := drive(stR, cmW, onStatus, h)
	cmW.Close()
	<-done
	return answers, err
}

func TestKeytocardWritesAndAsksPINOnce(t *testing.T) {
	asks := 0
	kc := &keytocard{
		cardDialog: cardDialog{serial: "11111111", ask: func() (string, error) { asks++; return "12345678", nil }},
		writes:     []SlotWrite{{"dec", encSub}, {"sig", sigSub}},
	}
	script := []string{
		"GET_LINE keyedit.prompt",
		"GET_LINE keyedit.prompt",
		"CARDCTRL 3 " + aid,
		"GET_LINE cardedit.genkeys.storekeytype",
		"GET_HIDDEN passphrase.enter",
		"GET_LINE keyedit.prompt",
		"GET_LINE keyedit.prompt",
		"GET_LINE keyedit.prompt",
		"CARDCTRL 3 " + aid,
		"GET_LINE cardedit.genkeys.storekeytype",
		"GET_HIDDEN passphrase.enter", // PIN proven by the first write: reused
		"GET_LINE keyedit.prompt",
		"GET_LINE keyedit.prompt",
	}
	got, err := runDialog(t, script, kc.status, kc.answer)
	if err != nil || kc.err != nil {
		t.Fatal(err, kc.err)
	}
	want := []string{"key " + encSub, "keytocard", "2", "12345678", "key " + encSub,
		"key " + sigSub, "keytocard", "1", "12345678", "key " + sigSub, "quit"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("answers\n got %q\nwant %q", got, want)
	}
	if asks != 1 || strings.Join(kc.done, ",") != "dec,sig" {
		t.Fatalf("asks=%d done=%v", asks, kc.done)
	}
}

func TestKeytocardStopsOnWrongPIN(t *testing.T) {
	asks := 0
	kc := &keytocard{
		cardDialog: cardDialog{serial: "11111111", ask: func() (string, error) { asks++; return "00000000", nil }},
		writes:     []SlotWrite{{"dec", encSub}, {"sig", sigSub}},
	}
	script := []string{
		"GET_LINE keyedit.prompt",
		"GET_LINE keyedit.prompt",
		"CARDCTRL 3 " + aid,
		"GET_LINE cardedit.genkeys.storekeytype",
		"GET_HIDDEN passphrase.enter",
		"SC_OP_FAILURE 2",
		"GET_LINE keyedit.prompt",
	}
	got, _ := runDialog(t, script, kc.status, kc.answer)
	if kc.err == nil || !strings.Contains(kc.err.Error(), "Admin PIN not accepted") || got[len(got)-1] != "quit" || asks != 1 || len(kc.done) != 0 {
		t.Fatalf("err=%v answers=%q done=%v", kc.err, got, kc.done)
	}
}

func TestKeytocardSecondPINWithoutSuccessIsCancelled(t *testing.T) {
	kc := &keytocard{
		cardDialog: cardDialog{serial: "11111111", ask: func() (string, error) { return "12345678", nil }},
		writes:     []SlotWrite{{"dec", encSub}},
	}
	script := []string{
		"GET_LINE keyedit.prompt",
		"GET_LINE keyedit.prompt",
		"CARDCTRL 3 " + aid,
		"GET_LINE cardedit.genkeys.storekeytype",
		"GET_HIDDEN passphrase.enter",
		"GET_HIDDEN passphrase.enter",
	}
	got, _ := runDialog(t, script, kc.status, kc.answer)
	if got[len(got)-1] != "" || kc.err == nil {
		t.Fatalf("second PIN request answered: %q err=%v", got, kc.err)
	}
}

func TestKeytocardWrongCardGetsNoPIN(t *testing.T) {
	kc := &keytocard{
		cardDialog: cardDialog{serial: "11111111", ask: func() (string, error) { t.Fatal("PIN asked"); return "", nil }},
		writes:     []SlotWrite{{"dec", encSub}},
	}
	script := []string{
		"GET_LINE keyedit.prompt",
		"GET_LINE keyedit.prompt",
		"CARDCTRL 3 D2760001240100000006222222220000",
		"GET_LINE cardedit.genkeys.storekeytype",
		"GET_HIDDEN passphrase.enter",
	}
	got, _ := runDialog(t, script, kc.status, kc.answer)
	if got[len(got)-1] != "" || kc.err == nil {
		t.Fatalf("%q %v", got, kc.err)
	}
}

func TestKeytocardNeverReplaces(t *testing.T) {
	kc := &keytocard{
		cardDialog: cardDialog{serial: "11111111", ask: func() (string, error) { return "12345678", nil }},
		writes:     []SlotWrite{{"dec", encSub}},
	}
	script := []string{
		"GET_LINE keyedit.prompt",
		"GET_LINE keyedit.prompt",
		"CARDCTRL 3 " + aid,
		"GET_LINE cardedit.genkeys.storekeytype",
		"GET_BOOL cardedit.genkeys.replace_key",
		"GET_LINE keyedit.prompt",
	}
	got, _ := runDialog(t, script, kc.status, kc.answer)
	if got[3] != "n" || got[4] != "quit" || kc.err == nil {
		t.Fatalf("%q %v", got, kc.err)
	}
}

func TestUIF(t *testing.T) {
	u := &uif{cardDialog: cardDialog{serial: "11111111", ask: func() (string, error) { return "", errors.New("no PIN expected") }}, slots: []string{"sig", "dec"}}
	script := []string{
		"CARDCTRL 3 " + aid,
		"GET_LINE cardedit.prompt",
		"GET_LINE cardedit.prompt",
		"GET_LINE cardedit.prompt",
		"GET_LINE cardedit.prompt",
	}
	got, _ := runDialog(t, script, u.status, u.answer)
	if strings.Join(got, "|") != "admin|uif 1 on|uif 2 on|quit" || u.err != nil || strings.Join(u.done, ",") != "sig,dec" {
		t.Fatalf("%q %v %v", got, u.err, u.done)
	}
}

func TestUnexpectedQuestionCancels(t *testing.T) {
	kc := &keytocard{cardDialog: cardDialog{serial: "11111111"}, writes: []SlotWrite{{"dec", encSub}}}
	got, _ := runDialog(t, []string{"GET_BOOL something.else", "GET_LINE keyedit.prompt"}, kc.status, kc.answer)
	if got[0] != "n" || got[1] != "quit" || kc.err == nil {
		t.Fatalf("%q %v", got, kc.err)
	}
}

func TestCardFingerprints(t *testing.T) {
	st := "Reader:Yubico YubiKey:AID:" + aid + ":openpgp-card\nfpr:" + sigSub + ":" + encSub + "::\n"
	got := CardFingerprints([]byte(st))
	if !got[sigSub] || !got[encSub] || len(got) != 2 {
		t.Fatalf("%v", got)
	}
}
