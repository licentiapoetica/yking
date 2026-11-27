package chalresp

import (
	"encoding/hex"
	"testing"
)

func TestResponseRFC2202(t *testing.T) {
	// RFC 2202 test case 2.
	got := hex.EncodeToString(Response([]byte("Jefe"), []byte("what do ya want for nothing?")))
	if got != "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" {
		t.Fatal(got)
	}
}

func TestPaperRoundTrip(t *testing.T) {
	s, _ := NewSecret()
	p := Paper(s)
	back, err := ParsePaper(p)
	if err != nil || hex.EncodeToString(back) != hex.EncodeToString(s) {
		t.Fatalf("%q %v", p, err)
	}
	if _, err := ParsePaper("abcd"); err == nil {
		t.Fatal("short secret accepted")
	}
	if len(SetID(s)) != 12 || SetID(s) == SetID(back[:19]) {
		t.Fatal("set id")
	}
}
