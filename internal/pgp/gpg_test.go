package pgp

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Real gpg in throwaway homes; no card operation is run.
func TestGPGPlumbing(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil || testing.Short() {
		t.Skip("gpg not available")
	}
	ctx := context.Background()
	src := GPG{Home: t.TempDir()}
	defer src.Kill("all")
	const pass = "correct horse"
	fpr, err := src.Generate(ctx, pass, "Alice Example <alice@example.com>", "2y")
	if err != nil {
		t.Fatal(err)
	}
	id, err := src.Find(ctx, fpr)
	if err != nil {
		t.Fatal(err)
	}
	sig, enc := id.ForSlot("sig"), id.ForSlot("dec")
	if sig == nil || enc == nil || sig.Algo != "ed25519" || enc.Algo != "cv25519" || strings.Contains(id.Subkeys[0].Usage, "c") {
		t.Fatalf("%+v", id)
	}
	if p, err := src.Protected(ctx, enc.Keygrip); err != nil || !p {
		t.Fatalf("protected=%v err=%v", p, err)
	}
	if _, err := src.ExportSecretSubkeys(ctx, "wrong", []string{enc.Fingerprint}); err == nil {
		t.Fatal("export with a wrong passphrase succeeded")
	}
	secret, err := src.ExportSecretSubkeys(ctx, pass, []string{enc.Fingerprint, sig.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := src.ExportPublic(ctx, fpr)
	if err != nil {
		t.Fatal(err)
	}

	dst := GPG{Home: t.TempDir()}
	defer dst.Kill("all")
	os.WriteFile(dst.Home+"/gpg-agent.conf", []byte("allow-preset-passphrase\n"), 0o600)
	if err := dst.Import(ctx, "", pub); err != nil {
		t.Fatal(err)
	}
	if err := dst.Import(ctx, pass, secret); err != nil {
		t.Fatal(err)
	}
	did, err := dst.Find(ctx, fpr)
	if err != nil {
		t.Fatal(err)
	}
	if did.Where != WhereNone || did.SubkeyByFpr(enc.Fingerprint).Where != WhereDisk {
		t.Fatalf("primary must stay a stub, subkeys secret: %+v", did)
	}
	if err := dst.Preset(ctx, enc.Keygrip, pass); err != nil {
		t.Fatal(err)
	}

	if err := src.DeleteSecretSubkeys(ctx, []string{enc.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	id, _ = src.Find(ctx, fpr)
	if id.Where != WhereDisk || id.SubkeyByFpr(enc.Fingerprint).Where != WhereNone || id.SubkeyByFpr(sig.Fingerprint).Where != WhereDisk {
		t.Fatalf("only the encryption subkey's secret should be gone: %+v", id)
	}
}
