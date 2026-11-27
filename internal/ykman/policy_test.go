package ykman

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAllowlistHasNoForbiddenTokens(t *testing.T) {
	for _, r := range allowlist {
		for _, p := range r.pattern {
			if forbiddenTokens[strings.ToLower(p)] {
				t.Errorf("rule %q contains forbidden token %q", r.name, p)
			}
		}
	}
}

// Add-only rules exist only for an empty OTP slot 2, guarded by
// ProgramChalResp's fresh read.
func TestAddOnlyRules(t *testing.T) {
	for _, r := range allowlist {
		if r.kind != ReadOnly && !strings.HasPrefix(r.name, "otp-chalresp") {
			t.Errorf("rule %q is %s; only otp-chalresp may write", r.name, r.kind)
		}
	}
}

func TestCheckAllows(t *testing.T) {
	for _, args := range [][]string{
		{"--version"},
		{"list"},
		{"list", "--serials"},
		{"--device", "12345678", "info"},
		{"--device", "12345678", "fido", "info"},
		{"--device", "12345678", "otp", "info"},
		{"--device", "12345678", "openpgp", "info"},
		{"--device", "12345678", "openpgp", "keys", "info", "dec"},
		{"--device", "12345678", "otp", "calculate", "2", "00ff"},
		{"--device", "12345678", "otp", "chalresp", "--touch", "2"},
		{"--device", "12345678", "otp", "delete", "2"},
	} {
		if _, err := Check(args); err != nil {
			t.Errorf("Check(%v) = %v, want allowed", args, err)
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"fido", "reset"},
		{"--device", "12345678", "fido", "reset"},
		{"--device", "12345678", "fido", "reset", "--force"},
		{"piv", "reset", "-f"},
		{"openpgp", "reset"},
		{"oath", "reset"},
		{"otp", "delete", "1"},
		{"fido", "access", "change-pin"},
		{"config", "usb", "--disable", "FIDO2"},
		{"config", "mode", "FIDO"},
		{"--device", "1234; rm -rf /", "info"}, // serial must be digits
		{"--device", "", "info"},
		{"--device", "12345678", "info", "extra"},
		{"info"}, // device must be selected explicitly
		{"LIST"},
		{"--device", "12345678", "openpgp", "keys", "info", "att"},
		{"--device", "12345678", "otp", "chalresp", "2", "00112233"}, // secret on argv
		{"--device", "12345678", "otp", "chalresp", "1"},
		{"--device", "12345678", "otp", "delete", "1"},
		{"--device", "12345678", "otp", "delete", "2", "--force"},
		{"otp", "delete", "2"},
		{"--device", "12345678", "otp", "calculate", "2", "XYZ"},
		{"--device", "12345678", "openpgp", "keys", "set-touch", "sig", "fixed"},
	} {
		_, err := Check(args)
		var pe *PolicyError
		if !errors.As(err, &pe) {
			t.Errorf("Check(%v) = %v, want PolicyError", args, err)
		}
	}
}

// TestNoYkmanOutsidePackage makes sure nothing outside internal/ykman runs
// ykman directly, bypassing the allowlist.
func TestNoYkmanOutsidePackage(t *testing.T) {
	root := filepath.Join("..", "..")
	self, _ := filepath.Abs(".")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "testdata" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		abs, _ := filepath.Abs(filepath.Dir(path))
		if abs == self {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if s, _ := strconv.Unquote(lit.Value); s == "ykman" {
				t.Errorf("%s: string literal %q outside internal/ykman; go through ykman.Client", path, s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
