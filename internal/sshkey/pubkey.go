// Package sshkey creates and inventories SSH keys backed by a YubiKey
// (FIDO2 "sk" keys). Fingerprints are computed in Go, not via ssh-keygen.
package sshkey

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Security-key public key types.
const (
	TypeEd25519SK = "sk-ssh-ed25519@openssh.com"
	TypeECDSASK   = "sk-ecdsa-sha2-nistp256@openssh.com"
)

// PubKey is one parsed public key file.
type PubKey struct {
	Path        string // .pub file
	Type        string
	Fingerprint string // SHA256:…
	Comment     string
}

// IsSK reports whether the key lives on a FIDO security key.
func (p PubKey) IsSK() bool { return p.Type == TypeEd25519SK || p.Type == TypeECDSASK }

// ParsePub parses an OpenSSH public key line.
func ParsePub(line string) (PubKey, error) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 2 {
		return PubKey{}, errors.New("not an OpenSSH public key")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return PubKey{}, errors.New("bad base64 key blob")
	}
	if !blobHasType(blob, f[0]) {
		return PubKey{}, errors.New("key type does not match blob")
	}
	return PubKey{
		Type:        f[0],
		Fingerprint: Fingerprint(blob),
		Comment:     strings.Join(f[2:], " "),
	}, nil
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of a key blob.
func Fingerprint(blob []byte) string {
	h := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// blobHasType checks the blob's leading string equals typ.
func blobHasType(blob []byte, typ string) bool {
	if len(blob) < 4 {
		return false
	}
	n := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	return n == len(typ) && len(blob) >= 4+n && string(blob[4:4+n]) == typ
}

// ReadPub parses a .pub file.
func ReadPub(path string) (PubKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return PubKey{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return PubKey{}, errors.New("empty file")
	}
	p, err := ParsePub(sc.Text())
	if err != nil {
		return PubKey{}, err
	}
	p.Path = path
	return p, nil
}

// ScanSK lists security-key public keys in dir (normally ~/.ssh), sorted by
// path. Unreadable or non-key files are skipped.
func ScanSK(dir string) ([]PubKey, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	var out []PubKey
	for _, m := range matches {
		p, err := ReadPub(m)
		if err == nil && p.IsSK() {
			out = append(out, p)
		}
	}
	return out, nil
}
