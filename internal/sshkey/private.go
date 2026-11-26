package sshkey

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// SK flag bits stored in an OpenSSH security-key private key file.
const (
	FlagUserPresence     = 0x01 // touch required
	FlagUserVerification = 0x04 // PIN required (verify-required)
	FlagResident         = 0x20
)

// SKHandle is the non-secret part of an "sk" private key file: which FIDO
// application it uses and the key handle the authenticator issued. The
// handle is useless without the physical key.
type SKHandle struct {
	Type        string
	Application string // FIDO relying party id, normally "ssh:"
	Flags       byte
	KeyHandle   []byte
}

// TouchRequired reports the user-presence flag.
func (h SKHandle) TouchRequired() bool { return h.Flags&FlagUserPresence != 0 }

// PINRequired reports the verify-required flag.
func (h SKHandle) PINRequired() bool { return h.Flags&FlagUserVerification != 0 }

// Resident reports whether the credential is stored on the key.
func (h SKHandle) Resident() bool { return h.Flags&FlagResident != 0 }

// KeyHandleB64 is the handle as fido2-assert expects it.
func (h SKHandle) KeyHandleB64() string { return base64.StdEncoding.EncodeToString(h.KeyHandle) }

// ErrEncrypted means the file has a passphrase; its handle is not readable
// without it.
var ErrEncrypted = errors.New("key file is passphrase-protected")

// ReadSKHandle parses an unencrypted OpenSSH sk private key file.
func ReadSKHandle(path string) (SKHandle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return SKHandle{}, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "OPENSSH PRIVATE KEY" {
		return SKHandle{}, errors.New("not an OpenSSH private key")
	}
	return parseSKPrivate(blk.Bytes)
}

type reader struct{ b []byte }

func (r *reader) str() ([]byte, error) {
	if len(r.b) < 4 {
		return nil, errors.New("truncated key file")
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		return nil, errors.New("truncated key file")
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s, nil
}

func (r *reader) u32() (uint32, error) {
	if len(r.b) < 4 {
		return 0, errors.New("truncated key file")
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, nil
}

func (r *reader) byte1() (byte, error) {
	if len(r.b) < 1 {
		return 0, errors.New("truncated key file")
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v, nil
}

func parseSKPrivate(data []byte) (SKHandle, error) {
	magic := []byte("openssh-key-v1\x00")
	if !bytes.HasPrefix(data, magic) {
		return SKHandle{}, errors.New("bad key file magic")
	}
	r := &reader{data[len(magic):]}
	cipher, err := r.str()
	if err != nil {
		return SKHandle{}, err
	}
	if string(cipher) != "none" {
		return SKHandle{}, ErrEncrypted
	}
	for i := 0; i < 2; i++ { // kdfname, kdfoptions
		if _, err := r.str(); err != nil {
			return SKHandle{}, err
		}
	}
	if n, err := r.u32(); err != nil || n != 1 {
		return SKHandle{}, fmt.Errorf("expected exactly one key")
	}
	if _, err := r.str(); err != nil { // public key blob
		return SKHandle{}, err
	}
	priv, err := r.str()
	if err != nil {
		return SKHandle{}, err
	}
	p := &reader{priv}
	c1, _ := p.u32()
	c2, err := p.u32()
	if err != nil || c1 != c2 {
		return SKHandle{}, errors.New("corrupt key file (check ints)")
	}
	typ, err := p.str()
	if err != nil {
		return SKHandle{}, err
	}
	h := SKHandle{Type: string(typ)}
	switch h.Type {
	case TypeEd25519SK:
		if _, err := p.str(); err != nil { // public key
			return h, err
		}
	case TypeECDSASK:
		for i := 0; i < 2; i++ { // curve name, EC point
			if _, err := p.str(); err != nil {
				return h, err
			}
		}
	default:
		return h, fmt.Errorf("%s is not a security-key type", h.Type)
	}
	app, err := p.str()
	if err != nil {
		return h, err
	}
	h.Application = string(app)
	if h.Flags, err = p.byte1(); err != nil {
		return h, err
	}
	kh, err := p.str()
	if err != nil {
		return h, err
	}
	h.KeyHandle = append([]byte(nil), kh...)
	if len(h.KeyHandle) == 0 {
		return h, errors.New("empty key handle")
	}
	return h, nil
}
