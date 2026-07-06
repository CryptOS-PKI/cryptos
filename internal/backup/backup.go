package backup

/*
Apache License 2.0

Copyright 2026 Shane

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// envelopeVersion is the current envelope format version. It is the first
// byte on the wire so a future format can be recognized and rejected
// distinctly rather than failing as a corrupt AEAD.
const envelopeVersion byte = 1

// Argon2id KDF parameters recorded in the header. These are the defaults
// used when sealing; Open reads whatever the sealed envelope carries.
const (
	// argonTime is the number of Argon2id passes.
	argonTime uint32 = 3
	// argonMemoryKiB is the Argon2id memory cost in KiB (64 MiB).
	argonMemoryKiB uint32 = 64 * 1024
	// argonThreads is the Argon2id parallelism.
	argonThreads uint8 = 4
	// keyLen is the derived AES-256 key length in bytes.
	keyLen uint32 = 32
	// saltLen is the KDF salt length in bytes.
	saltLen = 16
	// nonceLen is the AES-GCM nonce length in bytes (the standard 96-bit
	// nonce; also what cipher.NewGCM expects by default).
	nonceLen = 12
)

// headerLen is the fixed byte length of the envelope header that precedes
// the AEAD ciphertext: version(1) + time(4) + memoryKiB(4) + threads(1) +
// salt(16) + nonce(12).
const headerLen = 1 + 4 + 4 + 1 + saltLen + nonceLen

// ErrBadPassphrase is returned by Open when the AEAD open fails, which
// covers a wrong passphrase or a tampered/corrupt envelope: the two are
// cryptographically indistinguishable and are both reported as this
// sentinel so callers do not leak which case occurred.
var ErrBadPassphrase = errors.New("backup: bad passphrase or corrupt envelope")

// header is the parsed, self-describing envelope header.
type header struct {
	version   byte
	time      uint32
	memoryKiB uint32
	threads   uint8
	salt      []byte
	nonce     []byte
}

// marshal serializes the header to its fixed-length wire form.
func (h header) marshal() []byte {
	buf := make([]byte, headerLen)
	buf[0] = h.version
	binary.BigEndian.PutUint32(buf[1:5], h.time)
	binary.BigEndian.PutUint32(buf[5:9], h.memoryKiB)
	buf[9] = h.threads
	copy(buf[10:10+saltLen], h.salt)
	copy(buf[10+saltLen:10+saltLen+nonceLen], h.nonce)
	return buf
}

// parseHeader reads a header from the front of envelope, returning the
// header and the remaining ciphertext.
func parseHeader(envelope []byte) (header, []byte, error) {
	if len(envelope) < headerLen {
		return header{}, nil, fmt.Errorf("backup: envelope too short (%d bytes)", len(envelope))
	}
	h := header{
		version:   envelope[0],
		time:      binary.BigEndian.Uint32(envelope[1:5]),
		memoryKiB: binary.BigEndian.Uint32(envelope[5:9]),
		threads:   envelope[9],
		salt:      envelope[10 : 10+saltLen],
		nonce:     envelope[10+saltLen : 10+saltLen+nonceLen],
	}
	if h.version != envelopeVersion {
		return header{}, nil, fmt.Errorf("backup: unsupported envelope version %d", h.version)
	}
	if h.time == 0 || h.memoryKiB == 0 || h.threads == 0 {
		return header{}, nil, errors.New("backup: envelope has zero KDF parameters")
	}
	return h, envelope[headerLen:], nil
}

// Seal derives a key from passphrase with Argon2id over a random salt and
// seals plaintext with AES-256-GCM under a random nonce, binding the header
// in as additional authenticated data. The returned envelope is the
// marshaled header followed by the AEAD ciphertext.
func Seal(passphrase, plaintext []byte) (envelope []byte, err error) {
	if len(passphrase) == 0 {
		return nil, errors.New("backup: Seal: passphrase is empty")
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("backup: Seal: read salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("backup: Seal: read nonce: %w", err)
	}
	h := header{
		version:   envelopeVersion,
		time:      argonTime,
		memoryKiB: argonMemoryKiB,
		threads:   argonThreads,
		salt:      salt,
		nonce:     nonce,
	}
	hdr := h.marshal()

	aead, err := newAEAD(passphrase, h)
	if err != nil {
		return nil, err
	}
	// Seal appends the ciphertext to hdr, so the header is both the AAD and
	// the envelope prefix in a single allocation.
	return aead.Seal(hdr, nonce, plaintext, hdr), nil
}

// Open reverses Seal: it reads the self-describing header, re-derives the
// key with the recorded KDF parameters, and opens the AEAD ciphertext with
// the header as additional authenticated data. A wrong passphrase or any
// tampering (header or ciphertext) fails the AEAD open and is reported as
// ErrBadPassphrase.
func Open(passphrase, envelope []byte) (plaintext []byte, err error) {
	if len(passphrase) == 0 {
		return nil, errors.New("backup: Open: passphrase is empty")
	}
	h, ciphertext, err := parseHeader(envelope)
	if err != nil {
		return nil, err
	}
	hdr := envelope[:headerLen]

	aead, err := newAEAD(passphrase, h)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, h.nonce, ciphertext, hdr)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	return pt, nil
}

// newAEAD derives the Argon2id key for the header's parameters and returns
// an AES-256-GCM AEAD keyed with it.
func newAEAD(passphrase []byte, h header) (cipher.AEAD, error) {
	key := argon2.IDKey(passphrase, h.salt, h.time, h.memoryKiB, h.threads, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup: new GCM: %w", err)
	}
	return aead, nil
}
