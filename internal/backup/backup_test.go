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
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	pass := []byte("correct horse battery staple")
	plain := []byte("the CA key blob and chain payload")

	env, err := Seal(pass, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(env) <= headerLen {
		t.Fatalf("envelope length %d does not exceed header length %d", len(env), headerLen)
	}
	got, err := Open(pass, env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plain)
	}
}

func TestSealOpenEmptyPayload(t *testing.T) {
	pass := []byte("pw")
	env, err := Seal(pass, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(pass, env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %q", got)
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	env, err := Seal([]byte("right-passphrase"), []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = Open([]byte("wrong-passphrase"), env)
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Open with wrong passphrase = %v, want ErrBadPassphrase", err)
	}
}

func TestOpenTamperedEnvelope(t *testing.T) {
	pass := []byte("passphrase")
	env, err := Seal(pass, []byte("secret payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip a byte in the ciphertext region (past the header).
	tampered := append([]byte(nil), env...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := Open(pass, tampered); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Open tampered ciphertext = %v, want ErrBadPassphrase", err)
	}

	// Flip a byte inside the header (the salt): it is bound as AAD, so the
	// open must fail too.
	tamperedHdr := append([]byte(nil), env...)
	tamperedHdr[12] ^= 0x01
	if _, err := Open(pass, tamperedHdr); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Open tampered header = %v, want ErrBadPassphrase", err)
	}
}

func TestOpenTruncatedEnvelope(t *testing.T) {
	if _, err := Open([]byte("pw"), []byte{0x01, 0x02}); err == nil {
		t.Fatal("Open of a truncated envelope should error")
	}
}

func TestSealEmptyPassphrase(t *testing.T) {
	if _, err := Seal(nil, []byte("x")); err == nil {
		t.Fatal("Seal with an empty passphrase should error")
	}
}
