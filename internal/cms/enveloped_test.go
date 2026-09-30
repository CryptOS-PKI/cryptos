package cms

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
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	ra := ca.issue(t, "ra", keys.rsa3072.Public(), true)
	device := ca.issue(t, "device", keys.rsa2048.Public(), true)

	cases := []struct {
		name        string
		alg         ContentEncryption
		ski         bool
		content     []byte
		wantVersion int
		wantKeyLen  int
	}{
		{"aes128 issuerAndSerial", AES128CBC, false, []byte("a PKCS#10 request"), 0, 16},
		{"aes256 ski", AES256CBC, true, []byte("a PKCS#10 request"), 2, 32},
		{"block-aligned content", AES128CBC, false, bytes.Repeat([]byte{0x42}, 32), 0, 16},
		{"empty content", AES256CBC, false, []byte{}, 0, 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := Encrypt(tc.content, []*x509.Certificate{ra, device}, tc.alg, EncryptOptions{IdentifyBySKI: tc.ski})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			ed, err := ParseEnvelopedData(der)
			if err != nil {
				t.Fatalf("ParseEnvelopedData: %v", err)
			}
			if ed.Version != tc.wantVersion {
				t.Errorf("version = %d, want %d", ed.Version, tc.wantVersion)
			}
			if !ed.ContentType.Equal(OIDData) {
				t.Errorf("content type = %s, want id-data", ed.ContentType)
			}
			if len(ed.Recipients) != 2 {
				t.Fatalf("got %d recipients, want 2", len(ed.Recipients))
			}
			if n := len(ed.EncryptedContent); n%16 != 0 || n <= len(tc.content) {
				t.Errorf("ciphertext length %d is not padded CBC over %d bytes", n, len(tc.content))
			}
			if bytes.Contains(der, tc.content) && len(tc.content) > 0 {
				t.Error("plaintext appears in the message")
			}
			// Each recipient decrypts on its own, and only through the
			// crypto.Decrypter interface.
			for _, r := range []struct {
				cert *x509.Certificate
				key  decrypterOnly
			}{{ra, decrypterOnly{keys.rsa3072}}, {device, decrypterOnly{keys.rsa2048}}} {
				got, err := ed.Decrypt(r.cert, r.key)
				if err != nil {
					t.Fatalf("Decrypt as %s: %v", r.cert.Subject.CommonName, err)
				}
				if !bytes.Equal(got, tc.content) {
					t.Fatalf("Decrypt as %s: wrong plaintext", r.cert.Subject.CommonName)
				}
			}
		})
	}
}

func TestDecryptRejects(t *testing.T) {
	ca := newTestCA(t)
	ra := ca.issue(t, "ra", keys.rsa2048.Public(), false)
	stranger := ca.issue(t, "stranger", keys.rsa3072.Public(), false)
	secret := []byte("sixteen byte msg plus a tail")

	der, err := Encrypt(secret, []*x509.Certificate{ra}, AES128CBC, EncryptOptions{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parse := func(t *testing.T, der []byte) *EnvelopedData {
		t.Helper()
		ed, err := ParseEnvelopedData(der)
		if err != nil {
			t.Fatalf("ParseEnvelopedData: %v", err)
		}
		return ed
	}

	t.Run("wrong recipient", func(t *testing.T) {
		_, err := parse(t, der).Decrypt(stranger, keys.rsa3072)
		if !errors.Is(err, ErrNoRecipient) {
			t.Fatalf("err = %v, want ErrNoRecipient", err)
		}
	})
	t.Run("right certificate, wrong key", func(t *testing.T) {
		// RSA PKCS#1 v1.5 decryption answers a bad padding with a random
		// key rather than an error (the Bleichenbacher countermeasure), so
		// the only guarantee is that the plaintext never comes out.
		got, err := parse(t, der).Decrypt(ra, keys.rsa2048b)
		if err == nil && bytes.Equal(got, secret) {
			t.Fatal("decrypted with the wrong key")
		}
	})
	t.Run("tampered ciphertext", func(t *testing.T) {
		ed := parse(t, der)
		// In CBC, flipping a byte of the penultimate block flips the same
		// byte of the last plaintext block. XOR the last byte with the pad
		// value (28 bytes of content, so 4) and the pad becomes 0x00, which
		// PKCS#7 padding can never be.
		n := len(ed.EncryptedContent)
		tampered := flipCiphertextByte(t, der, ed.EncryptedContent, n-16-1, 0x04)
		_, err := parse(t, tampered).Decrypt(ra, keys.rsa2048)
		if !errors.Is(err, ErrDecrypt) {
			t.Fatalf("err = %v, want ErrDecrypt", err)
		}
	})
	t.Run("tampered encrypted key", func(t *testing.T) {
		ed := parse(t, der)
		tampered := flipCiphertextByte(t, der, ed.Recipients[0].EncryptedKey, 5, 0x01)
		got, err := parse(t, tampered).Decrypt(ra, keys.rsa2048)
		if err == nil && bytes.Equal(got, secret) {
			t.Fatal("a tampered key transport still decrypted")
		}
	})
	t.Run("errors do not carry the plaintext", func(t *testing.T) {
		ed := parse(t, der)
		n := len(ed.EncryptedContent)
		tampered := flipCiphertextByte(t, der, ed.EncryptedContent, n-16-1, 0x04)
		_, err := parse(t, tampered).Decrypt(ra, keys.rsa2048)
		if err == nil || strings.Contains(err.Error(), "sixteen") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unsupported content encryption", func(t *testing.T) {
		// aes192-CBC has the same encoded length as aes128-CBC, so it
		// swaps in place.
		aes128, _ := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2})
		aes192, _ := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22})
		swapped := bytes.Replace(der, aes128, aes192, 1)
		_, err := parse(t, swapped).Decrypt(ra, keys.rsa2048)
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}

// flipCiphertextByte XORs one byte of field (located inside der) with mask.
func flipCiphertextByte(t *testing.T, der, field []byte, at int, mask byte) []byte {
	t.Helper()
	i := bytes.Index(der, field)
	if i < 0 {
		t.Fatal("field not found in message")
	}
	out := bytes.Clone(der)
	out[i+at] ^= mask
	return out
}

func TestEncryptRejects(t *testing.T) {
	ca := newTestCA(t)
	ecRecipient := ca.issue(t, "ec", keys.p256.Public(), false)
	noSKI := ca.issue(t, "no-ski", keys.rsa3072.Public(), false)
	ok := ca.issue(t, "ok", keys.rsa3072.Public(), false)

	if _, err := Encrypt([]byte("x"), nil, AES128CBC, EncryptOptions{}); err == nil {
		t.Fatal("no recipients accepted")
	}
	if _, err := Encrypt([]byte("x"), []*x509.Certificate{ecRecipient}, AES128CBC, EncryptOptions{}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("ECDSA recipient: err = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := Encrypt([]byte("x"), []*x509.Certificate{noSKI}, AES128CBC, EncryptOptions{IdentifyBySKI: true}); err == nil {
		t.Fatal("SKI identification accepted for a certificate without one")
	}
	if _, err := Encrypt([]byte("x"), []*x509.Certificate{ok}, ContentEncryption(99), EncryptOptions{}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unknown cipher: err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestParseEnvelopedDataRejects(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, "c", keys.p256.Public(), false)
	sd, err := Degenerate([][]byte{cert.Raw}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok := ca.issue(t, "ok", keys.rsa3072.Public(), false)
	env, err := Encrypt([]byte("x"), []*x509.Certificate{ok}, AES128CBC, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{
		"empty":          nil,
		"garbage":        []byte("nope"),
		"signedData":     sd,
		"trailing bytes": append(bytes.Clone(env), 0x00),
		"truncated":      env[:len(env)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnvelopedData(der); err == nil {
				t.Fatal("parsed")
			}
		})
	}
}

// TestEnvelopedInsideSigned is the SCEP pkiMessage shape (RFC 8894 section
// 3): a SignedData whose id-data content is an EnvelopedData. Integrity comes
// from the outer signature, so a tampered ciphertext is caught there even
// when CBC alone would not notice.
func TestEnvelopedInsideSigned(t *testing.T) {
	ca := newTestCA(t)
	ra := ca.issue(t, "ra", keys.rsa3072.Public(), false)
	device := selfSigned(t, "device", keys.rsa2048)
	csr := []byte("stand-in for a PKCS#10 CertificationRequest")

	env, err := Encrypt(csr, []*x509.Certificate{ra}, AES256CBC, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Sign(OIDData, env, []Signer{{Certificate: device, Key: keys.rsa2048}}, SignOptions{Certificates: [][]byte{device.Raw}})
	if err != nil {
		t.Fatal(err)
	}

	sd, err := ParseSignedData(msg)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := sd.Verify(VerifyOptions{})
	if err != nil || !signers[0].Equal(device) {
		t.Fatalf("Verify: %v", err)
	}
	ed, err := ParseEnvelopedData(sd.Content)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ed.Decrypt(ra, decrypterOnly{keys.rsa3072})
	if err != nil || !bytes.Equal(got, csr) {
		t.Fatalf("Decrypt: %v", err)
	}

	tampered := bytes.Clone(msg)
	i := bytes.Index(tampered, ed.EncryptedContent)
	tampered[i] ^= 0x01
	sd2, err := ParseSignedData(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sd2.Verify(VerifyOptions{}); !errors.Is(err, ErrVerification) {
		t.Fatalf("tampered ciphertext passed the outer signature: %v", err)
	}
}
