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
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	content := []byte("a certificate signing request, as far as CMS cares")

	cases := []struct {
		name        string
		key         crypto.Signer
		hash        crypto.Hash
		ski         bool
		contentType asn1.ObjectIdentifier
		wantVersion int
		wantSIVer   int
	}{
		{"rsa2048 sha256 issuerAndSerial", keys.rsa2048, crypto.SHA256, false, OIDData, 1, 1},
		{"rsa3072 sha384 ski", keys.rsa3072, crypto.SHA384, true, OIDData, 3, 3},
		{"rsa2048 sha512", keys.rsa2048, crypto.SHA512, false, OIDData, 1, 1},
		{"p256 sha256", keys.p256, crypto.SHA256, false, OIDData, 1, 1},
		{"p384 sha384 ski", keys.p384, crypto.SHA384, true, OIDData, 3, 3},
		// RFC 3161 section 2.4.2: a time-stamp token encapsulates TSTInfo,
		// which forces SignedData version 3 (RFC 5652 section 5.1).
		{"tstinfo content type", keys.p384, crypto.SHA384, false, OIDTSTInfo, 3, 1},
		{"default hash is sha256", keys.p256, 0, false, OIDData, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := ca.issue(t, "signer", tc.key.Public(), tc.ski)
			der, err := Sign(tc.contentType, content, []Signer{{
				Certificate:   cert,
				Key:           signerOnly{tc.key},
				Hash:          tc.hash,
				IdentifyBySKI: tc.ski,
			}}, SignOptions{Certificates: [][]byte{cert.Raw, ca.cert.Raw}})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			sd, err := ParseSignedData(der)
			if err != nil {
				t.Fatalf("ParseSignedData: %v", err)
			}
			if sd.Version != tc.wantVersion {
				t.Errorf("SignedData version = %d, want %d", sd.Version, tc.wantVersion)
			}
			if !sd.ContentType.Equal(tc.contentType) {
				t.Errorf("content type = %s, want %s", sd.ContentType, tc.contentType)
			}
			if !bytes.Equal(sd.Content, content) {
				t.Error("encapsulated content did not round-trip")
			}
			if len(sd.Certificates) != 2 || !bytes.Equal(sd.Certificates[0], cert.Raw) {
				t.Error("certificates did not round-trip in order")
			}
			if len(sd.SignerInfos) != 1 {
				t.Fatalf("got %d signers, want 1", len(sd.SignerInfos))
			}
			si := sd.SignerInfos[0]
			if si.Version != tc.wantSIVer {
				t.Errorf("SignerInfo version = %d, want %d", si.Version, tc.wantSIVer)
			}
			if tc.ski {
				if si.IssuerAndSerial != nil || !bytes.Equal(si.SubjectKeyID, cert.SubjectKeyId) {
					t.Error("signer is not identified by its subject key identifier")
				}
			} else if si.IssuerAndSerial == nil || si.IssuerAndSerial.SerialNumber.Cmp(cert.SerialNumber) != 0 {
				t.Error("signer is not identified by issuer and serial number")
			}

			signers, err := sd.Verify(VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if len(signers) != 1 || !signers[0].Equal(cert) {
				t.Fatal("Verify did not return the signing certificate")
			}
		})
	}
}

func TestSignedAttributes(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, "signer", keys.p256.Public(), false)

	// A SCEP messageType attribute (RFC 8894 section 3.2.1.2) stands in for
	// any caller-supplied authenticated attribute.
	oidMessageType := asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	mt, err := NewAttribute(oidMessageType, asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte("19")})
	if err != nil {
		t.Fatalf("NewAttribute: %v", err)
	}

	der, err := Sign(OIDData, []byte("abc"), []Signer{{
		Certificate: cert, Key: keys.p256, Attributes: []Attribute{mt},
	}}, SignOptions{Certificates: [][]byte{cert.Raw}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sd, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	si := sd.SignerInfos[0]

	// DER orders a SET OF by encoding (X.690 section 11.6), so insertion
	// order is irrelevant: the messageType attribute (SEQUENCE length 0x12)
	// sorts before contentType (0x18), which sorts before messageDigest
	// (0x2f).
	var order []string
	for _, a := range si.SignedAttributes {
		order = append(order, a.Type.String())
	}
	want := []string{oidMessageType.String(), OIDAttributeContentType.String(), OIDAttributeMessageDigest.String()}
	if len(order) != len(want) {
		t.Fatalf("signed attributes = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("signed attributes = %v, want DER order %v", order, want)
		}
	}

	// Known answer: SHA-256("abc") from FIPS 180-2 appendix B.1.
	var digest []byte
	if err := si.SignedAttribute(OIDAttributeMessageDigest, &digest); err != nil {
		t.Fatalf("messageDigest: %v", err)
	}
	if got := hex.EncodeToString(digest); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("messageDigest = %s", got)
	}
	var ct asn1.ObjectIdentifier
	if err := si.SignedAttribute(OIDAttributeContentType, &ct); err != nil || !ct.Equal(OIDData) {
		t.Fatalf("contentType = %v, %v", ct, err)
	}
	var mtValue string
	if err := si.SignedAttribute(oidMessageType, &mtValue); err != nil || mtValue != "19" {
		t.Fatalf("messageType = %q, %v", mtValue, err)
	}
	if err := si.SignedAttribute(OIDAttributeSigningTime, new(asn1.RawValue)); !errors.Is(err, ErrAttributeNotFound) {
		t.Fatalf("absent attribute: err = %v, want ErrAttributeNotFound", err)
	}
	if _, err := sd.Verify(VerifyOptions{}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignRejects(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, "signer", keys.p256.Public(), false)
	ok := Signer{Certificate: cert, Key: keys.p256}

	dupCT, err := NewAttribute(OIDAttributeContentType, OIDData)
	if err != nil {
		t.Fatalf("NewAttribute: %v", err)
	}
	certNoSKI := ca.issue(t, "no-ski", keys.p256.Public(), false)

	cases := []struct {
		name    string
		signers []Signer
		wantErr error
	}{
		{"no signers", nil, nil},
		{"sha1", []Signer{{Certificate: cert, Key: keys.p256, Hash: crypto.SHA1}}, ErrUnsupportedAlgorithm},
		{"md5", []Signer{{Certificate: cert, Key: keys.p256, Hash: crypto.MD5}}, ErrUnsupportedAlgorithm},
		{"key does not match certificate", []Signer{{Certificate: cert, Key: keys.p384}}, nil},
		{"caller supplies contentType", []Signer{{Certificate: cert, Key: keys.p256, Attributes: []Attribute{dupCT}}}, nil},
		{"ski requested but absent", []Signer{{Certificate: certNoSKI, Key: keys.p256, IdentifyBySKI: true}}, nil},
		{"missing certificate", []Signer{{Key: keys.p256}}, nil},
		{"missing key", []Signer{{Certificate: cert}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Sign(OIDData, []byte("x"), tc.signers, SignOptions{})
			if err == nil {
				t.Fatal("Sign accepted it")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
	if _, err := Sign(OIDData, []byte("x"), []Signer{ok}, SignOptions{}); err != nil {
		t.Fatalf("control case failed: %v", err)
	}
}

// flipAt returns a copy of b with one bit flipped at the first occurrence of
// needle (plus offset).
func flipAt(t *testing.T, b, needle []byte, offset int) []byte {
	t.Helper()
	i := bytes.Index(b, needle)
	if i < 0 {
		t.Fatal("needle not found in message")
	}
	out := bytes.Clone(b)
	out[i+offset] ^= 0x01
	return out
}

func TestVerifyRejects(t *testing.T) {
	ca := newTestCA(t)
	content := []byte("content that must not change in transit")
	cert := ca.issue(t, "signer", keys.rsa2048.Public(), false)
	other := ca.issue(t, "other", keys.rsa2048b.Public(), false)

	sign := func(t *testing.T, s Signer, ct asn1.ObjectIdentifier, opts SignOptions) []byte {
		t.Helper()
		der, err := Sign(ct, content, []Signer{s}, opts)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return der
	}
	good := sign(t, Signer{Certificate: cert, Key: keys.rsa2048}, OIDData, SignOptions{Certificates: [][]byte{cert.Raw}})

	verify := func(der []byte, opts VerifyOptions) error {
		sd, err := ParseSignedData(der)
		if err != nil {
			return err
		}
		_, err = sd.Verify(opts)
		return err
	}

	t.Run("control", func(t *testing.T) {
		if err := verify(good, VerifyOptions{}); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
	t.Run("bad digest: content altered", func(t *testing.T) {
		err := verify(flipAt(t, good, content, 3), VerifyOptions{})
		if !errors.Is(err, ErrVerification) {
			t.Fatalf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("signed attribute altered", func(t *testing.T) {
		sd, _ := ParseSignedData(good)
		var digest []byte
		if err := sd.SignerInfos[0].SignedAttribute(OIDAttributeMessageDigest, &digest); err != nil {
			t.Fatal(err)
		}
		err := verify(flipAt(t, good, digest, 0), VerifyOptions{})
		if !errors.Is(err, ErrVerification) {
			t.Fatalf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("signature altered", func(t *testing.T) {
		sd, _ := ParseSignedData(good)
		err := verify(flipAt(t, good, sd.SignerInfos[0].Signature, 10), VerifyOptions{})
		if !errors.Is(err, ErrVerification) {
			t.Fatalf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("wrong signer: key does not match the identified certificate", func(t *testing.T) {
		// other's key signs, but the only certificate carrying other's issuer
		// and serial is an impostor over a different key. The identifier
		// resolves, so only the signature check stands between the two.
		impostor := ca.issueSerial(t, "impostor", keys.rsa2048.Public(), other.SerialNumber)
		forged := sign(t, Signer{Certificate: other, Key: keys.rsa2048b}, OIDData, SignOptions{Certificates: [][]byte{impostor.Raw}})
		err := verify(forged, VerifyOptions{})
		if !errors.Is(err, ErrVerification) {
			t.Fatalf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("signer certificate not present", func(t *testing.T) {
		bare := sign(t, Signer{Certificate: cert, Key: keys.rsa2048}, OIDData, SignOptions{})
		if err := verify(bare, VerifyOptions{}); !errors.Is(err, ErrSignerNotFound) {
			t.Fatalf("err = %v, want ErrSignerNotFound", err)
		}
		if err := verify(bare, VerifyOptions{Certificates: []*x509.Certificate{other}}); !errors.Is(err, ErrSignerNotFound) {
			t.Fatalf("with an unrelated candidate: err = %v, want ErrSignerNotFound", err)
		}
		if err := verify(bare, VerifyOptions{Certificates: []*x509.Certificate{cert}}); err != nil {
			t.Fatalf("with the signer supplied out of band: %v", err)
		}
	})
	t.Run("content-type attribute does not match eContentType", func(t *testing.T) {
		// id-envelopedData and id-data encode to the same length, so the
		// eContentType can be swapped without disturbing any length.
		der := sign(t, Signer{Certificate: cert, Key: keys.rsa2048}, OIDEnvelopedData, SignOptions{Certificates: [][]byte{cert.Raw}})
		envOID, _ := asn1.Marshal(OIDEnvelopedData)
		dataOID, _ := asn1.Marshal(OIDData)
		i := bytes.Index(der, envOID)
		swapped := bytes.Clone(der)
		copy(swapped[i:], dataOID)
		err := verify(swapped, VerifyOptions{})
		if !errors.Is(err, ErrVerification) {
			t.Fatalf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("detached", func(t *testing.T) {
		det := sign(t, Signer{Certificate: cert, Key: keys.rsa2048}, OIDData, SignOptions{Certificates: [][]byte{cert.Raw}, Detached: true})
		sd, err := ParseSignedData(det)
		if err != nil {
			t.Fatal(err)
		}
		if sd.Content != nil {
			t.Fatal("detached message carries content")
		}
		if _, err := sd.Verify(VerifyOptions{}); err == nil {
			t.Fatal("verified a detached message with no content supplied")
		}
		if _, err := sd.Verify(VerifyOptions{Content: []byte("something else")}); !errors.Is(err, ErrVerification) {
			t.Fatalf("wrong detached content: err = %v, want ErrVerification", err)
		}
		if _, err := sd.Verify(VerifyOptions{Content: content}); err != nil {
			t.Fatalf("detached content: %v", err)
		}
		attached, _ := ParseSignedData(good)
		if _, err := attached.Verify(VerifyOptions{Content: content}); err == nil {
			t.Fatal("accepted detached content for an attached message")
		}
	})
	t.Run("degenerate has no signers", func(t *testing.T) {
		der, err := Degenerate([][]byte{cert.Raw}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(der, VerifyOptions{Content: content}); err == nil {
			t.Fatal("a message with no signers verified")
		}
	})
}

func TestParseSignedDataRejects(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, "r", keys.rsa3072.Public(), false)
	env, err := Encrypt([]byte("x"), []*x509.Certificate{cert}, AES128CBC, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	good, err := Degenerate([][]byte{cert.Raw}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":             nil,
		"garbage":           []byte("not asn.1"),
		"trailing bytes":    append(bytes.Clone(good), 0x00),
		"bare certificate":  cert.Raw,
		"envelopedData":     env,
		"truncated":         good[:len(good)-3],
		"unterminated ber":  {0x30, 0x80, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02},
		"deeply nested ber": append(bytes.Repeat([]byte{0x30, 0x80}, 200), bytes.Repeat([]byte{0x00, 0x00}, 200)...),
	}
	for name, der := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSignedData(der); err == nil {
				t.Fatal("parsed")
			}
		})
	}
}

// TestParseBER covers the encodings streaming encoders emit: indefinite
// lengths and a constructed eContent OCTET STRING split into chunks. RFC 5652
// only requires DER for the signed attributes, so the rest may arrive as BER.
func TestParseBER(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, "signer", keys.p256.Public(), false)
	content := bytes.Repeat([]byte("0123456789abcdef"), 20)
	der, err := Sign(OIDData, content, []Signer{{Certificate: cert, Key: keys.p256}}, SignOptions{Certificates: [][]byte{cert.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	ber := toIndefiniteBER(t, der, content)
	if bytes.Equal(ber, der) {
		t.Fatal("the BER rewrite changed nothing")
	}
	sd, err := ParseSignedData(ber)
	if err != nil {
		t.Fatalf("ParseSignedData(BER): %v", err)
	}
	if !bytes.Equal(sd.Content, content) {
		t.Fatal("chunked eContent was not reassembled")
	}
	if _, err := sd.Verify(VerifyOptions{}); err != nil {
		t.Fatalf("Verify(BER): %v", err)
	}
}

func TestDegenerate(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.issue(t, "leaf", keys.p256.Public(), false)
	crl := ca.crl(t)

	der, err := Degenerate([][]byte{leaf.Raw, ca.cert.Raw}, [][]byte{crl})
	if err != nil {
		t.Fatalf("Degenerate: %v", err)
	}
	sd, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if sd.Version != 1 || len(sd.SignerInfos) != 0 || len(sd.DigestAlgorithms) != 0 || sd.Content != nil {
		t.Fatalf("not the degenerate shape: version %d, %d signers, %d digests", sd.Version, len(sd.SignerInfos), len(sd.DigestAlgorithms))
	}
	if !sd.ContentType.Equal(OIDData) {
		t.Fatalf("eContentType = %s, want id-data", sd.ContentType)
	}
	if len(sd.Certificates) != 2 || !bytes.Equal(sd.Certificates[0], leaf.Raw) || !bytes.Equal(sd.Certificates[1], ca.cert.Raw) {
		t.Fatal("certificates did not round-trip in order")
	}
	if len(sd.CRLs) != 1 || !bytes.Equal(sd.CRLs[0], crl) {
		t.Fatal("CRL did not round-trip")
	}

	crlOnly, err := Degenerate(nil, [][]byte{crl})
	if err != nil {
		t.Fatalf("CRL-only: %v", err)
	}
	if sd, err := ParseSignedData(crlOnly); err != nil || len(sd.Certificates) != 0 || len(sd.CRLs) != 1 {
		t.Fatalf("CRL-only did not round-trip: %v", err)
	}

	if _, err := Degenerate(nil, nil); err == nil {
		t.Fatal("an empty degenerate message was accepted")
	}
	if _, err := Degenerate([][]byte{{}}, nil); err == nil {
		t.Fatal("an empty certificate was accepted")
	}
	if _, err := Degenerate(nil, [][]byte{{}}); err == nil {
		t.Fatal("an empty CRL was accepted")
	}
}

// TestDegenerateKnownAnswer pins the exact bytes, worked by hand from RFC 5652
// sections 3 and 5.1, so the encoding cannot drift unnoticed. The
// certificate and CRL slots hold an empty SEQUENCE: the structure is what is
// under test.
func TestDegenerateKnownAnswer(t *testing.T) {
	der, err := Degenerate([][]byte{{0x30, 0x00}}, [][]byte{{0x30, 0x00}})
	if err != nil {
		t.Fatal(err)
	}
	want := "302b" + // ContentInfo
		"06092a864886f70d010702" + // id-signedData
		"a01e" + // [0] EXPLICIT
		"301c" + // SignedData
		"020101" + // version 1
		"3100" + // digestAlgorithms: empty SET
		"300b06092a864886f70d010701" + // encapContentInfo: id-data, no eContent
		"a0023000" + // certificates [0] IMPLICIT
		"a1023000" + // crls [1] IMPLICIT
		"3100" // signerInfos: empty SET
	if got := hex.EncodeToString(der); got != want {
		t.Fatalf("Degenerate =\n%s\nwant\n%s", got, want)
	}
}
