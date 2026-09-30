package tpm

/*
Copyright The CryptOS Authors.

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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// The in-process simulator (go-tpm-tools' build of the Microsoft reference
// TPM) implements RSA-2048 only, which is also what many real TPM parts
// implement. So the simulator covers two things here: the RSA signing
// mechanics, exercised on a 2048-bit key made through the same template and
// load path CreateKey uses, and the refusal of RSA-3072 on a TPM that lacks
// it. A TPM-held RSA-3072 key end to end is covered against swtpm in
// internal/e2e.

// newSimRSAKey creates and loads an RSA-2048 key in the simulator through the
// unexported path below CreateKey's floor.
func newSimRSAKey(t *testing.T, tp *TPM) *Key {
	t.Helper()
	ck, err := tp.createFromTemplate(rsaTemplate(2048))
	if err != nil {
		t.Fatalf("createFromTemplate(RSA-2048): %v", err)
	}
	key, err := tp.loadKey(ck.Private, ck.Public)
	if err != nil {
		t.Fatalf("loadKey(RSA-2048): %v", err)
	}
	t.Cleanup(func() { _ = key.Close() })
	return key
}

// countingTPM forwards every command to the simulator and counts the
// TPM2_Create commands it sees.
type countingTPM struct {
	transport.TPMCloser
	creates int
}

func (c *countingTPM) Send(cmd []byte) ([]byte, error) {
	if len(cmd) >= 10 && tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10])) == tpm2.TPMCCCreate {
		c.creates++
	}
	return c.TPMCloser.Send(cmd)
}

func TestProbe_ReportsRSAKeySizes(t *testing.T) {
	tp := openSim(t)
	caps, err := tp.Probe()
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !caps.SupportsRSAKeyBits(2048) {
		t.Fatalf("simulator implements RSA-2048; Probe reported %v", caps.RSAKeyBits)
	}
	if caps.SupportsRSAKeyBits(3072) {
		t.Fatalf("simulator does not implement RSA-3072; Probe reported %v", caps.RSAKeyBits)
	}
	if !caps.SupportsCurve(tpm2.TPMECCNistP384) {
		t.Fatalf("adding RSA probing must not drop the curve list; got %v", caps.LoadedCurves)
	}
}

// TestCreateKey_UnsupportedRSASizeFailsClearly covers a TPM without the
// configured RSA size. CreateKey must refuse with ErrKeyAlgorithmUnsupported,
// name the size, and send no TPM2_Create: there is no fallback to a smaller
// size or to a software key.
func TestCreateKey_UnsupportedRSASizeFailsClearly(t *testing.T) {
	sim := openSim(t)
	spy := &countingTPM{TPMCloser: sim.rwc}
	tp := &TPM{rwc: spy}

	for _, alg := range []KeyAlgorithm{AlgorithmRSA3072, AlgorithmRSA4096} {
		ck, err := tp.CreateKey(alg)
		if !errors.Is(err, ErrKeyAlgorithmUnsupported) {
			t.Fatalf("CreateKey(%s) = %v, want ErrKeyAlgorithmUnsupported", algName(alg), err)
		}
		if ck != nil {
			t.Fatalf("CreateKey(%s) returned key material alongside the error", algName(alg))
		}
		if !strings.Contains(err.Error(), algName(alg)) {
			t.Errorf("CreateKey(%s) error %q does not name the algorithm", algName(alg), err)
		}
	}
	if spy.creates != 0 {
		t.Fatalf("TPM2_Create was sent %d times; the size check must refuse first", spy.creates)
	}

	if _, err := tp.CreateKey(AlgorithmECDSAP384); err != nil {
		t.Fatalf("CreateKey(ECDSA-P384) on the same TPM: %v", err)
	}
}

func TestLoadKey_RefusesRSABelowFloor(t *testing.T) {
	tp := openSim(t)
	ck, err := tp.createFromTemplate(rsaTemplate(2048))
	if err != nil {
		t.Fatalf("createFromTemplate: %v", err)
	}
	if _, err := tp.LoadKey(ck.Private, ck.Public); err == nil {
		t.Fatal("LoadKey(RSA-2048): want an error, the CA key floor is 3072")
	}
}

func TestSimRSAKey_PublicKey(t *testing.T) {
	tp := openSim(t)
	key := newSimRSAKey(t, tp)
	pk, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *rsa.PublicKey", key.Public())
	}
	if pk.N.BitLen() != 2048 || pk.E != 65537 {
		t.Fatalf("public key = %d bits, e=%d; want 2048 bits, e=65537", pk.N.BitLen(), pk.E)
	}
}

// TestRSATemplate_HasECDSAKeyProperties pins the property that makes a
// TPM-held CA key worth having: the private half is generated inside the TPM
// and can never be moved off it or re-parented, exactly as for the ECDSA key.
func TestRSATemplate_HasECDSAKeyProperties(t *testing.T) {
	tp := openSim(t)
	attrsOf := func(ck *CreatedKey) tpm2.TPMAObject {
		pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](ck.Public)
		if err != nil {
			t.Fatalf("unmarshal public: %v", err)
		}
		contents, err := pub.Contents()
		if err != nil {
			t.Fatalf("public contents: %v", err)
		}
		return contents.ObjectAttributes
	}
	rsaCK, err := tp.createFromTemplate(rsaTemplate(2048))
	if err != nil {
		t.Fatalf("createFromTemplate(RSA): %v", err)
	}
	ecCK, err := tp.CreateKey(AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey(ECDSA): %v", err)
	}
	rsaAttrs, ecAttrs := attrsOf(rsaCK), attrsOf(ecCK)
	if rsaAttrs != ecAttrs {
		t.Fatalf("RSA key attributes %+v differ from the ECDSA key's %+v", rsaAttrs, ecAttrs)
	}
	if !rsaAttrs.FixedTPM || !rsaAttrs.FixedParent || !rsaAttrs.SensitiveDataOrigin {
		t.Fatalf("RSA key attributes %+v: want fixedTPM, fixedParent and sensitiveDataOrigin", rsaAttrs)
	}
	for _, alg := range []KeyAlgorithm{AlgorithmRSA3072, AlgorithmRSA4096} {
		tmpl, err := publicTemplate(alg)
		if err != nil {
			t.Fatalf("publicTemplate(%s): %v", algName(alg), err)
		}
		if tmpl.ObjectAttributes != ecAttrs {
			t.Fatalf("publicTemplate(%s) attributes %+v differ from the ECDSA key's %+v", algName(alg), tmpl.ObjectAttributes, ecAttrs)
		}
	}
}

func TestSign_RSA_PKCS1v15(t *testing.T) {
	tp := openSim(t)
	key := newSimRSAKey(t, tp)
	pk := key.Public().(*rsa.PublicKey)
	msg := []byte("CryptOS-PKI TPM RSA round trip")
	sum256 := sha256.Sum256(msg)
	sum384 := sha512.Sum384(msg)
	sum512 := sha512.Sum512(msg)

	for _, tc := range []struct {
		name   string
		hash   crypto.Hash
		digest []byte
	}{
		{"SHA-256", crypto.SHA256, sum256[:]},
		{"SHA-384", crypto.SHA384, sum384[:]},
		{"SHA-512", crypto.SHA512, sum512[:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := key.Sign(rand.Reader, tc.digest, tc.hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig) != pk.Size() {
				t.Fatalf("signature is %d bytes, want the modulus size %d (raw, not ASN.1-wrapped)", len(sig), pk.Size())
			}
			if err := rsa.VerifyPKCS1v15(pk, tc.hash, tc.digest, sig); err != nil {
				t.Fatalf("VerifyPKCS1v15: %v", err)
			}
		})
	}
}

// TestSign_RSA_HonoursPSSOpts checks that the scheme comes from the caller's
// opts: a PSS request must yield a PSS signature, not the PKCS#1 v1.5 one a
// scheme baked into the key would give.
func TestSign_RSA_HonoursPSSOpts(t *testing.T) {
	tp := openSim(t)
	key := newSimRSAKey(t, tp)
	pk := key.Public().(*rsa.PublicKey)
	digest := sha256.Sum256([]byte("pss"))

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	sig, err := key.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		t.Fatalf("Sign(PSS): %v", err)
	}
	if err := rsa.VerifyPSS(pk, crypto.SHA256, digest[:], sig, opts); err != nil {
		t.Fatalf("VerifyPSS: %v", err)
	}
	if rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig) == nil {
		t.Fatal("a PSS request produced a PKCS#1 v1.5 signature")
	}

	// The TPM picks its own PSS salt length. When the caller pins one, the
	// signer either returns a signature valid under that length or refuses;
	// it never returns one the caller's verifier would reject.
	pinned := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	if sig, err := key.Sign(rand.Reader, digest[:], pinned); err == nil {
		if err := rsa.VerifyPSS(pk, crypto.SHA256, digest[:], sig, pinned); err != nil {
			t.Fatalf("Sign returned a PSS signature invalid under the requested salt length: %v", err)
		}
	}
}

func TestSign_RSA_RejectsBadInput(t *testing.T) {
	tp := openSim(t)
	key := newSimRSAKey(t, tp)
	sum384 := sha512.Sum384([]byte("x"))

	if _, err := key.Sign(rand.Reader, sum384[:], nil); err == nil {
		t.Error("Sign with nil opts: want an error, RSA needs the hash and padding from opts")
	}
	if _, err := key.Sign(rand.Reader, sum384[:], crypto.SHA256); err == nil {
		t.Error("Sign with a 48-byte digest and SHA-256 opts: want a length error")
	}
	if _, err := key.Sign(rand.Reader, make([]byte, 20), crypto.SHA1); err == nil {
		t.Error("Sign with SHA-1: want an error, only SHA-2 is accepted")
	}
}

func TestSign_ECDSAIgnoresOpts(t *testing.T) {
	tp := openSim(t)
	ck, err := tp.CreateKey(AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	key, err := tp.LoadKey(ck.Private, ck.Public)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	defer func() { _ = key.Close() }()
	sum := sha512.Sum384([]byte("ecdsa with opts"))
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA384)
	if err != nil {
		t.Fatalf("Sign(ECDSA, SHA384 opts): %v", err)
	}
	if !ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), sum[:], sig) {
		t.Fatal("ecdsa.VerifyASN1 rejected a TPM-signed signature")
	}
}
