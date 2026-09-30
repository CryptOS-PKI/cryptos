package init

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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

func TestSoftRootBackend_CreateLoadSign(t *testing.T) {
	var b softRootBackend
	if err := b.ProvisionSRK(); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	created, err := b.CreateKey(tpm.AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if len(created.Private) == 0 || len(created.Public) == 0 {
		t.Fatal("CreateKey returned empty key material")
	}
	if len(created.CreationData) != 0 || len(created.CreationTicket) != 0 {
		t.Error("software key must carry no TPM creation attestation")
	}

	signer, err := b.LoadKey(created.Private, created.Public)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	defer func() { _ = signer.Close() }()

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() type = %T, want *ecdsa.PublicKey", signer.Public())
	}
	if pub.Curve.Params().BitSize != 384 {
		t.Errorf("curve bits = %d, want 384", pub.Curve.Params().BitSize)
	}

	digest := sha512.Sum384([]byte("root cert tbs"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("signature does not verify against the loaded public key")
	}
}

func TestSoftRootBackend_RejectsWrongAlg(t *testing.T) {
	var b softRootBackend
	if _, err := b.CreateKey(tpm.KeyAlgorithm(999)); err == nil {
		t.Error("want error for unsupported algorithm")
	}
}

// TestSoftRootBackend_CreateLoadSignRSA covers an RSA CA key in the software
// backend: generated, persisted, reloaded, and able to sign. The persisted
// blob must survive a round trip because it is what the ceremony writes to the
// state partition and every later boot reads back.
func TestSoftRootBackend_CreateLoadSignRSA(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  tpm.KeyAlgorithm
		bits int
	}{
		{"rsa 2048", tpm.AlgorithmRSA2048, 2048},
		{"rsa 3072", tpm.AlgorithmRSA3072, 3072},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b softRootBackend
			created, err := b.CreateKey(tc.alg)
			if err != nil {
				t.Fatalf("CreateKey: %v", err)
			}
			signer, err := b.LoadKey(created.Private, created.Public)
			if err != nil {
				t.Fatalf("LoadKey: %v", err)
			}
			defer func() { _ = signer.Close() }()

			pub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatalf("Public() type = %T, want *rsa.PublicKey", signer.Public())
			}
			if got := pub.N.BitLen(); got != tc.bits {
				t.Errorf("modulus = %d bits, want %d", got, tc.bits)
			}

			digest := sha512.Sum384([]byte("root cert tbs"))
			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA384, digest[:], sig); err != nil {
				t.Errorf("VerifyPKCS1v15: %v", err)
			}
		})
	}
}
