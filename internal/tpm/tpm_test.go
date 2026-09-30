package tpm

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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// openSim is a test helper that returns a simulator-backed TPM with
// the SRK already provisioned.
func openSim(t *testing.T) *TPM {
	t.Helper()
	tpm, err := OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator: %v", err)
	}
	t.Cleanup(func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := tpm.ProvisionSRK(); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	return tpm
}

func TestProvisionSRK_Idempotent(t *testing.T) {
	tpm := openSim(t)
	// A second provision must be a no-op and succeed.
	if err := tpm.ProvisionSRK(); err != nil {
		t.Fatalf("second ProvisionSRK: %v", err)
	}
	// And a third, for good measure.
	if err := tpm.ProvisionSRK(); err != nil {
		t.Fatalf("third ProvisionSRK: %v", err)
	}
}

func TestProbe_SupportsP384(t *testing.T) {
	tpm := openSim(t)
	caps, err := tpm.Probe()
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !caps.SupportsCurve(tpm2.TPMECCNistP384) {
		t.Fatalf("simulator must support P-384; got curves %v", caps.LoadedCurves)
	}
	if !caps.SupportsCurve(tpm2.TPMECCNistP256) {
		t.Fatalf("simulator must support P-256; got curves %v", caps.LoadedCurves)
	}
}

func TestCreateAndLoad_P384(t *testing.T) {
	tpm := openSim(t)
	ck, err := tpm.CreateKey(AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if len(ck.Private) == 0 || len(ck.Public) == 0 {
		t.Fatalf("CreateKey returned empty blob(s): priv=%d pub=%d", len(ck.Private), len(ck.Public))
	}
	if len(ck.CreationData) == 0 || len(ck.CreationTicket) == 0 {
		t.Fatalf("CreateKey returned empty creation evidence: data=%d ticket=%d", len(ck.CreationData), len(ck.CreationTicket))
	}
	key, err := tpm.LoadKey(ck.Private, ck.Public)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	defer func() {
		if err := key.Close(); err != nil {
			t.Errorf("Key.Close: %v", err)
		}
	}()

	pk, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() did not return *ecdsa.PublicKey: %T", key.Public())
	}
	if pk.Curve.Params().BitSize != 384 {
		t.Fatalf("Public key curve is not P-384: bitsize=%d", pk.Curve.Params().BitSize)
	}
}

func TestSign_RoundTrip_P384(t *testing.T) {
	tpm := openSim(t)
	ck, err := tpm.CreateKey(AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	key, err := tpm.LoadKey(ck.Private, ck.Public)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	msg := []byte("CryptOS-PKI Phase 1 TPM round-trip test")
	sum := sha512.Sum384(msg)

	sig, err := key.Sign(rand.Reader, sum[:], nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pk := key.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pk, sum[:], sig) {
		t.Fatalf("ecdsa.VerifyASN1 rejected a TPM-signed signature")
	}
}

func TestSign_RejectsWrongDigestLength(t *testing.T) {
	tpm := openSim(t)
	ck, err := tpm.CreateKey(AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	key, err := tpm.LoadKey(ck.Private, ck.Public)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	// SHA-256 digest length (32) is not valid for a P-384 key here —
	// the package pairs P-384 with SHA-384 (48-byte digest) only.
	if _, err := key.Sign(rand.Reader, make([]byte, 32), nil); err == nil {
		t.Fatalf("Sign should have rejected a 32-byte digest for P-384")
	}
}

func TestKey_SignAfterCloseFails(t *testing.T) {
	tpm := openSim(t)
	ck, err := tpm.CreateKey(AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	key, err := tpm.LoadKey(ck.Private, ck.Public)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if err := key.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sum := sha512.Sum384([]byte("post-close"))
	if _, err := key.Sign(rand.Reader, sum[:], nil); err == nil {
		t.Fatalf("Sign on closed key should have failed")
	}
}
