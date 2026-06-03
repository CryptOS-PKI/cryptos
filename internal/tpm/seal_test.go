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
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealUnseal_RoundTrip(t *testing.T) {
	tpm := openSim(t)

	secret := make([]byte, 32) // a LUKS master key is 32 bytes
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	priv, pub, err := tpm.SealToPCR(secret, DefaultSealPCRs)
	if err != nil {
		t.Fatalf("SealToPCR: %v", err)
	}
	if len(priv) == 0 || len(pub) == 0 {
		t.Fatalf("SealToPCR returned empty blob(s): priv=%d pub=%d", len(priv), len(pub))
	}

	got, err := tpm.UnsealWithPCR(priv, pub, DefaultSealPCRs)
	if err != nil {
		t.Fatalf("UnsealWithPCR: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("unsealed data mismatch: got %x, want %x", got, secret)
	}

	// Unsealing twice works (each call opens a fresh policy session).
	if _, err := tpm.UnsealWithPCR(priv, pub, DefaultSealPCRs); err != nil {
		t.Fatalf("second UnsealWithPCR: %v", err)
	}
}

func TestUnseal_FailsAfterPCRDrift(t *testing.T) {
	tpm := openSim(t)

	secret := []byte("seal-me-to-pcr-7")
	priv, pub, err := tpm.SealToPCR(secret, []int{7})
	if err != nil {
		t.Fatalf("SealToPCR: %v", err)
	}

	// Sanity: unseal works before drift.
	if _, err := tpm.UnsealWithPCR(priv, pub, []int{7}); err != nil {
		t.Fatalf("pre-drift UnsealWithPCR: %v", err)
	}

	// Extend PCR 7 — now it no longer matches the seal-time value.
	if err := tpm.ExtendPCR(7, []byte("a firmware/config change")); err != nil {
		t.Fatalf("ExtendPCR: %v", err)
	}

	if _, err := tpm.UnsealWithPCR(priv, pub, []int{7}); err == nil {
		t.Fatal("UnsealWithPCR succeeded after PCR drift, want failure")
	}
}

func TestSeal_MultiplePCRs(t *testing.T) {
	tpm := openSim(t)
	secret := []byte("multi-pcr-secret")
	pcrs := []int{7, 11, 14}
	priv, pub, err := tpm.SealToPCR(secret, pcrs)
	if err != nil {
		t.Fatalf("SealToPCR: %v", err)
	}
	got, err := tpm.UnsealWithPCR(priv, pub, pcrs)
	if err != nil {
		t.Fatalf("UnsealWithPCR: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("multi-PCR unseal mismatch")
	}

	// Drifting any one of the sealed PCRs breaks the unseal.
	if err := tpm.ExtendPCR(11, []byte("change")); err != nil {
		t.Fatalf("ExtendPCR: %v", err)
	}
	if _, err := tpm.UnsealWithPCR(priv, pub, pcrs); err == nil {
		t.Fatal("unseal succeeded after one of several PCRs drifted, want failure")
	}
}

func TestSeal_InputValidation(t *testing.T) {
	tpm := openSim(t)
	if _, _, err := tpm.SealToPCR(nil, DefaultSealPCRs); err == nil {
		t.Error("SealToPCR(nil data) = nil error, want error")
	}
	if _, _, err := tpm.SealToPCR([]byte("x"), nil); err == nil {
		t.Error("SealToPCR(no PCRs) = nil error, want error")
	}
	if _, err := tpm.UnsealWithPCR([]byte("x"), []byte("y"), nil); err == nil {
		t.Error("UnsealWithPCR(no PCRs) = nil error, want error")
	}
	if _, err := tpm.UnsealWithPCR([]byte("garbage"), []byte("garbage"), DefaultSealPCRs); err == nil {
		t.Error("UnsealWithPCR(garbage blobs) = nil error, want error")
	}
}
