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
	"crypto/sha256"
	"testing"
)

// extended is what a PCR holding old reads after ExtendPCR(pcr, data).
func extended(old, data []byte) []byte {
	d := sha256.Sum256(data)
	h := sha256.New()
	h.Write(old)
	h.Write(d[:])

	return h.Sum(nil)
}

func TestReadPCRs_TracksExtends(t *testing.T) {
	tpm := openSim(t)

	before, err := tpm.ReadPCRs([]int{11, 7})
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	if len(before) != 2 || len(before[7]) != sha256.Size || len(before[11]) != sha256.Size {
		t.Fatalf("ReadPCRs = %x, want two SHA-256 values", before)
	}

	if err := tpm.ExtendPCR(11, []byte("an image section")); err != nil {
		t.Fatalf("ExtendPCR: %v", err)
	}
	after, err := tpm.ReadPCRs([]int{7, 11})
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	if !bytes.Equal(after[11], extended(before[11], []byte("an image section"))) {
		t.Errorf("PCR 11 after extend = %x, want %x", after[11], extended(before[11], []byte("an image section")))
	}
	if !bytes.Equal(after[7], before[7]) {
		t.Error("PCR 7 moved though only PCR 11 was extended")
	}
}

// The upgrade case: seal to the PCR 11 value a later boot will reach, and
// check it opens only once the TPM actually gets there.
func TestSealToPCRValues_UnsealsOnlyAtThePredictedValues(t *testing.T) {
	tpm := openSim(t)
	secret := []byte("state key for the next image")

	now, err := tpm.ReadPCRs(DefaultSealPCRs)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	next := map[int][]byte{7: now[7], 11: extended(now[11], []byte("next image"))}

	priv, pub, err := tpm.SealToPCRValues(secret, next)
	if err != nil {
		t.Fatalf("SealToPCRValues: %v", err)
	}
	if _, err := tpm.UnsealWithPCR(priv, pub, DefaultSealPCRs); err == nil {
		t.Fatal("unsealed before PCR 11 reached the predicted value")
	}

	if err := tpm.ExtendPCR(11, []byte("next image")); err != nil {
		t.Fatalf("ExtendPCR: %v", err)
	}
	got, err := tpm.UnsealWithPCR(priv, pub, DefaultSealPCRs)
	if err != nil {
		t.Fatalf("UnsealWithPCR at the predicted values: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("unsealed %q, want %q", got, secret)
	}
}

func TestSealToPCRValues_AtTheCurrentValuesMatchesSealToPCR(t *testing.T) {
	tpm := openSim(t)

	now, err := tpm.ReadPCRs(DefaultSealPCRs)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	priv, pub, err := tpm.SealToPCRValues([]byte("k"), now)
	if err != nil {
		t.Fatalf("SealToPCRValues: %v", err)
	}
	if _, err := tpm.UnsealWithPCR(priv, pub, DefaultSealPCRs); err != nil {
		t.Fatalf("UnsealWithPCR: %v", err)
	}
}

func TestSealToPCRValues_RejectsBadInput(t *testing.T) {
	tpm := openSim(t)
	good := make([]byte, sha256.Size)

	for name, tc := range map[string]struct {
		data   []byte
		values map[int][]byte
	}{
		"empty data":  {nil, map[int][]byte{7: good}},
		"no PCRs":     {[]byte("k"), nil},
		"short value": {[]byte("k"), map[int][]byte{7: good, 11: good[:20]}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := tpm.SealToPCRValues(tc.data, tc.values); err == nil {
				t.Fatal("SealToPCRValues accepted bad input")
			}
		})
	}
	if _, err := tpm.ReadPCRs(nil); err == nil {
		t.Fatal("ReadPCRs accepted an empty selection")
	}
}
