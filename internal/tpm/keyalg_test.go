package tpm

/*
Apache License 2.0

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
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestRSAKeyBits(t *testing.T) {
	tests := []struct {
		alg       KeyAlgorithm
		wantBits  int
		wantIsRSA bool
	}{
		{alg: AlgorithmRSA2048, wantBits: 2048, wantIsRSA: true},
		{alg: AlgorithmRSA3072, wantBits: 3072, wantIsRSA: true},
		{alg: AlgorithmRSA4096, wantBits: 4096, wantIsRSA: true},
		{alg: AlgorithmECDSAP384, wantBits: 0, wantIsRSA: false},
		{alg: KeyAlgorithm(999), wantBits: 0, wantIsRSA: false},
	}
	for _, tc := range tests {
		bits, isRSA := RSAKeyBits(tc.alg)
		if isRSA != tc.wantIsRSA || bits != tc.wantBits {
			t.Errorf("RSAKeyBits(%d) = (%d, %v), want (%d, %v)", tc.alg, bits, isRSA, tc.wantBits, tc.wantIsRSA)
		}
	}
}

// TestPublicTemplateRSAFloor pins the boundary of TPM-held RSA CA keys: RSA-3072
// and RSA-4096 get a template, RSA-2048 is refused because a CA key below the
// 3072-bit subject-key floor could not certify a key of its own size. The error
// has to name the reason, because the alternative failure mode is an operator
// setting RSA-2048 on a TPM-backed node and getting an opaque refusal.
func TestPublicTemplateRSAFloor(t *testing.T) {
	if _, err := publicTemplate(AlgorithmRSA2048); err == nil {
		t.Error("publicTemplate(AlgorithmRSA2048): want error, got nil")
	} else if !strings.Contains(err.Error(), "3072") {
		t.Errorf("publicTemplate(AlgorithmRSA2048) error = %q, want it to name the 3072-bit floor", err)
	}
	for _, alg := range []KeyAlgorithm{AlgorithmRSA3072, AlgorithmRSA4096} {
		tmpl, err := publicTemplate(alg)
		if err != nil {
			t.Errorf("publicTemplate(%d): unexpected error: %v", alg, err)
		} else if tmpl.Type != tpm2.TPMAlgRSA {
			t.Errorf("publicTemplate(%d).Type = 0x%x, want RSA", alg, tmpl.Type)
		}
	}
	if _, err := publicTemplate(AlgorithmECDSAP384); err != nil {
		t.Errorf("publicTemplate(AlgorithmECDSAP384): unexpected error: %v", err)
	}
}
