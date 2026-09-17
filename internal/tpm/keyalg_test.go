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
	"strings"
	"testing"
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

// TestPublicTemplateRejectsRSA pins the boundary of RSA CA support: the
// software key backend holds RSA CA keys, this package does not. The error has
// to name the reason, because the alternative failure mode is an operator
// setting an RSA algorithm on a TPM-backed node and getting an opaque refusal.
func TestPublicTemplateRejectsRSA(t *testing.T) {
	for _, alg := range []KeyAlgorithm{AlgorithmRSA2048, AlgorithmRSA3072, AlgorithmRSA4096} {
		if _, err := publicTemplate(alg); err == nil {
			t.Errorf("publicTemplate(%d): want error, got nil", alg)
		} else if !strings.Contains(err.Error(), "RSA") {
			t.Errorf("publicTemplate(%d) error = %q, want it to mention RSA", alg, err)
		}
	}
	if _, err := publicTemplate(AlgorithmECDSAP384); err != nil {
		t.Errorf("publicTemplate(AlgorithmECDSAP384): unexpected error: %v", err)
	}
}
