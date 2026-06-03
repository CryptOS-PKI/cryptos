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
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// Capabilities describes the subset of the TPM's reported capabilities
// that PID 1 needs to check at boot.
type Capabilities struct {
	// LoadedCurves is the set of ECC curves the TPM supports. A Phase 1
	// Root cannot proceed unless this contains TPMECCNistP384.
	LoadedCurves []tpm2.TPMECCCurve
}

// SupportsCurve reports whether the TPM advertised the given ECC curve.
func (c Capabilities) SupportsCurve(curve tpm2.TPMECCCurve) bool {
	for _, supported := range c.LoadedCurves {
		if supported == curve {
			return true
		}
	}
	return false
}

// Probe issues TPM2_GetCapability(TPM_CAP_ECC_CURVES) and returns the
// list of supported curves. Used at boot for fail-fast checks.
//
// The query asks for up to 16 curves, which is more than the spec
// defines, so a single call is sufficient on every real TPM.
func (t *TPM) Probe() (Capabilities, error) {
	rwc, err := t.transport()
	if err != nil {
		return Capabilities{}, err
	}

	resp, err := (tpm2.GetCapability{
		Capability:    tpm2.TPMCapECCCurves,
		Property:      0,
		PropertyCount: 16,
	}).Execute(rwc)
	if err != nil {
		return Capabilities{}, fmt.Errorf("tpm: probe: GetCapability(ECC_CURVES): %w", err)
	}

	curves, err := resp.CapabilityData.Data.ECCCurves()
	if err != nil {
		return Capabilities{}, fmt.Errorf("tpm: probe: unexpected capability data: %w", err)
	}

	out := make([]tpm2.TPMECCCurve, len(curves.ECCCurves))
	copy(out, curves.ECCCurves)
	return Capabilities{LoadedCurves: out}, nil
}
