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
	"strings"
	"testing"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// nodeid mode must build software backends WITHOUT opening a TPM. This test
// host has no TPM, so a passing result proves the TPM was never touched.
func TestNewStateKeyBackends_NodeID(t *testing.T) {
	prot, root, closeFn, tpmState, err := newStateKeyBackends("nodeid", config.StateKey{})
	if err != nil {
		t.Fatalf("nodeid backends: %v", err)
	}
	defer closeFn()
	if prot == nil || prot.Name() != "nodeid" {
		t.Errorf("protector = %v, want nodeid", prot)
	}
	if _, ok := root.(softRootBackend); !ok {
		t.Errorf("root backend = %T, want softRootBackend", root)
	}
	if tpmState != cryptosv1.TpmState_TPM_STATE_UNAVAILABLE {
		t.Errorf("tpmState = %v, want UNAVAILABLE", tpmState)
	}
}

// kms mode must build the kms protector with a software Root backend and never
// open a TPM. This test host has no TPM, so a passing result proves the TPM was
// never touched.
func TestNewStateKeyBackends_KMS(t *testing.T) {
	sk := config.StateKey{
		Mode: config.StateKeyModeKMS,
		KMS:  &config.KmsStateKey{Endpoint: "https://kms.example"},
	}
	prot, root, closeFn, tpmState, err := newStateKeyBackends(config.StateKeyModeKMS, sk)
	if err != nil {
		t.Fatalf("kms backends: %v", err)
	}
	defer closeFn()
	if prot == nil || prot.Name() != "kms" {
		t.Errorf("protector = %v, want kms", prot)
	}
	if _, ok := root.(softRootBackend); !ok {
		t.Errorf("root backend = %T, want softRootBackend", root)
	}
	if tpmState != cryptosv1.TpmState_TPM_STATE_UNAVAILABLE {
		t.Errorf("tpmState = %v, want UNAVAILABLE", tpmState)
	}
}

// kms mode without a usable kms section must fail closed.
func TestNewStateKeyBackends_KMSMissingConfig(t *testing.T) {
	if _, _, _, _, err := newStateKeyBackends(config.StateKeyModeKMS, config.StateKey{Mode: config.StateKeyModeKMS}); err == nil {
		t.Fatal("kms mode with no kms endpoint must fail closed")
	}
}

// tpm mode on a host with no TPM must fail closed with the nodeID hint.
func TestNewStateKeyBackends_TPMHintOnNoDevice(t *testing.T) {
	_, _, _, _, err := newStateKeyBackends("tpm", config.StateKey{})
	if err == nil {
		t.Fatal("want error opening TPM on a TPM-less host")
	}
	if !strings.Contains(err.Error(), "nodeID image variant") {
		t.Errorf("error missing nodeID hint: %v", err)
	}
}
