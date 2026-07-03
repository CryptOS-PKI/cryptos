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
	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// tpmRootBackend adapts *tpm.TPM to ceremony.RootKeyBackend. The Root key is
// created in and non-exportable from the TPM (default, hardware-backed).
type tpmRootBackend struct{ t *tpm.TPM }

func (b tpmRootBackend) ProvisionSRK() error { return b.t.ProvisionSRK() }

func (b tpmRootBackend) CreateKey(alg tpm.KeyAlgorithm) (*tpm.CreatedKey, error) {
	return b.t.CreateKey(alg)
}

func (b tpmRootBackend) LoadKey(private, public []byte) (ceremony.RootSigner, error) {
	k, err := b.t.LoadKey(private, public)
	if err != nil {
		return nil, err
	}
	return k, nil // *tpm.Key satisfies ceremony.RootSigner
}
