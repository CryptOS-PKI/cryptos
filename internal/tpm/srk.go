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

// ProvisionSRK ensures the Storage Root Key (Storage Hierarchy primary)
// exists at SRKPersistentHandle. It is idempotent: if the SRK is already
// persisted at that handle, ProvisionSRK is a no-op.
//
// The template used is the TCG reference ECC P-256 SRK template
// (tpm2.ECCSRKTemplate), which matches what tpm2-tools' standard
// provisioning recipe installs.
func (t *TPM) ProvisionSRK() error {
	rwc, err := t.transport()
	if err != nil {
		return err
	}

	// Fast path: if an object already lives at the persistent handle,
	// trust it and return.
	if _, err := (tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(SRKPersistentHandle),
	}.Execute(rwc)); err == nil {
		return nil
	}

	// Create the primary key under the Storage Hierarchy.
	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(rwc)
	if err != nil {
		return fmt.Errorf("tpm: srk: CreatePrimary: %w", err)
	}
	// Make sure we flush the transient primary handle once it has been
	// evicted to the persistent handle (or on error).
	defer func() {
		_, _ = (tpm2.FlushContext{FlushHandle: primary.ObjectHandle}.Execute(rwc))
	}()

	// Persist at SRKPersistentHandle.
	if _, err := (tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
		},
		PersistentHandle: tpm2.TPMHandle(SRKPersistentHandle),
	}.Execute(rwc)); err != nil {
		return fmt.Errorf("tpm: srk: EvictControl: %w", err)
	}

	return nil
}
