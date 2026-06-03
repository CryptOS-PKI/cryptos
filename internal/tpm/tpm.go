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
	"errors"
	"fmt"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// SRKPersistentHandle is the persistent handle at which we install the
// Storage Hierarchy primary key (Storage Root Key). This follows the
// Microsoft TBS convention used by most modern TPM stacks.
const SRKPersistentHandle = 0x81000001

// TPM is an open connection to a TPM 2.0 device — either /dev/tpmrm0 on
// real hardware or an in-process simulator used by tests.
//
// TPM is not safe for concurrent use; callers serialize access at a
// higher level (the supervisor in PID 1).
type TPM struct {
	rwc transport.TPMCloser
}

// DefaultDevice is the path PID 1 opens by default on Linux: the
// resource-managed TPM 2.0 device.
const DefaultDevice = "/dev/tpmrm0"

// Open opens the TPM at the given path. If path is empty, DefaultDevice
// is used.
func Open(path string) (*TPM, error) {
	if path == "" {
		path = DefaultDevice
	}
	rwc, err := linuxtpm.Open(path)
	if err != nil {
		return nil, fmt.Errorf("tpm: open %q: %w", path, err)
	}
	return &TPM{rwc: rwc}, nil
}

// OpenSimulator returns a TPM backed by an in-process Microsoft TPM2
// simulator. Intended for tests and CI; never used in a built UKI.
func OpenSimulator() (*TPM, error) {
	sim, err := simulator.Get()
	if err != nil {
		return nil, fmt.Errorf("tpm: open simulator: %w", err)
	}
	return &TPM{rwc: transport.FromReadWriteCloser(sim)}, nil
}

// Close releases the underlying TPM connection. Persistent objects
// (e.g. the SRK at SRKPersistentHandle) remain in the TPM across opens.
func (t *TPM) Close() error {
	if t == nil || t.rwc == nil {
		return nil
	}
	if err := t.rwc.Close(); err != nil {
		return fmt.Errorf("tpm: close: %w", err)
	}
	t.rwc = nil
	return nil
}

// transport returns the underlying transport for use by command helpers
// within the package. Returns ErrClosed if the TPM is no longer open.
func (t *TPM) transport() (transport.TPM, error) {
	if t == nil || t.rwc == nil {
		return nil, ErrClosed
	}
	return t.rwc, nil
}

// ErrClosed is returned when an operation is attempted on a closed TPM
// or Key handle.
var ErrClosed = errors.New("tpm: connection closed")
