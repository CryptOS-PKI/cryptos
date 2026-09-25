package reset

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
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
)

// ErrConfirmMismatch is returned when the caller-supplied confirmation
// CN does not match the node's Root CA CN. The reset is refused and no
// destructive action is taken.
var ErrConfirmMismatch = errors.New("reset: confirmation CN does not match the Root CA CN")

// ErrNoCAIdentity is returned when the node has no CA common name yet (before
// the ceremony commits, or on a subordinate still waiting for its
// certificate), so a confirmation cannot be checked at all. It is distinct
// from ErrConfirmMismatch so a caller is not told a correct CN was mistyped.
var ErrNoCAIdentity = errors.New("reset: node has no CA identity yet; confirmation cannot be checked")

// CheckConfirm checks a caller-supplied confirmation CN against the node's CA
// CN. It fails closed: an empty caCN returns ErrNoCAIdentity, and an empty or
// different confirmation returns ErrConfirmMismatch. The empty checks run
// before the constant-time compare because ConstantTimeCompare("", "") == 1.
// Every CN-confirmed operation (reset, image activate, reboot) uses it, so they
// all refuse the same way.
func CheckConfirm(caCN, confirmCN string) error {
	if caCN == "" {
		return ErrNoCAIdentity
	}
	if confirmCN == "" || subtle.ConstantTimeCompare([]byte(confirmCN), []byte(caCN)) != 1 {
		return ErrConfirmMismatch
	}
	return nil
}

// Eraser destroys the key material on the state partition, rendering the
// encrypted data unrecoverable. It is satisfied by *luks.Device.
type Eraser interface {
	Erase(ctx context.Context) error
}

// Options carries the dependencies for a Wipe. Every field is required.
type Options struct {
	// RootCN is the node's Root CA common name. The caller-supplied
	// confirmation CN must equal it exactly.
	RootCN string
	// Device erases the state-partition key material.
	Device Eraser
	// ClearStage deletes the staged config on the ESP. It is
	// best-effort: a failure is logged and the reset proceeds.
	ClearStage func() error
	// Reboot restarts the node into maintenance. It runs only after a
	// successful erase.
	Reboot func()
}

// Wipe performs a destructive, confirmed node reset.
//
// It checks confirmCN against o.RootCN with CheckConfirm, which fails
// closed: an unset Root CN (e.g. before the identity ceremony has committed)
// returns ErrNoCAIdentity and can never authorize an erase, and an empty or
// different confirmation returns ErrConfirmMismatch. Either way no action is
// taken. On a match it erases the state
// device; if the erase errors it returns that error WITHOUT rebooting
// (fail-safe, so the node keeps serving with its identity intact). On a
// successful erase it clears the staged ESP config best-effort (logging
// but not failing on error) and then reboots, returning nil.
func Wipe(ctx context.Context, confirmCN string, o Options) error {
	if err := CheckConfirm(o.RootCN, confirmCN); err != nil {
		return err
	}
	if err := o.Device.Erase(ctx); err != nil {
		// Fail-safe: do not reboot on an erase failure. The node stays
		// up with its key material intact so the operator can recover.
		return err
	}
	if err := o.ClearStage(); err != nil {
		// Best-effort: the key material is already gone, so a stale
		// stage cannot re-provision on its own. Log and proceed.
		slog.Warn("reset: clearing staged config failed; proceeding with reboot", "error", err)
	}
	o.Reboot()
	return nil
}
