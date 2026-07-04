package reset_test

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
	"errors"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

// eraserFunc adapts a plain func to the reset.Eraser interface.
type eraserFunc func(context.Context) error

func (f eraserFunc) Erase(ctx context.Context) error { return f(ctx) }

func TestWipeMismatchDoesNothing(t *testing.T) {
	var erased, cleared, rebooted bool
	err := reset.Wipe(context.Background(), "WRONG", reset.Options{
		RootCN:     "Root CA G1",
		Device:     eraserFunc(func(context.Context) error { erased = true; return nil }),
		ClearStage: func() error { cleared = true; return nil },
		Reboot:     func() { rebooted = true },
	})
	if !errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("err = %v, want ErrConfirmMismatch", err)
	}
	if erased || cleared || rebooted {
		t.Fatalf("mismatch must no-op: erased=%v cleared=%v rebooted=%v", erased, cleared, rebooted)
	}
}

func TestWipeEraseErrorDoesNotReboot(t *testing.T) {
	eraseErr := errors.New("cryptsetup busy")
	var cleared, rebooted bool
	err := reset.Wipe(context.Background(), "Root CA G1", reset.Options{
		RootCN:     "Root CA G1",
		Device:     eraserFunc(func(context.Context) error { return eraseErr }),
		ClearStage: func() error { cleared = true; return nil },
		Reboot:     func() { rebooted = true },
	})
	if !errors.Is(err, eraseErr) {
		t.Fatalf("err = %v, want the erase error", err)
	}
	if cleared {
		t.Fatalf("ClearStage must not run after an erase failure")
	}
	if rebooted {
		t.Fatalf("fail-safe: must not reboot after an erase failure")
	}
}

func TestWipeHappyPath(t *testing.T) {
	var erased, cleared, rebooted bool
	err := reset.Wipe(context.Background(), "Root CA G1", reset.Options{
		RootCN:     "Root CA G1",
		Device:     eraserFunc(func(context.Context) error { erased = true; return nil }),
		ClearStage: func() error { cleared = true; return nil },
		Reboot:     func() { rebooted = true },
	})
	if err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if !erased || !cleared || !rebooted {
		t.Fatalf("happy path must run all steps: erased=%v cleared=%v rebooted=%v", erased, cleared, rebooted)
	}
}

func TestWipeClearStageErrorStillReboots(t *testing.T) {
	var erased, rebooted bool
	err := reset.Wipe(context.Background(), "Root CA G1", reset.Options{
		RootCN:     "Root CA G1",
		Device:     eraserFunc(func(context.Context) error { erased = true; return nil }),
		ClearStage: func() error { return errors.New("stage delete failed") },
		Reboot:     func() { rebooted = true },
	})
	if err != nil {
		t.Fatalf("ClearStage error must not fail Wipe: %v", err)
	}
	if !erased {
		t.Fatalf("Erase must run before the best-effort ClearStage")
	}
	if !rebooted {
		t.Fatalf("ClearStage is best-effort: must still reboot")
	}
}

func TestWipeConstantTimeMatch(t *testing.T) {
	// A confirm CN that is a prefix of the Root CN must not match.
	var erased bool
	err := reset.Wipe(context.Background(), "Root CA", reset.Options{
		RootCN:     "Root CA G1",
		Device:     eraserFunc(func(context.Context) error { erased = true; return nil }),
		ClearStage: func() error { return nil },
		Reboot:     func() {},
	})
	if !errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("prefix CN must not match: err=%v", err)
	}
	if erased {
		t.Fatalf("prefix CN must not trigger an erase")
	}
}
