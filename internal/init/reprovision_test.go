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
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// TestReprovisioner_PersistsAndReboots verifies that Install persists the
// config to the mounted state FileStore and signals a reboot, returning
// RequiresReboot: true. This is the re-provision landing after a reset: the
// state partition exists but holds no config, so the applied config is written
// to it rather than re-partitioning a disk.
func TestReprovisioner_PersistsAndReboots(t *testing.T) {
	store := config.NewFileStore(t.TempDir())
	rebootCh := make(chan struct{}, 1)
	rp := &reprovisioner{store: store, rebootCh: rebootCh}

	resp, err := rp.Install(context.Background(), validMachineConfig())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !resp.GetRequiresReboot() {
		t.Fatal("RequiresReboot = false, want true")
	}

	// Config must be persisted to the state store.
	if _, _, ok, rerr := store.Read(); rerr != nil || !ok {
		t.Fatalf("config not persisted: ok=%v err=%v", ok, rerr)
	}

	// Reboot must be signalled.
	select {
	case <-rebootCh:
		// expected
	default:
		t.Fatal("rebootCh did not receive a signal after a successful re-provision")
	}
}

// TestReprovisioner_NilConfig verifies that a nil proto returns
// INVALID_ARGUMENT, does not persist, and does not signal a reboot.
func TestReprovisioner_NilConfig(t *testing.T) {
	store := config.NewFileStore(t.TempDir())
	rebootCh := make(chan struct{}, 1)
	rp := &reprovisioner{store: store, rebootCh: rebootCh}

	_, err := rp.Install(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}

	if _, _, ok, _ := store.Read(); ok {
		t.Fatal("config was persisted for a nil config; expected none")
	}
	select {
	case <-rebootCh:
		t.Fatal("rebootCh received a signal for a nil config; should not reboot")
	default:
		// expected: no reboot signal
	}
}

// TestReprovisioner_InvalidConfig verifies that a config that fails validation
// returns INVALID_ARGUMENT, does not persist, and does not signal a reboot.
func TestReprovisioner_InvalidConfig(t *testing.T) {
	store := config.NewFileStore(t.TempDir())
	rebootCh := make(chan struct{}, 1)
	rp := &reprovisioner{store: store, rebootCh: rebootCh}

	cfg := validMachineConfig()
	cfg.Network.Address = "not-a-cidr" // fails config.Validate

	_, err := rp.Install(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}

	if _, _, ok, _ := store.Read(); ok {
		t.Fatal("invalid config was persisted; expected none")
	}
	select {
	case <-rebootCh:
		t.Fatal("rebootCh received a signal for an invalid config; should not reboot")
	default:
		// expected: no reboot signal
	}
}
