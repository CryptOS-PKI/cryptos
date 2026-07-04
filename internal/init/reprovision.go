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
	"crypto/sha256"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// reprovisioner implements grpc.Installer for the re-provision maintenance path
// reached after a console Reset. Unlike maintenanceInstaller (the bare-disk ISO
// installer, which re-partitions a disk), the state partition already exists and
// is mounted but holds no config: the reset erased the state-key material and
// cleared the staged ESP config, then rebooted. So ApplyConfig here PERSISTS the
// applied config to the mounted state store and reboots into the ceremony,
// rather than installing to a raw disk.
//
// Reusing the grpc.Installer interface (NewMaintenance + Installer set) avoids a
// server change: the ApplyConfig handler calls Install, which here means
// "persist to state + reboot".
//
// Reboot handoff mirrors maintenanceInstaller: Install sends on rebootCh after
// persisting, inside the gRPC handler and before it returns to the interceptor.
// runReprovisionMaintenance selects on rebootCh; the gRPC framework flushes the
// ApplyConfigResponse to the client before the transport teardown, so the client
// observes RequiresReboot: true before the connection drops on reboot.
type reprovisioner struct {
	store    *config.FileStore
	rebootCh chan struct{}
}

// Install validates cfg, persists it to the mounted state store, signals a
// reboot, and returns RequiresReboot: true. It does not touch any disk: the
// state partition is already present from the pre-reset install.
func (r *reprovisioner) Install(_ context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	parsed, err := config.FromProto(cfg)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "reprovision: parse: %v", err)
	}
	if err := parsed.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "reprovision: validate: %v", err)
	}
	raw, err := parsed.Marshal()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reprovision: marshal config: %v", err)
	}
	gen, err := r.store.Write(raw)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reprovision: persist config: %v", err)
	}

	// Signal runReprovisionMaintenance to return so PID 1 reboots. Non-blocking
	// send: if nothing is listening (e.g. in unit tests) we simply continue.
	select {
	case r.rebootCh <- struct{}{}:
	default:
	}

	digest := sha256.Sum256(raw)
	return &cryptosv1.ApplyConfigResponse{
		Generation:     gen,
		RequiresReboot: true,
		ConfigDigest:   digest[:],
	}, nil
}
