// Command init is the CryptOS PID 1 binary. It owns OS bring-up: early
// mounts, networking, TPM access, encrypted state-partition unseal,
// embedded etcd, the gRPC management API, and the first-boot ceremony.
// It is compiled CGO_ENABLED=0 and dropped into the SquashFS rootfs at
// /init.
//
// Phase 1 status: early mounts and machine-config loading are wired here,
// and the boot plan (state device, mount points, listener address) is
// derived from that config. The device-level remainder of the sequence
// (TPM probe, networking, LUKS unseal, filesystem mount, embedded etcd,
// and the mTLS + local gRPC listeners) is assembled and validated on a
// Linux host with QEMU + swtpm, where each step can actually run. Until
// then this binary is fail-closed: it reboots rather than serving in a
// half-brought-up state.
package main

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
	"fmt"
	"log"
	"os"

	bootinit "github.com/CryptOS-PKI/cryptos/internal/init"
	"github.com/CryptOS-PKI/cryptos/internal/init/mounts"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// errBootSequenceDeferred marks the device-level steps not yet wired in
// this build. It keeps PID 1 honest and fail-closed instead of pretending
// to have finished bring-up.
var errBootSequenceDeferred = errors.New(
	"device bring-up beyond config load is completed on a Linux host with QEMU + swtpm: " +
		"TPM probe, networking, LUKS unseal, filesystem mount, embedded etcd, and the mTLS/local gRPC listeners")

func main() {
	log.SetFlags(0)
	log.SetPrefix("cryptos init: ")

	sup := bootinit.Supervisor{Logf: func(format string, args ...any) { log.Printf(format, args...) }}
	if err := sup.Run(context.Background(), bringUpSteps()); err != nil {
		log.Printf("boot failed: %v", err)
	}
	// PID 1 must never return; fail-closed reboot (Linux) or exit.
	fatal()
}

// bringUpSteps returns the ordered boot bring-up steps. Early mounts and
// config-driven planning are wired; the device-level remainder is an
// explicit deferral so the sequence is honest and fail-closed.
func bringUpSteps() []bootinit.Step {
	return []bootinit.Step{
		{Name: "early-mounts", Run: func(context.Context) error { return mounts.EarlyMounts() }},
		{Name: "load-config", Run: loadAndPlan},
		{Name: "device-bring-up", Run: func(context.Context) error { return errBootSequenceDeferred }},
	}
}

// loadAndPlan reads the baked-in machine config and derives the boot plan
// (state device, mount points, listener address), logging it so the
// remaining device steps have a validated, config-driven target.
func loadAndPlan(context.Context) error {
	raw, err := os.ReadFile(bootinit.DefaultConfigPath)
	if err != nil {
		return fmt.Errorf("read machine config %s: %w", bootinit.DefaultConfigPath, err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse machine config: %w", err)
	}
	paths := bootinit.DerivePaths(cfg)
	addr, err := bootinit.ManagementAddr(cfg)
	if err != nil {
		return err
	}
	log.Printf("role=%s state-device=%s mount=%s mgmt=%s first-boot=%t",
		cfg.Role.Kind, paths.Device, paths.Mount, addr, cfg.Storage.FirstBoot)
	return nil
}
