// Command init is the CryptOS PID 1 binary. It owns OS bring-up: early
// mounts, networking, TPM access, encrypted state-partition unseal,
// embedded etcd, the gRPC management API, and the first-boot ceremony.
// It is compiled CGO_ENABLED=0 and dropped into the SquashFS rootfs at
// /init.
//
// Phase 1 status: the supervisor and early-mount step are wired here.
// The remainder of the boot sequence (networking via rtnetlink,
// TPM-sealed LUKS unseal, embedded etcd, and the mTLS + local gRPC
// listeners) is completed on a Linux host with QEMU + swtpm where it can
// be validated end to end. Until then this binary is fail-closed: it
// reboots rather than serving in a half-brought-up state.
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
	"log"

	bootinit "github.com/CryptOS-PKI/cryptos/internal/init"
	"github.com/CryptOS-PKI/cryptos/internal/init/mounts"
)

// errBootSequenceDeferred marks the parts of the boot sequence not yet
// wired in this build. It keeps PID 1 honest and fail-closed instead of
// pretending to have finished bring-up.
var errBootSequenceDeferred = errors.New(
	"boot sequence beyond early mounts is not yet wired: networking (rtnetlink), " +
		"TPM-sealed LUKS unseal, embedded etcd, and the mTLS/local gRPC listeners " +
		"are completed on a Linux host with QEMU + swtpm")

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

// bringUpSteps returns the ordered boot bring-up steps. Phase 1 wires the
// early kernel mounts; the rest is represented as an explicit deferral so
// the sequence is honest and fail-closed.
func bringUpSteps() []bootinit.Step {
	return []bootinit.Step{
		{Name: "early-mounts", Run: func(context.Context) error { return mounts.EarlyMounts() }},
		{Name: "boot-sequence", Run: func(context.Context) error { return errBootSequenceDeferred }},
	}
}
