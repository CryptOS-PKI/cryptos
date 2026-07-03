// Command init is the CryptOS PID 1 binary. It owns OS bring-up: early
// mounts, networking, TPM access, encrypted state-partition unseal,
// embedded etcd, the gRPC management API, and the first-boot ceremony.
// It is compiled CGO_ENABLED=0 and dropped into the SquashFS rootfs at
// /init.
//
// The whole sequence lives in internal/init.Boot; this entry point just
// runs it and is fail-closed — any error reboots the node (Linux) rather
// than serving in a half-brought-up state. Boot is device-level I/O and
// only runs on a Linux node with a TPM; runtime validation is the
// QEMU + swtpm integration boot.
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
	"log"

	bootinit "github.com/CryptOS-PKI/cryptos/internal/init"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("cryptos init: ")

	if err := bootinit.Boot(context.Background()); err != nil {
		log.Printf("boot failed: %v", err)
	}
	// PID 1 must never return; fail-closed reboot (Linux) or exit.
	fatal()
}
