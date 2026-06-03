// Command init is the CryptOS PID 1 binary. It owns OS bring-up:
// early mounts, networking, TPM access, encrypted state-partition
// unseal, embedded etcd, the gRPC management API, and the first-boot
// ceremony. It is compiled CGO_ENABLED=0 and dropped into the SquashFS
// rootfs at /init.
//
// This file is a scaffold; subsystem packages under internal/ ship in
// follow-up PRs as Phase 1 progresses.
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
	"fmt"
	"os"

	// Pin the api module as a build-time dependency so go mod tidy
	// keeps it pinned. The gRPC handlers in internal/grpc will
	// import these types in a follow-up PR.
	_ "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func main() {
	fmt.Fprintln(os.Stderr, "cryptos init: not yet implemented")
	os.Exit(1)
}
