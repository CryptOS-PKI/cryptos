// Command cryptos-switchroot is the shim init for the SquashFS-root boot
// path. It is the /init of a tiny initramfs that also carries the read-only
// SquashFS rootfs image; it loop-mounts that image and switch_roots into it
// so the real PID 1 (the Go init baked into the SquashFS) runs from an
// immutable, RAM-resident read-only root. See internal/switchroot.
//
// It is only ever run as PID 1 on Linux. On failure there is nowhere to go,
// so it panics — PID 1 dying triggers a kernel panic and reboot, which is
// the correct fail-closed behavior for a trust anchor that can't boot.
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
	"os"

	"github.com/CryptOS-PKI/cryptos/internal/switchroot"
)

func main() {
	if err := switchroot.Run(switchroot.NewSystem(), os.Environ()); err != nil {
		panic("cryptos-switchroot: " + err.Error())
	}
}
