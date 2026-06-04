// Package integration holds the Phase 1 end-to-end acceptance test: it
// boots the UKI in QEMU + swtpm + OVMF, drives the first-boot ceremony
// with cryptosctl, and checks the Root certificate with zlint.
//
// The test is guarded by the `integration` build tag and skips unless the
// toolchain (qemu, swtpm, OVMF, a built UKI, cryptosctl, zlint) is
// present, so it is inert under a normal `go test ./...`. Run it with
// `go test -tags=integration ./test/integration/` (or `task
// test:integration`) on a Linux host that has the toolchain.
package integration

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
