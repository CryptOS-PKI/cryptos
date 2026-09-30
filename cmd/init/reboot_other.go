//go:build !linux

package main

/*
Copyright The CryptOS Authors.

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

	bootinit "github.com/CryptOS-PKI/cryptos/internal/init"
)

// halt exits non-zero on non-Linux hosts. CryptOS PID 1 only ever runs on
// Linux, where halt reboots or powers off instead; this stub keeps the binary
// buildable on a developer workstation.
func halt(bootinit.ShutdownAction) {
	os.Exit(1)
}
