// Command cryptosctl is the operator CLI for a CryptOS node. It speaks
// the same mTLS gRPC API as the Fleet Manager and is the only management
// surface for a standalone (unlinked) node.
//
// Phase 1 ships the bootstrap, status, identity show/validate, ceremony
// driving, config apply, and (debug-only) sign-csr subcommands.
// Subcommands ship as the underlying RPCs land.
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
)

func main() {
	fmt.Fprintln(os.Stderr, "cryptosctl: not yet implemented")
	os.Exit(1)
}
