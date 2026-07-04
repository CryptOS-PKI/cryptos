// Package reset orchestrates a destructive, operator-confirmed node
// reset. Wipe verifies a caller-supplied Root CA CN in constant time,
// erases the state-partition key material, clears the staged ESP config
// best-effort, and reboots the node into maintenance to be
// re-provisioned.
//
// The orchestration is fail-safe: if the erase step errors it returns
// the error WITHOUT rebooting, leaving the node serving with its
// identity intact. The package is pure — the eraser, stage-clearer, and
// reboot are injected as small interfaces/funcs so it is unit-testable
// with fakes and carries no device dependencies.
package reset

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
