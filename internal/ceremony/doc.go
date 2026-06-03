// Package ceremony runs the first-boot Root ceremony state machine and
// emits CeremonyEvents on the StartCeremony gRPC stream. Phase 1 is a
// degenerate 1-of-1 ceremony; the Ceremony Manifest schema accommodates
// M-of-N for Phase 3 without a breaking change.
//
// The 11-step Phase 1 flow is specified in plan/specs/phase-1-core.md
// §6.4. All identity-creating writes are persisted via a single etcd
// transaction guarded with If(no current identity); a crash before the
// transaction commits re-runs the ceremony on next boot.
package ceremony

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
