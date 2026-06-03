// Package init implements the PID 1 supervisor and boot bring-up sequence:
// early mounts, hostname, TPM probe, networking, state-partition open
// (delegated to internal/storage/luks), embedded etcd start (delegated
// to internal/storage/etcd), bootstrap admin cert verification (delegated
// to internal/bootstrap), and gRPC listener startup (delegated to
// internal/grpc).
//
// The supervisor model is "everything in one process, goroutines under a
// recover boundary, panics reboot the node, no shell ever." See
// plan/specs/phase-1-core.md §5 for the exact boot sequence.
package init

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
