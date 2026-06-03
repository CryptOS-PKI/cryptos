// Package etcd embeds go.etcd.io/etcd/server/v3/embed in PID 1. Single
// writer in Phase 1; HA replication and watch-based secondary tailing
// land in Phase 3. Data dir lives on the encrypted state partition; the
// LUKS layer below provides encryption-at-rest, so etcd itself does
// not double-encrypt.
//
// Schema constants (key paths under /cryptos/) are exported from here
// so the rest of the code never hardcodes etcd paths.
package etcd

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
