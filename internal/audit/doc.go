// Package audit appends to the hash-chained audit log on the encrypted
// state partition. Entry schema is api.cryptos.v1.AuditEvent; the chain
// is SHA-256 over the canonical-encoded prior entry. Entries are signed
// by an HKDF-SHA256-derived audit-signing key (label
// "cryptos.dev/audit-signer/v1") separate from the CA key — so audit
// signatures don't share session state with cert issuance.
//
// Phase 1 ships local-only persistence and a stub StreamEvents RPC.
// SIEM ship + historical retrieval are Phase 3.
package audit

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
