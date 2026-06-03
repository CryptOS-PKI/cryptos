// Package tpm wraps github.com/google/go-tpm to provide:
//
//   - SRK provisioning under the Storage Hierarchy at persistent handle
//     0x81000001.
//   - Creation of ECDSA P-384 (Root) and P-256 (Issuing) signing keys
//     bound to the SRK; the private blob never leaves the TPM in the
//     clear.
//   - A crypto.Signer implementation that routes through TPM2_Sign and
//     returns DER-encoded ECDSA signatures for crypto/x509.CreateCertificate
//     to consume directly.
//   - Capability probing (PT_LOADED_CURVES) so PID 1 can fail-fast when
//     P-384 is unavailable on the target TPM.
//
// Per CLAUDE.md guiding principle #7, go-tpm is on the wire-format side
// of the rule, not the crypto side: the TPM does the math.
package tpm

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
