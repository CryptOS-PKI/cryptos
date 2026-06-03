// Package ca builds X.509 certificate templates and invokes
// crypto/x509.CreateCertificate with a TPM-backed crypto.Signer. RFC
// 5280 conformance is mandatory: every Phase 1 Root certificate must
// pass zlint with zero errors and zero warnings.
//
// Phase 1 produces a single self-signed Root cert. Phase 2 adds the
// validateAndSign pipeline that every CSR — from gRPC RPCs and from
// protocol adapters — funnels through before signing.
//
// Strictly stdlib + golang.org/x/crypto on this path. No PKI/CA wrappers
// (cfssl, smallstep, go-acme/lego, etc.) — they are explicitly off the
// cert path. Wire-format-only libraries for SCEP/EST/ACME adapters are
// allowed under separate rules but never used here.
package ca

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
