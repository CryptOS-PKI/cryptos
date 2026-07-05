// Package revocation owns a CryptOS CA node's certificate revocation state:
// the issued-cert and revoked-cert etcd records, an RFC 5280 CRL builder, an
// RFC 6960 OCSP responder, and the anonymous HTTP listener that publishes
// them. Serial numbers are the single join key across the store, the CRL, and
// OCSP, encoded as lowercase hex.
package revocation

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
