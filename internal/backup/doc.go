// Package backup implements the versioned, self-describing encrypted
// envelope used for operator-held CA key escrow (export/restore).
//
// An envelope seals an arbitrary plaintext payload under an operator
// passphrase. The key is derived from the passphrase with Argon2id over a
// random per-envelope salt; the payload is sealed with AES-256-GCM under
// that derived key, with the envelope header (version + KDF parameters +
// salt + nonce) bound in as additional authenticated data so any tampering
// with the header is detected on open.
//
// The envelope is self-describing: Open reads the KDF parameters and salt
// back out of the header, so an envelope sealed with one parameter set can
// still be opened later without out-of-band knowledge of those parameters.
package backup

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
