// Package grpc serves the NodeService gRPC API defined in the api/
// module. TLS 1.3 only (MinVersion=tls.VersionTLS13), client cert
// required and verified against the trust bundle, no plaintext
// fallback. RFC 8446 strict by construction — the stdlib does the heavy
// lifting.
//
// PID 1 refuses to bring up the network listener until the bootstrap
// admin cert (per internal/bootstrap) is loaded; the local UNIX socket
// at /run/cryptos.sock comes up earlier so on-box cryptosctl can drive
// the first-boot ceremony.
package grpc

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
