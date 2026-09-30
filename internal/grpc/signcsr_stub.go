//go:build !debug_signcsr

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

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// SignCSR is not available in production builds. Compile with
// -tags=debug_signcsr to enable the debug implementation that signs via
// the configured Signer.
func (s *Server) SignCSR(_ context.Context, _ *cryptosv1.SignCSRRequest) (*cryptosv1.SignCSRResponse, error) {
	return nil, status.Error(codes.Unimplemented, "SignCSR is debug-only; build with -tags=debug_signcsr to enable")
}
