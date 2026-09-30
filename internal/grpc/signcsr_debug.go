//go:build debug_signcsr

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
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// SignCSR is the debug-only signing endpoint. Enabled only when the
// build tag debug_signcsr is set, and only used by the Phase 1
// integration test harness. Production builds return UNIMPLEMENTED
// from the corresponding stub.
func (s *Server) SignCSR(ctx context.Context, req *cryptosv1.SignCSRRequest) (*cryptosv1.SignCSRResponse, error) {
	if s.cfg.Signer == nil {
		return nil, status.Error(codes.FailedPrecondition, "SignCSR: no Signer configured")
	}
	if req == nil || len(req.CsrDer) == 0 {
		return nil, status.Error(codes.InvalidArgument, "SignCSR: csr_der is required")
	}
	certDER, err := s.cfg.Signer.SignCSR(ctx, req.CsrDer, req.Profile)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, status.Error(codes.Canceled, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "SignCSR: %v", err)
	}
	return &cryptosv1.SignCSRResponse{CertDer: certDER}, nil
}
