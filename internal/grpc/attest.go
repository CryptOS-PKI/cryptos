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

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Attest handles cryptos.v1.NodeService/Attest: the Fleet Manager sends a
// random challenge nonce and the node signs it with its CA identity key,
// returning the signature plus the identity public key so the manager can
// verify possession of the private key it pinned during enrollment. The
// maintenance servers leave Attester nil, so the RPC returns Unimplemented
// there. On a running node the caller is authorized against the bootstrap
// admin trust before the CA key is touched. This handler is thin: the
// signing lives in the attester.
func (s *Server) Attest(ctx context.Context, req *cryptosv1.AttestRequest) (*cryptosv1.AttestResponse, error) {
	if s.cfg.Attester == nil {
		return nil, status.Error(codes.Unimplemented, "attestation not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Attest: nonce is required")
	}
	sig, pub, err := s.cfg.Attester.SignNonce(ctx, req.GetNonce())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Attest: %v", err)
	}
	return &cryptosv1.AttestResponse{Signature: sig, IdentityPubDer: pub}, nil
}
