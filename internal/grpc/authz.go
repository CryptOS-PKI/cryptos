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
	"crypto/sha256"
	"crypto/x509"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
)

// AuthorizeAdmin authorizes a caller against the bootstrap admin trust for
// the administrative RPCs (the signing handlers and the first-boot
// ceremony share this single source of truth).
//
// A connection with no TLS peer info is the local UNIX socket
// (/run/cryptos.sock, root-only, no auth) and is trusted; it returns nil.
// A TLS connection must present a client certificate whose DER SHA-256
// matches the pinned bootstrap admin fingerprint. A TLS peer with no leaf
// certificate is codes.Unauthenticated; a mismatching leaf is
// codes.PermissionDenied. This mirrors ceremony.authorizeCaller, which
// additionally returns the presented cert so the ceremony can promote it.
func AuthorizeAdmin(ctx context.Context, trust *bootstrap.Trust) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		// Non-TLS transport (local UNIX socket): trusted.
		return nil
	}
	var leaf *x509.Certificate
	if vc := tlsInfo.State.VerifiedChains; len(vc) > 0 && len(vc[0]) > 0 {
		leaf = vc[0][0]
	} else if pc := tlsInfo.State.PeerCertificates; len(pc) > 0 {
		leaf = pc[0]
	}
	if leaf == nil {
		return status.Error(codes.Unauthenticated, "grpc: no client certificate presented")
	}
	if sha256.Sum256(leaf.Raw) != trust.Fingerprint() {
		return status.Error(codes.PermissionDenied, "grpc: client certificate is not the authorized bootstrap admin")
	}
	return nil
}
