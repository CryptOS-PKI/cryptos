package init

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
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"fmt"

	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

// nodeAttester implements grpc.Attester for the FM enrollment
// challenge-response (Attest RPC): it signs a manager-supplied nonce with
// this node's CA identity key, reloading the key per request through the
// same node.KeyLoader the signing and revocation handlers use. The key is
// never held after boot; the loaded signer is always closed once signing
// completes.
type nodeAttester struct {
	load node.KeyLoader
}

var _ cgrpc.Attester = (*nodeAttester)(nil)

// newAttester builds a nodeAttester over load. load is required.
func newAttester(load node.KeyLoader) (*nodeAttester, error) {
	if load == nil {
		return nil, fmt.Errorf("init: newAttester: nil key loader")
	}
	return &nodeAttester{load: load}, nil
}

// SignNonce signs nonce with this node's CA identity key (SHA-384 digest via a
// generic crypto.Signer.Sign call — the concrete scheme follows the key type,
// ECDSA in Phase 2) and returns the ASN.1 DER signature
// alongside the identity's PKIX/DER-encoded public key, so the Fleet Manager
// can verify the signature against the public key it pinned during
// enrollment.
func (a *nodeAttester) SignNonce(ctx context.Context, nonce []byte) (signature, identityPubDER []byte, err error) {
	signer, closeFn, err := a.load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("init: load CA key: %w", err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	if signer == nil {
		return nil, nil, fmt.Errorf("init: CA key loader returned a nil signer")
	}

	digest := sha512.Sum384(nonce)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	if err != nil {
		return nil, nil, fmt.Errorf("init: sign nonce: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("init: marshal identity public key: %w", err)
	}
	return sig, pub, nil
}
