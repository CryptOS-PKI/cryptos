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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

// renewStore is the slice of node.Store the renewer reads.
type renewStore interface {
	Identity(ctx context.Context) (*cryptosv1.Identity, error)
}

// renewalAccepter verifies a parent-signed re-certification of the current key
// and swaps the CA certificate, satisfied by
// *node.SubordinateEnroller.AcceptRenewal.
type renewalAccepter interface {
	AcceptRenewal(ctx context.Context, chainDER [][]byte) (*cryptosv1.Identity, error)
}

// nodeRenewer implements grpc.Renewer: same-key re-certification of an
// established subordinate. RenewalCSR signs a PKCS#10 request with the node's
// CURRENT CA key, loaded through the same KeyLoader the CA signer uses, and
// copies the subject byte for byte from the current CA certificate rather than
// rebuilding it from config, so the renewed certificate's subject (and with it
// the issuer name in every certificate already issued) cannot drift. Nothing is
// staged. AcceptRenewal delegates to the enroller, which owns the trust
// decision and the atomic swap. It is built only on a subordinate; a Root
// leaves the Renewer nil at wiring time, so the RPCs return Unimplemented there.
type nodeRenewer struct {
	store    renewStore
	load     node.KeyLoader
	accepter renewalAccepter
}

var _ cgrpc.Renewer = (*nodeRenewer)(nil)

// newRenewer builds a nodeRenewer. All dependencies are required.
func newRenewer(store renewStore, load node.KeyLoader, accepter renewalAccepter) (*nodeRenewer, error) {
	switch {
	case store == nil:
		return nil, errors.New("init: newRenewer: nil store")
	case load == nil:
		return nil, errors.New("init: newRenewer: nil key loader")
	case accepter == nil:
		return nil, errors.New("init: newRenewer: nil accepter")
	}
	return &nodeRenewer{store: store, load: load, accepter: accepter}, nil
}

// NewRenewer is the exported constructor production wiring and the
// cross-package end-to-end tests use: a renewer over store, reloading the CA key
// through load, with enr owning the trust decision on submit.
func NewRenewer(store *node.Store, load node.KeyLoader, enr *node.SubordinateEnroller) (cgrpc.Renewer, error) {
	if store == nil || enr == nil {
		return nil, errors.New("init: NewRenewer: nil store or enroller")
	}
	return newRenewer(store, load, enr)
}

// RenewalCSR returns a DER CSR for the node's current CA key with the current CA
// certificate's subject. It fails closed with FailedPrecondition when the node
// has no identity, or when the loaded key is not the key in the current
// certificate (a renewal must never be requested for a key the certificate does
// not carry).
func (r *nodeRenewer) RenewalCSR(ctx context.Context) ([]byte, error) {
	id, err := r.store.Identity(ctx)
	if err != nil {
		if errors.Is(err, node.ErrNoIdentity) {
			return nil, status.Error(codes.FailedPrecondition,
				"init: re-certification requires an established identity")
		}
		return nil, status.Errorf(codes.Internal, "init: read identity: %v", err)
	}
	if len(id.GetChainDer()) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "init: identity has no certificate chain")
	}
	cur, err := x509.ParseCertificate(id.GetChainDer()[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: parse current CA certificate: %v", err)
	}

	signer, closeFn, err := r.load(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: load CA key: %v", err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	gotPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: marshal CA public key: %v", err)
	}
	wantPub, err := x509.MarshalPKIXPublicKey(cur.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: marshal certificate public key: %v", err)
	}
	if !bytes.Equal(gotPub, wantPub) {
		return nil, status.Error(codes.FailedPrecondition,
			"init: the loaded CA key is not the key in the current CA certificate")
	}

	sigAlg, err := ca.SignatureAlgorithmFor(signer.Public())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject:         cur.RawSubject,
		SignatureAlgorithm: sigAlg,
	}, signer)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: build renewal CSR: %v", err)
	}
	return csrDER, nil
}

// AcceptRenewal verifies the parent-signed chain for the current key and swaps
// the CA certificate. The trust decision and the atomic swap live in the
// accepter (the subordinate enroller); this method only delegates.
func (r *nodeRenewer) AcceptRenewal(ctx context.Context, chainDER [][]byte) (*cryptosv1.Identity, error) {
	return r.accepter.AcceptRenewal(ctx, chainDER)
}
