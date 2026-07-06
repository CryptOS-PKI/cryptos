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
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// rekeyStore is the slice of node.Store the rekeyer uses. It keeps the rekeyer
// testable against a real embedded-etcd store while narrowing the surface.
type rekeyStore interface {
	HasIdentity(ctx context.Context) (bool, error)
	StageRotation(ctx context.Context, csrDER, keyBlob, keyPublic []byte) error
}

// rotationAccepter verifies a parent-signed re-key chain and swaps the node to
// it. It is the CompleteRotation half of the rekeyer, satisfied by
// *node.SubordinateEnroller.AcceptRotation.
type rotationAccepter interface {
	AcceptRotation(ctx context.Context, chainDER [][]byte) (*cryptosv1.Identity, error)
}

// nodeRekeyer implements grpc.Rekeyer for CA key rotation on an established
// subordinate. BeginRotation generates a new CA key through the same
// RootKeyBackend the ceremony provisions with, builds the subordinate CSR (same
// subject as first-boot enrollment), and stages it in the store's rotation
// slot; the node keeps serving with its current key. CompleteRotation delegates
// to the enroller's AcceptRotation, which owns the trust decision and the atomic
// swap. It is built only on an established subordinate; a Root is handled by
// leaving the Rekeyer nil at wiring time, so the RPC returns Unimplemented there.
type nodeRekeyer struct {
	store    rekeyStore
	backend  ceremony.RootKeyBackend
	cfg      *config.Config
	accepter rotationAccepter
}

var _ cgrpc.Rekeyer = (*nodeRekeyer)(nil)

// newRekeyer builds a nodeRekeyer. All dependencies are required: the backend
// generates the new CA key, the store stages it, the config supplies the CA
// subject, and the accepter (the subordinate enroller) verifies and swaps on
// completion.
func newRekeyer(store rekeyStore, backend ceremony.RootKeyBackend, cfg *config.Config, accepter rotationAccepter) (*nodeRekeyer, error) {
	switch {
	case store == nil:
		return nil, errors.New("init: newRekeyer: nil store")
	case backend == nil:
		return nil, errors.New("init: newRekeyer: nil backend")
	case cfg == nil:
		return nil, errors.New("init: newRekeyer: nil config")
	case accepter == nil:
		return nil, errors.New("init: newRekeyer: nil accepter")
	}
	return &nodeRekeyer{store: store, backend: backend, cfg: cfg, accepter: accepter}, nil
}

// BeginRotation generates a new CA key and stages its CSR in the rotation slot,
// returning the CSR DER to ferry to the parent. It fails closed: an established
// identity is required (StageRotation is guarded to that state and returns
// node.ErrNoIdentity otherwise, which surfaces as FailedPrecondition). The
// current key is untouched; the node keeps serving until CompleteRotation swaps.
func (r *nodeRekeyer) BeginRotation(ctx context.Context) ([]byte, error) {
	hasIdentity, err := r.store.HasIdentity(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: check identity: %v", err)
	}
	if !hasIdentity {
		return nil, status.Error(codes.FailedPrecondition,
			"init: key rotation requires an established identity")
	}

	if err := r.backend.ProvisionSRK(); err != nil {
		return nil, status.Errorf(codes.Internal, "init: provision SRK: %v", err)
	}
	created, err := r.backend.CreateKey(tpm.AlgorithmECDSAP384)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: create rotation key: %v", err)
	}
	signer, err := r.backend.LoadKey(created.Private, created.Public)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: load rotation key: %v", err)
	}
	defer func() { _ = signer.Close() }()

	csrDER, err := buildSubordinateCSR(signer, subordinateSubject(r.cfg))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "init: build rotation CSR: %v", err)
	}
	if err := r.store.StageRotation(ctx, csrDER, created.Private, created.Public); err != nil {
		if errors.Is(err, node.ErrNoIdentity) {
			return nil, status.Error(codes.FailedPrecondition,
				"init: key rotation requires an established identity")
		}
		return nil, status.Errorf(codes.Internal, "init: stage rotation: %v", err)
	}
	return csrDER, nil
}

// CompleteRotation verifies the parent-signed chain for the staged rotation key
// and swaps the node's identity to it. The trust decision and the atomic swap
// live in the accepter (the subordinate enroller); this method only delegates.
func (r *nodeRekeyer) CompleteRotation(ctx context.Context, chainDER [][]byte) (*cryptosv1.Identity, error) {
	return r.accepter.AcceptRotation(ctx, chainDER)
}
