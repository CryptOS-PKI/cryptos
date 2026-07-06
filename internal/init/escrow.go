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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/backup"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

// escrowPayload is the plaintext sealed inside an escrow envelope. The key
// blobs use the same encoding as node.Store.RootKeyBlobs (a software CA key:
// KeyBlob is the marshaled EC private key, KeyPublic is the PKIX public key);
// ChainDER is the identity chain leaf-first; CACN is the leaf CA common name,
// recorded for a human-readable sanity check on restore.
type escrowPayload struct {
	KeyBlob   []byte   `json:"key_blob"`
	KeyPublic []byte   `json:"key_public"`
	ChainDER  [][]byte `json:"chain_der"`
	CACN      string   `json:"ca_cn"`
}

// escrowStore is the slice of node.Store the escrow uses. It keeps the escrow
// testable against a real embedded-etcd store while narrowing the surface.
type escrowStore interface {
	RootKeyBlobs(ctx context.Context) (private, public []byte, ok bool, err error)
	Identity(ctx context.Context) (*cryptosv1.Identity, error)
	HasIdentity(ctx context.Context) (bool, error)
	CommitRestoredIdentity(ctx context.Context, keyBlob, keyPublic []byte, chainDER [][]byte) error
}

// caEscrow implements grpc.Exporter and grpc.Importer for operator-held CA key
// escrow. exportable reflects whether the CA key is software-backed and thus
// portable: it is true for the nodeID/KMS state-key modes (softRootBackend) and
// false for the TPM mode, where the key is sealed and non-exportable by design.
type caEscrow struct {
	store      escrowStore
	exportable bool
}

// newCAEscrow builds a caEscrow over the store. exportable must be derived from
// the state-key mode (true for nodeid/kms, false for tpm).
func newCAEscrow(store escrowStore, exportable bool) *caEscrow {
	return &caEscrow{store: store, exportable: exportable}
}

var (
	_ cgrpc.Exporter = (*caEscrow)(nil)
	_ cgrpc.Importer = (*caEscrow)(nil)
)

// ExportCAKey seals this node's software CA key blobs and identity chain under
// passphrase and returns the encrypted envelope. It refuses on a TPM node
// (cgrpc.ErrNotExportable) because a TPM-sealed key is non-portable. The
// plaintext key is marshaled and sealed here and never leaves the node.
func (e *caEscrow) ExportCAKey(ctx context.Context, passphrase []byte) ([]byte, error) {
	if !e.exportable {
		return nil, cgrpc.ErrNotExportable
	}
	priv, pub, ok, err := e.store.RootKeyBlobs(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: read CA key blobs: %w", err)
	}
	if !ok {
		return nil, errors.New("init: no CA key material to export (node has no identity)")
	}
	id, err := e.store.Identity(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: read identity: %w", err)
	}
	if len(id.GetChainDer()) == 0 {
		return nil, errors.New("init: identity has no certificate chain")
	}
	payload := escrowPayload{
		KeyBlob:   priv,
		KeyPublic: pub,
		ChainDER:  id.GetChainDer(),
		CACN:      leafCommonName(id.GetChainDer()[0]),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("init: marshal escrow payload: %w", err)
	}
	envelope, err := backup.Seal(passphrase, raw)
	if err != nil {
		return nil, fmt.Errorf("init: seal escrow envelope: %w", err)
	}
	return envelope, nil
}

// ImportCAKey opens the envelope with passphrase, validates that the payload's
// leaf certificate carries the payload's public key, and atomically restores the
// CA identity onto a node that has none. It returns backup.ErrBadPassphrase
// (from Open) unchanged so the handler can map it, and cgrpc.ErrIdentityExists
// when the node already has an identity (translated from node.ErrIdentityExists
// so the grpc package need not import internal/node).
func (e *caEscrow) ImportCAKey(ctx context.Context, envelope, passphrase []byte) (*cryptosv1.Identity, error) {
	raw, err := backup.Open(passphrase, envelope)
	if err != nil {
		// Includes backup.ErrBadPassphrase; pass through for the handler to map.
		return nil, err
	}
	var payload escrowPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("init: decode escrow payload: %w", err)
	}
	switch {
	case len(payload.KeyBlob) == 0:
		return nil, errors.New("init: escrow payload has no CA key blob")
	case len(payload.KeyPublic) == 0:
		return nil, errors.New("init: escrow payload has no CA public key")
	case len(payload.ChainDER) == 0:
		return nil, errors.New("init: escrow payload has no certificate chain")
	}

	// Refuse a restore onto a node that already has an identity, before touching
	// state. The commit below is guarded too, so this is defense in depth.
	has, err := e.store.HasIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: check identity: %w", err)
	}
	if has {
		return nil, cgrpc.ErrIdentityExists
	}

	// Validate that the restored leaf certificate carries the restored key: the
	// leaf's SubjectPublicKeyInfo (PKIX DER) must equal the payload public key
	// (the same PKIX encoding node.RootKeyBlobs stores for a software key). This
	// rejects a payload whose key and chain do not belong together.
	leaf, err := x509.ParseCertificate(payload.ChainDER[0])
	if err != nil {
		return nil, fmt.Errorf("init: parse restored leaf certificate: %w", err)
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, payload.KeyPublic) {
		return nil, errors.New("init: escrow payload key does not match the certificate chain leaf")
	}

	if err := e.store.CommitRestoredIdentity(ctx, payload.KeyBlob, payload.KeyPublic, payload.ChainDER); err != nil {
		if errors.Is(err, node.ErrIdentityExists) {
			return nil, cgrpc.ErrIdentityExists
		}
		return nil, fmt.Errorf("init: commit restored identity: %w", err)
	}
	return e.store.Identity(ctx)
}

// leafCommonName returns the leaf certificate's subject common name, or an
// empty string when the certificate cannot be parsed (the CN is a
// human-readable convenience recorded in the payload, not a trust input).
func leafCommonName(der []byte) string {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}
