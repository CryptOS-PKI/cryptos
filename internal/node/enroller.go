package node

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
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
)

// SubordinateEnroller exposes a subordinate node's pending CSR and accepts the
// parent-signed certificate chain that establishes its identity. It is the
// security core of the P3b ceremony: AcceptCertificate verifies the offered
// chain roots to the pinned parent trust anchor AND that the leaf public key is
// this node's own staged key before it commits. It is decoupled from the gRPC
// layer so it is testable with an in-memory ECDSA signer and imports no
// transport code.
//
// The pinned parent anchor comes from config pki.parent (a full CA certificate
// or a SHA-256 fingerprint). A nil enroller (the maintenance servers) means the
// RPCs are refused with Unimplemented at the transport layer; this type never
// stands in for that.
type SubordinateEnroller struct {
	store  *Store
	parent *bootstrap.Trust
}

// NewSubordinateEnroller constructs a SubordinateEnroller over store, pinned to
// the parent trust anchor. Both are required: store persists the ceremony and
// parent is the trust root the offered chain must verify to. A nil parent is
// rejected so a subordinate can never accept an unpinned chain.
func NewSubordinateEnroller(store *Store, parent *bootstrap.Trust) (*SubordinateEnroller, error) {
	if store == nil {
		return nil, errors.New("node: NewSubordinateEnroller: nil store")
	}
	if parent == nil {
		return nil, errors.New("node: NewSubordinateEnroller: nil parent trust anchor")
	}
	return &SubordinateEnroller{store: store, parent: parent}, nil
}

// CSR returns the DER-encoded CSR this subordinate staged on first boot. It is
// available only while the node is awaiting its certificate; before staging (or
// after the chain has committed) it returns FailedPrecondition so an operator
// cannot ferry a stale or absent CSR.
func (e *SubordinateEnroller) CSR(ctx context.Context) ([]byte, error) {
	phase, err := e.store.Phase(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "node: read phase: %v", err)
	}
	if phase != PhaseAwaitingCert {
		return nil, status.Errorf(codes.FailedPrecondition,
			"node: no subordinate CSR available in phase %q", phase)
	}
	csrDER, ok, err := e.store.SubordinateCSR(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "node: read subordinate CSR: %v", err)
	}
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "node: no subordinate CSR staged")
	}
	return csrDER, nil
}

// AcceptCertificate verifies a parent-signed certificate chain and, only if it
// is fully trustworthy, commits it as this node's identity. This is the trust
// boundary of the subordinate ceremony; it fails closed on any doubt:
//
//   - the node must be awaiting its certificate (a staged CSR must exist);
//   - chainDER is parsed leaf-first (chainDER[0] is this node's certificate);
//   - the leaf public key MUST equal the public key in the staged CSR, so a
//     chain minted for a different key can never be accepted;
//   - the leaf MUST cryptographically verify (x509 path build + signatures) to
//     the pinned parent trust anchor. When the anchor is a full certificate it
//     is the sole root; when only a SHA-256 fingerprint is pinned, a certificate
//     in the offered chain whose DER matches that fingerprint is the sole root
//     and every other non-leaf certificate is an intermediate.
//
// On success the chain is committed atomically (guarded to PhaseAwaitingCert)
// and the node's Identity becomes the full leaf-first chain. Verification
// failures return InvalidArgument/FailedPrecondition and never touch the store.
func (e *SubordinateEnroller) AcceptCertificate(ctx context.Context, chainDER [][]byte) (*cryptosv1.Identity, error) {
	if len(chainDER) == 0 {
		return nil, status.Error(codes.InvalidArgument, "node: certificate chain is empty")
	}

	// The node must be mid-ceremony with a staged CSR; the CSR is the record of
	// the key this chain must be bound to.
	csrDER, err := e.CSR(ctx)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "node: parse staged CSR: %v", err)
	}

	certs := make([]*x509.Certificate, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "node: parse chain[%d]: %v", i, err)
		}
		certs[i] = c
	}
	leaf := certs[0]

	// The leaf must carry this node's own staged key. Bind before path building
	// so a chain minted for a different key is rejected outright.
	if !samePublicKey(leaf.PublicKey, csr.PublicKey) {
		return nil, status.Error(codes.FailedPrecondition,
			"node: certificate public key does not match this node's staged key")
	}

	roots, intermediates, err := e.pools(certs)
	if err != nil {
		return nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// KeyUsages left as the default (ANY) so a subordinate CA leaf verifies;
		// the trust decision here is "does it chain to the pinned parent", not
		// server/client EKU.
	}); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"node: certificate chain does not verify to the pinned parent anchor: %v", err)
	}

	if err := e.store.CommitSubordinateCert(ctx, chainDER); err != nil {
		if errors.Is(err, ErrNotAwaitingCert) {
			return nil, status.Error(codes.FailedPrecondition, "node: node is not awaiting a certificate")
		}
		return nil, status.Errorf(codes.Internal, "node: commit chain: %v", err)
	}
	return e.store.Identity(ctx)
}

// AcceptRotation is the re-key sibling of AcceptCertificate: it verifies a
// parent-signed chain for the node's STAGED ROTATION key and, only if it is
// fully trustworthy, atomically swaps the node's identity to it. It fails closed
// on any doubt, reusing the same trust logic as AcceptCertificate but binding to
// the rotation key rather than the current identity key:
//
//   - a rotation must be staged (a rotation CSR must exist), else
//     FailedPrecondition;
//   - chainDER is parsed leaf-first (chainDER[0] is this node's new certificate);
//   - the leaf public key MUST equal the public key in the staged rotation CSR,
//     so a chain minted for any other key (including the node's current key) is
//     rejected;
//   - the leaf MUST cryptographically verify to the pinned parent trust anchor
//     via the same pools as AcceptCertificate.
//
// On success the swap is committed atomically (CommitRotation) and the node's
// Identity becomes the new leaf-first chain; the old key is discarded.
// Verification failures return InvalidArgument/FailedPrecondition and never
// touch the store.
func (e *SubordinateEnroller) AcceptRotation(ctx context.Context, chainDER [][]byte) (*cryptosv1.Identity, error) {
	if len(chainDER) == 0 {
		return nil, status.Error(codes.InvalidArgument, "node: certificate chain is empty")
	}

	// A rotation must be staged; its CSR records the new key this chain must be
	// bound to.
	csrDER, ok, err := e.store.RotationCSR(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "node: read staged rotation CSR: %v", err)
	}
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "node: no key rotation staged")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "node: parse staged rotation CSR: %v", err)
	}

	certs := make([]*x509.Certificate, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "node: parse chain[%d]: %v", i, err)
		}
		certs[i] = c
	}
	leaf := certs[0]

	// The leaf must carry the node's staged ROTATION key (not the current key).
	// Bind before path building so a chain minted for a different key is rejected
	// outright.
	if !samePublicKey(leaf.PublicKey, csr.PublicKey) {
		return nil, status.Error(codes.FailedPrecondition,
			"node: certificate public key does not match this node's staged rotation key")
	}

	roots, intermediates, err := e.pools(certs)
	if err != nil {
		return nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"node: certificate chain does not verify to the pinned parent anchor: %v", err)
	}

	if err := e.store.CommitRotation(ctx, chainDER); err != nil {
		if errors.Is(err, ErrNoRotation) {
			return nil, status.Error(codes.FailedPrecondition, "node: no key rotation staged")
		}
		return nil, status.Errorf(codes.Internal, "node: commit rotation: %v", err)
	}
	return e.store.Identity(ctx)
}

// pools builds the roots and intermediates x509 pools for verifying leaf
// against the pinned parent anchor. When the anchor is a full certificate it is
// the sole root and every non-leaf offered certificate is an intermediate. When
// only a fingerprint is pinned, the offered certificate whose DER SHA-256
// matches becomes the sole root and the other non-leaf certificates are
// intermediates. A fingerprint with no matching certificate in the chain is a
// hard failure (nothing to anchor to).
func (e *SubordinateEnroller) pools(certs []*x509.Certificate) (roots, intermediates *x509.CertPool, err error) {
	roots = x509.NewCertPool()
	intermediates = x509.NewCertPool()

	if e.parent.HasCertificate() {
		roots.AddCert(e.parent.Certificate())
		anchorDER := e.parent.Certificate().Raw
		for _, c := range certs[1:] {
			if !bytesEqual(c.Raw, anchorDER) {
				intermediates.AddCert(c)
			}
		}
		return roots, intermediates, nil
	}

	// Fingerprint-only anchor: find it inside the offered chain.
	want := e.parent.Fingerprint()
	var anchor *x509.Certificate
	for _, c := range certs[1:] {
		if sha256.Sum256(c.Raw) == want {
			anchor = c
			break
		}
	}
	if anchor == nil {
		return nil, nil, status.Error(codes.FailedPrecondition,
			"node: offered chain does not contain the pinned parent anchor")
	}
	roots.AddCert(anchor)
	for _, c := range certs[1:] {
		if c != anchor {
			intermediates.AddCert(c)
		}
	}
	return roots, intermediates, nil
}

// samePublicKey reports whether two public keys are byte-identical once
// marshaled to PKIX DER. Both keys come from parsed x509 material (the leaf
// certificate and the staged CSR), so a marshal failure means an unexpected key
// type and is treated as not-equal (fail closed).
func samePublicKey(a, b crypto.PublicKey) bool {
	da, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	db, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytesEqual(da, db)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
