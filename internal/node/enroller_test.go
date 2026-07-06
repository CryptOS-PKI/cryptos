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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
)

// parentFixture is an in-memory ECDSA-P384 parent CA (a self-signed root)
// used to sign subordinate leaves in the enroller tests, CGO-free.
type parentFixture struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newParentFixture(t *testing.T) *parentFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	der, _, err := ca.SelfSignRoot(ca.RootParams{
		Signer:    key,
		Subject:   pkix.Name{CommonName: "Test Parent Root CA"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &parentFixture{key: key, cert: cert, der: der}
}

// signSubCA signs a subordinate-CA certificate for subjectPub with the parent
// key and returns its DER.
func (p *parentFixture) signSubCA(t *testing.T, subjectPub crypto.PublicKey, cn string) []byte {
	t.Helper()
	now := time.Now()
	pathLen := 0
	der, _, err := ca.Sign(ca.Profile{
		Subject:   pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(12 * time.Hour),
		IsCA:      true,
		PathLen:   &pathLen,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, subjectPub, p.cert, p.key)
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	return der
}

// stageWithKey generates a fresh P-384 CA key, builds a CSR for it, and stages
// it on the store (moving the node to PhaseAwaitingCert). It returns the key so
// the test can have the parent sign the matching public key.
func stageWithKey(t *testing.T, s *Store, ctx context.Context) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "Child Issuing CA"},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if err := s.StageSubordinate(ctx, csrDER, []byte("blob"), []byte("pub")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	return key
}

// establishIdentity stages and commits a first subordinate identity so the node
// reaches PhaseIdentityEstablished, the precondition for a re-key.
func establishIdentity(t *testing.T, s *Store, ctx context.Context, parent *parentFixture) {
	t.Helper()
	key := stageWithKey(t, s, ctx)
	leafDER := parent.signSubCA(t, &key.PublicKey, "Child Issuing CA")
	if err := s.CommitSubordinateCert(ctx, [][]byte{leafDER, parent.der}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}
}

// stageRotationWithKey generates a fresh P-384 CA key, builds a CSR for it, and
// stages it in the rotation slot. It returns the key so the test can have the
// parent sign the matching public key.
func stageRotationWithKey(t *testing.T, s *Store, ctx context.Context) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "Child Issuing CA"},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if err := s.StageRotation(ctx, csrDER, []byte("new-blob"), []byte("new-pub")); err != nil {
		t.Fatalf("StageRotation: %v", err)
	}
	return key
}

func pemOf(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func sha256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func TestSubordinateEnrollerRequiresStore(t *testing.T) {
	if _, err := NewSubordinateEnroller(nil, &bootstrap.Trust{}); err == nil {
		t.Error("NewSubordinateEnroller(nil store) = nil error, want error")
	}
}

func TestSubordinateEnrollerRequiresParent(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := NewSubordinateEnroller(s, nil); err == nil {
		t.Error("NewSubordinateEnroller(nil parent) = nil error, want error")
	}
}

func TestSubordinateEnrollerCSRPhaseGuard(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	// Before staging (no-identity): FailedPrecondition.
	if _, err := e.CSR(ctx); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("CSR before staging code = %v, want FailedPrecondition", status.Code(err))
	}

	stageWithKey(t, s, ctx)
	got, err := e.CSR(ctx)
	if err != nil {
		t.Fatalf("CSR after staging: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("CSR after staging returned empty")
	}
}

func TestAcceptCertificateGoodChainCommits(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	key := stageWithKey(t, s, ctx)
	leafDER := parent.signSubCA(t, &key.PublicKey, "Child Issuing CA")
	chain := [][]byte{leafDER, parent.der}

	id, err := e.AcceptCertificate(ctx, chain)
	if err != nil {
		t.Fatalf("AcceptCertificate: %v", err)
	}
	if len(id.GetChainDer()) != 2 {
		t.Fatalf("Identity chain len = %d, want 2", len(id.GetChainDer()))
	}
	if phase, _ := s.Phase(ctx); phase != PhaseIdentityEstablished {
		t.Errorf("phase after accept = %q, want %q", phase, PhaseIdentityEstablished)
	}
}

func TestAcceptCertificateRejectsChainNotRootingToAnchor(t *testing.T) {
	s, ctx := newTestStore(t)
	pinned := newParentFixture(t) // the pinned anchor
	rogue := newParentFixture(t)  // an unrelated CA that actually signs the leaf
	trust, err := bootstrap.LoadTrust(pemOf(pinned.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	key := stageWithKey(t, s, ctx)
	// The leaf carries the node's staged key, but is signed by the rogue CA and
	// the offered chain roots to the rogue, not the pinned anchor.
	leafDER := rogue.signSubCA(t, &key.PublicKey, "Child Issuing CA")
	chain := [][]byte{leafDER, rogue.der}

	if _, err := e.AcceptCertificate(ctx, chain); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("AcceptCertificate(unrooted) code = %v, want FailedPrecondition", status.Code(err))
	}
	// Nothing committed: still awaiting.
	if phase, _ := s.Phase(ctx); phase != PhaseAwaitingCert {
		t.Errorf("phase after rejected accept = %q, want %q", phase, PhaseAwaitingCert)
	}
}

func TestAcceptCertificateRejectsWrongLeafKey(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	stageWithKey(t, s, ctx) // stages the node's real key
	// The parent signs a leaf for a DIFFERENT key than the node staged. The
	// chain roots to the pinned anchor, but the leaf key is wrong.
	otherKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leafDER := parent.signSubCA(t, &otherKey.PublicKey, "Child Issuing CA")
	chain := [][]byte{leafDER, parent.der}

	if _, err := e.AcceptCertificate(ctx, chain); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("AcceptCertificate(wrong key) code = %v, want FailedPrecondition", status.Code(err))
	}
	if phase, _ := s.Phase(ctx); phase != PhaseAwaitingCert {
		t.Errorf("phase after rejected accept = %q, want %q", phase, PhaseAwaitingCert)
	}
}

func TestAcceptCertificateFingerprintOnlyAnchor(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	// Pin by SHA-256 fingerprint only; the anchor cert must arrive in the chain.
	sum := sha256Hex(parent.der)
	trust, err := bootstrap.LoadTrust("", sum)
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	key := stageWithKey(t, s, ctx)
	leafDER := parent.signSubCA(t, &key.PublicKey, "Child Issuing CA")

	// Chain includes the anchor: accepted.
	if _, err := e.AcceptCertificate(ctx, [][]byte{leafDER, parent.der}); err != nil {
		t.Fatalf("AcceptCertificate(fingerprint anchor in chain): %v", err)
	}
}

func TestAcceptCertificateFingerprintAnchorMissing(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust("", sha256Hex(parent.der))
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	key := stageWithKey(t, s, ctx)
	leafDER := parent.signSubCA(t, &key.PublicKey, "Child Issuing CA")
	// Only the leaf is offered; the pinned anchor is not in the chain: rejected.
	if _, err := e.AcceptCertificate(ctx, [][]byte{leafDER}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("AcceptCertificate(anchor missing) code = %v, want FailedPrecondition", status.Code(err))
	}
	if phase, _ := s.Phase(ctx); phase != PhaseAwaitingCert {
		t.Errorf("phase after rejected accept = %q, want %q", phase, PhaseAwaitingCert)
	}
}

func TestAcceptRotationGoodChainSwaps(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	establishIdentity(t, s, ctx, parent)
	oldPriv, _, _, _ := s.RootKeyBlobs(ctx)

	newKey := stageRotationWithKey(t, s, ctx)
	newLeafDER := parent.signSubCA(t, &newKey.PublicKey, "Child Issuing CA rekeyed")
	chain := [][]byte{newLeafDER, parent.der}

	id, err := e.AcceptRotation(ctx, chain)
	if err != nil {
		t.Fatalf("AcceptRotation: %v", err)
	}
	if len(id.GetChainDer()) != 2 || string(id.GetChainDer()[0]) != string(newLeafDER) {
		t.Fatalf("identity after rotation = %v, want new leaf-first chain", id.GetChainDer())
	}

	// The CA key was swapped away from the original key.
	newPriv, _, ok, err := s.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs after rotation ok=%v err=%v", ok, err)
	}
	if string(newPriv) == string(oldPriv) {
		t.Error("CA key was not swapped after rotation")
	}
	if string(newPriv) != "new-blob" {
		t.Errorf("CA key after rotation = %q, want the staged rotation key %q", newPriv, "new-blob")
	}

	// The rotation slot was cleared, and the node stays established.
	if _, ok, _ := s.RotationCSR(ctx); ok {
		t.Error("rotation slot not cleared after AcceptRotation")
	}
	if phase, _ := s.Phase(ctx); phase != PhaseIdentityEstablished {
		t.Errorf("phase after rotation = %q, want %q", phase, PhaseIdentityEstablished)
	}
}

func TestAcceptRotationRejectsWrongAnchor(t *testing.T) {
	s, ctx := newTestStore(t)
	pinned := newParentFixture(t)
	rogue := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(pinned.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	establishIdentity(t, s, ctx, pinned)
	newKey := stageRotationWithKey(t, s, ctx)
	// The new leaf carries the staged rotation key but roots to the rogue CA.
	leafDER := rogue.signSubCA(t, &newKey.PublicKey, "Child rekeyed")
	chain := [][]byte{leafDER, rogue.der}

	if _, err := e.AcceptRotation(ctx, chain); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("AcceptRotation(unrooted) code = %v, want FailedPrecondition", status.Code(err))
	}
	// Nothing swapped: the rotation slot is intact and the original identity stands.
	if _, ok, _ := s.RotationCSR(ctx); !ok {
		t.Error("rotation slot cleared on a rejected rotation")
	}
	newPriv, _, _, _ := s.RootKeyBlobs(ctx)
	if string(newPriv) == "new-blob" {
		t.Error("CA key was swapped despite a rejected rotation")
	}
}

func TestAcceptRotationRejectsWrongLeafKey(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	establishIdentity(t, s, ctx, parent)
	stageRotationWithKey(t, s, ctx) // stages the intended new key
	// The parent signs a leaf for a DIFFERENT key than the staged rotation key.
	// The chain roots to the pinned anchor, but the leaf key is wrong.
	otherKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leafDER := parent.signSubCA(t, &otherKey.PublicKey, "Child rekeyed")
	chain := [][]byte{leafDER, parent.der}

	if _, err := e.AcceptRotation(ctx, chain); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("AcceptRotation(wrong key) code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, ok, _ := s.RotationCSR(ctx); !ok {
		t.Error("rotation slot cleared on a rejected rotation")
	}
}

func TestAcceptRotationNoStagedRotation(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	establishIdentity(t, s, ctx, parent)
	// No rotation staged: FailedPrecondition.
	if _, err := e.AcceptRotation(ctx, [][]byte{[]byte("x")}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("AcceptRotation(no rotation) code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestAcceptRotationEmptyChain(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	establishIdentity(t, s, ctx, parent)
	stageRotationWithKey(t, s, ctx)
	if _, err := e.AcceptRotation(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("AcceptRotation(nil) code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestAcceptCertificateEmptyChain(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	stageWithKey(t, s, ctx)
	if _, err := e.AcceptCertificate(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("AcceptCertificate(nil) code = %v, want InvalidArgument", status.Code(err))
	}
}
