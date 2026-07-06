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
	"crypto/sha256"
	"errors"
	"testing"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func TestStageSubordinateAndCSR(t *testing.T) {
	s, ctx := newTestStore(t)

	csr := []byte("csr-der")
	blob := []byte("sub-priv-blob")
	pub := []byte("sub-pub-blob")

	if err := s.StageSubordinate(ctx, csr, blob, pub); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}

	phase, err := s.Phase(ctx)
	if err != nil {
		t.Fatalf("Phase: %v", err)
	}
	if phase != PhaseAwaitingCert {
		t.Errorf("phase after StageSubordinate = %q, want %q", phase, PhaseAwaitingCert)
	}
	if phase.IdentityState() != cryptosv1.IdentityState_IDENTITY_STATE_AWAITING_CERT {
		t.Errorf("IdentityState = %v, want AWAITING_CERT", phase.IdentityState())
	}

	gotCSR, ok, err := s.SubordinateCSR(ctx)
	if err != nil || !ok {
		t.Fatalf("SubordinateCSR ok=%v err=%v", ok, err)
	}
	if string(gotCSR) != string(csr) {
		t.Errorf("SubordinateCSR = %q, want %q", gotCSR, csr)
	}

	gotPriv, gotPub, ok, err := s.SubordinateKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("SubordinateKeyBlobs ok=%v err=%v", ok, err)
	}
	if string(gotPriv) != string(blob) || string(gotPub) != string(pub) {
		t.Errorf("SubordinateKeyBlobs = (%q,%q), want (%q,%q)", gotPriv, gotPub, blob, pub)
	}

	// No identity is established yet while awaiting the signed chain.
	if _, err := s.Identity(ctx); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("Identity while AwaitingCert = %v, want ErrNoIdentity", err)
	}
}

func TestSubordinateCSRAbsent(t *testing.T) {
	s, ctx := newTestStore(t)
	if _, ok, err := s.SubordinateCSR(ctx); err != nil || ok {
		t.Fatalf("SubordinateCSR on fresh store ok=%v err=%v, want ok=false", ok, err)
	}
}

func TestStageSubordinateValidation(t *testing.T) {
	s, ctx := newTestStore(t)
	if err := s.StageSubordinate(ctx, nil, []byte("b"), []byte("p")); err == nil {
		t.Error("StageSubordinate with empty CSR = nil, want error")
	}
	if err := s.StageSubordinate(ctx, []byte("c"), nil, []byte("p")); err == nil {
		t.Error("StageSubordinate with empty keyBlob = nil, want error")
	}
	if err := s.StageSubordinate(ctx, []byte("c"), []byte("b"), nil); err == nil {
		t.Error("StageSubordinate with empty keyPublic = nil, want error")
	}
}

func TestCommitSubordinateCertLifecycle(t *testing.T) {
	s, ctx := newTestStore(t)

	if err := s.StageSubordinate(ctx, []byte("csr"), []byte("blob"), []byte("pub")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}

	leaf := []byte("leaf-cert-der")
	parent := []byte("parent-cert-der")
	chain := [][]byte{leaf, parent}

	if err := s.CommitSubordinateCert(ctx, chain); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}

	phase, _ := s.Phase(ctx)
	if phase != PhaseIdentityEstablished {
		t.Errorf("phase after commit = %q, want %q", phase, PhaseIdentityEstablished)
	}
	if ok, _ := s.HasIdentity(ctx); !ok {
		t.Error("HasIdentity = false after subordinate commit")
	}

	id, err := s.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity after commit: %v", err)
	}
	if len(id.ChainDer) != 2 {
		t.Fatalf("Identity.ChainDer len = %d, want 2", len(id.ChainDer))
	}
	if string(id.ChainDer[0]) != string(leaf) || string(id.ChainDer[1]) != string(parent) {
		t.Errorf("Identity.ChainDer = %v, want leaf-first [leaf, parent]", id.ChainDer)
	}
	wantLeaf := sha256.Sum256(leaf)
	if string(id.LeafSha256) != string(wantLeaf[:]) {
		t.Error("Identity.LeafSha256 != sha256(leaf)")
	}

	// The staged CA key is promoted into the canonical CA-key location the
	// signer reads, so an established subordinate can issue. Without this the
	// node establishes identity but RootKeyBlobs is empty and issuance fails
	// with "no CA key material".
	priv, pub, ok, err := s.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs after subordinate commit: ok=%v err=%v", ok, err)
	}
	if string(priv) != "blob" || string(pub) != "pub" {
		t.Errorf("promoted CA key = (%q,%q), want the staged (%q,%q)", priv, pub, "blob", "pub")
	}
}

func TestCommitSubordinateCertWrongPhase(t *testing.T) {
	s, ctx := newTestStore(t)

	// From a fresh (no-identity) store, committing without staging fails.
	if err := s.CommitSubordinateCert(ctx, [][]byte{[]byte("leaf")}); !errors.Is(err, ErrNotAwaitingCert) {
		t.Fatalf("commit from no-identity = %v, want ErrNotAwaitingCert", err)
	}

	// After a successful commit the phase is Established; a re-commit does
	// not apply (guard is PhaseAwaitingCert only).
	if err := s.StageSubordinate(ctx, []byte("csr"), []byte("blob"), []byte("pub")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	if err := s.CommitSubordinateCert(ctx, [][]byte{[]byte("leaf"), []byte("parent")}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}
	if err := s.CommitSubordinateCert(ctx, [][]byte{[]byte("other")}); !errors.Is(err, ErrNotAwaitingCert) {
		t.Fatalf("re-commit from Established = %v, want ErrNotAwaitingCert", err)
	}
	// The first-committed chain is intact.
	id, _ := s.Identity(ctx)
	if string(id.ChainDer[0]) != "leaf" {
		t.Error("re-commit overwrote the committed leaf")
	}
}

func TestOCSPResponderRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)

	// Absent on a fresh store.
	if _, _, _, ok, err := s.OCSPResponder(ctx); err != nil || ok {
		t.Fatalf("OCSPResponder on fresh store ok=%v err=%v, want ok=false", ok, err)
	}

	cert := []byte("responder-cert-der")
	blob := []byte("responder-priv-blob")
	pub := []byte("responder-pub-blob")

	if err := s.PutOCSPResponder(ctx, cert, blob, pub); err != nil {
		t.Fatalf("PutOCSPResponder: %v", err)
	}

	gotCert, gotBlob, gotPub, ok, err := s.OCSPResponder(ctx)
	if err != nil || !ok {
		t.Fatalf("OCSPResponder ok=%v err=%v, want ok=true", ok, err)
	}
	if string(gotCert) != string(cert) || string(gotBlob) != string(blob) || string(gotPub) != string(pub) {
		t.Errorf("OCSPResponder = (%q,%q,%q), want (%q,%q,%q)", gotCert, gotBlob, gotPub, cert, blob, pub)
	}
}

func TestPutOCSPResponderValidation(t *testing.T) {
	s, ctx := newTestStore(t)
	if err := s.PutOCSPResponder(ctx, nil, []byte("b"), []byte("p")); err == nil {
		t.Error("PutOCSPResponder with empty cert = nil, want error")
	}
	if err := s.PutOCSPResponder(ctx, []byte("c"), nil, []byte("p")); err == nil {
		t.Error("PutOCSPResponder with empty keyBlob = nil, want error")
	}
	if err := s.PutOCSPResponder(ctx, []byte("c"), []byte("b"), nil); err == nil {
		t.Error("PutOCSPResponder with empty keyPublic = nil, want error")
	}
}

func TestCommitSubordinateCertValidation(t *testing.T) {
	s, ctx := newTestStore(t)
	if err := s.StageSubordinate(ctx, []byte("csr"), []byte("blob"), []byte("pub")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	if err := s.CommitSubordinateCert(ctx, nil); err == nil {
		t.Error("CommitSubordinateCert(nil) = nil, want error")
	}
	if err := s.CommitSubordinateCert(ctx, [][]byte{nil}); err == nil {
		t.Error("CommitSubordinateCert with empty cert = nil, want error")
	}
}

func TestStageRotationRequiresIdentity(t *testing.T) {
	s, ctx := newTestStore(t)

	// No identity yet: StageRotation is refused (the opposite guard of
	// StageSubordinate).
	if err := s.StageRotation(ctx, []byte("csr"), []byte("blob"), []byte("pub")); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("StageRotation on no-identity node = %v, want ErrNoIdentity", err)
	}
	if _, ok, err := s.RotationCSR(ctx); err != nil || ok {
		t.Fatalf("RotationCSR after refused stage ok=%v err=%v, want ok=false", ok, err)
	}

	// Establish an identity (subordinate commit), then StageRotation applies.
	if err := s.StageSubordinate(ctx, []byte("csr0"), []byte("blob0"), []byte("pub0")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	if err := s.CommitSubordinateCert(ctx, [][]byte{[]byte("leaf0"), []byte("parent0")}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}

	if err := s.StageRotation(ctx, []byte("csr1"), []byte("blob1"), []byte("pub1")); err != nil {
		t.Fatalf("StageRotation on established node: %v", err)
	}
	gotCSR, ok, err := s.RotationCSR(ctx)
	if err != nil || !ok {
		t.Fatalf("RotationCSR ok=%v err=%v", ok, err)
	}
	if string(gotCSR) != "csr1" {
		t.Errorf("RotationCSR = %q, want %q", gotCSR, "csr1")
	}
	gotPriv, gotPub, ok, err := s.RotationKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RotationKeyBlobs ok=%v err=%v", ok, err)
	}
	if string(gotPriv) != "blob1" || string(gotPub) != "pub1" {
		t.Errorf("RotationKeyBlobs = (%q,%q), want (%q,%q)", gotPriv, gotPub, "blob1", "pub1")
	}

	// Re-begin overwrites the rotation slot.
	if err := s.StageRotation(ctx, []byte("csr2"), []byte("blob2"), []byte("pub2")); err != nil {
		t.Fatalf("StageRotation re-begin: %v", err)
	}
	gotCSR, _, _ = s.RotationCSR(ctx)
	if string(gotCSR) != "csr2" {
		t.Errorf("RotationCSR after re-begin = %q, want %q", gotCSR, "csr2")
	}

	// The active identity is untouched while the rotation is only staged.
	id, err := s.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if string(id.ChainDer[0]) != "leaf0" {
		t.Errorf("active identity leaf = %q, want unchanged %q", id.ChainDer[0], "leaf0")
	}
}

func TestStageRotationValidation(t *testing.T) {
	s, ctx := newTestStore(t)
	if err := s.StageRotation(ctx, nil, []byte("b"), []byte("p")); err == nil {
		t.Error("StageRotation with empty CSR = nil, want error")
	}
	if err := s.StageRotation(ctx, []byte("c"), nil, []byte("p")); err == nil {
		t.Error("StageRotation with empty keyBlob = nil, want error")
	}
	if err := s.StageRotation(ctx, []byte("c"), []byte("b"), nil); err == nil {
		t.Error("StageRotation with empty keyPublic = nil, want error")
	}
}

func TestCommitRotationSwapsKeyAndIdentity(t *testing.T) {
	s, ctx := newTestStore(t)

	// Establish an identity with an original key.
	if err := s.StageSubordinate(ctx, []byte("csr0"), []byte("old-blob"), []byte("old-pub")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	if err := s.CommitSubordinateCert(ctx, [][]byte{[]byte("leaf0"), []byte("parent0")}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}

	// Stage a re-key with a new key.
	if err := s.StageRotation(ctx, []byte("csr1"), []byte("new-blob"), []byte("new-pub")); err != nil {
		t.Fatalf("StageRotation: %v", err)
	}

	newChain := [][]byte{[]byte("leaf1"), []byte("parent1")}
	if err := s.CommitRotation(ctx, newChain); err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}

	// The CA key was swapped to the new rotation key.
	priv, pub, ok, err := s.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs after rotation ok=%v err=%v", ok, err)
	}
	if string(priv) != "new-blob" || string(pub) != "new-pub" {
		t.Errorf("CA key after rotation = (%q,%q), want the new (%q,%q)", priv, pub, "new-blob", "new-pub")
	}

	// The identity was swapped to the new chain.
	id, err := s.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if len(id.ChainDer) != 2 || string(id.ChainDer[0]) != "leaf1" {
		t.Fatalf("identity chain = %v, want new leaf %q", id.ChainDer, "leaf1")
	}

	// The rotation slot was cleared.
	if _, ok, _ := s.RotationCSR(ctx); ok {
		t.Error("RotationCSR still present after commit; slot not cleared")
	}
	if _, _, ok, _ := s.RotationKeyBlobs(ctx); ok {
		t.Error("RotationKeyBlobs still present after commit; slot not cleared")
	}

	// The phase remains established throughout (no awaiting-cert dip).
	if phase, _ := s.Phase(ctx); phase != PhaseIdentityEstablished {
		t.Errorf("phase after rotation = %q, want %q", phase, PhaseIdentityEstablished)
	}
}

func TestCommitRotationNoStagedSlot(t *testing.T) {
	s, ctx := newTestStore(t)

	// Establish an identity but do not stage a rotation.
	if err := s.StageSubordinate(ctx, []byte("csr0"), []byte("old-blob"), []byte("old-pub")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	if err := s.CommitSubordinateCert(ctx, [][]byte{[]byte("leaf0"), []byte("parent0")}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}

	if err := s.CommitRotation(ctx, [][]byte{[]byte("leaf1")}); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("CommitRotation with no staged slot = %v, want ErrNoRotation", err)
	}
	// The active identity is untouched.
	id, _ := s.Identity(ctx)
	if string(id.ChainDer[0]) != "leaf0" {
		t.Error("CommitRotation without a slot mutated the active identity")
	}
}

func TestCommitRotationValidation(t *testing.T) {
	s, ctx := newTestStore(t)
	if err := s.CommitRotation(ctx, nil); err == nil {
		t.Error("CommitRotation(nil) = nil, want error")
	}
	if err := s.CommitRotation(ctx, [][]byte{nil}); err == nil {
		t.Error("CommitRotation with empty cert = nil, want error")
	}
}

func TestCommitRestoredIdentity(t *testing.T) {
	s, ctx := newTestStore(t)

	keyBlob := []byte("restored-priv-blob")
	keyPub := []byte("restored-pub-blob")
	leaf := []byte("restored-ca-cert-der")
	root := []byte("restored-root-der")
	chain := [][]byte{leaf, root}

	// From a no-identity state the restore commits.
	if err := s.CommitRestoredIdentity(ctx, keyBlob, keyPub, chain); err != nil {
		t.Fatalf("CommitRestoredIdentity: %v", err)
	}

	// The identity is populated from the committed chain.
	id, err := s.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if len(id.ChainDer) != 2 || string(id.ChainDer[0]) != string(leaf) {
		t.Fatalf("Identity chain = %d entries (leaf %q), want 2 with leaf %q", len(id.ChainDer), id.ChainDer[0], leaf)
	}
	wantLeaf := sha256.Sum256(leaf)
	if string(id.LeafSha256) != string(wantLeaf[:]) {
		t.Errorf("LeafSha256 mismatch")
	}

	// The CA key blobs are populated so the signer can load.
	gotPriv, gotPub, ok, err := s.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs ok=%v err=%v", ok, err)
	}
	if string(gotPriv) != string(keyBlob) || string(gotPub) != string(keyPub) {
		t.Errorf("RootKeyBlobs = (%q,%q), want (%q,%q)", gotPriv, gotPub, keyBlob, keyPub)
	}

	// The node reaches the established phase.
	phase, err := s.Phase(ctx)
	if err != nil {
		t.Fatalf("Phase: %v", err)
	}
	if phase != PhaseIdentityEstablished {
		t.Errorf("phase = %q, want %q", phase, PhaseIdentityEstablished)
	}

	// A second restore onto a node that now has an identity is refused.
	if err := s.CommitRestoredIdentity(ctx, keyBlob, keyPub, chain); !errors.Is(err, ErrIdentityExists) {
		t.Errorf("second CommitRestoredIdentity = %v, want ErrIdentityExists", err)
	}
}

func TestCommitRestoredIdentityValidation(t *testing.T) {
	s, ctx := newTestStore(t)
	chain := [][]byte{[]byte("leaf")}
	if err := s.CommitRestoredIdentity(ctx, nil, []byte("pub"), chain); err == nil {
		t.Error("empty keyBlob = nil, want error")
	}
	if err := s.CommitRestoredIdentity(ctx, []byte("blob"), nil, chain); err == nil {
		t.Error("empty keyPublic = nil, want error")
	}
	if err := s.CommitRestoredIdentity(ctx, []byte("blob"), []byte("pub"), nil); err == nil {
		t.Error("empty chain = nil, want error")
	}
	if err := s.CommitRestoredIdentity(ctx, []byte("blob"), []byte("pub"), [][]byte{nil}); err == nil {
		t.Error("empty chain entry = nil, want error")
	}
}
