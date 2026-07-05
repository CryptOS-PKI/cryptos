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
