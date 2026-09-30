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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

type nopAccepter struct{}

func (nopAccepter) AcceptRenewal(context.Context, [][]byte) (*cryptosv1.Identity, error) {
	return &cryptosv1.Identity{}, nil
}

// establishRenewable commits a subordinate identity and returns its CA key and
// certificate. The parent sets the certificate subject itself, so it differs
// from the first-boot CSR subject: the renewal CSR must follow the certificate.
func establishRenewable(t *testing.T, s *node.Store, ctx context.Context, parent *rekeyParent) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Child Issuing CA", Organization: []string{"CryptOS"}, Country: []string{"US"}},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	blob, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if err := s.StageSubordinate(ctx, csrDER, blob, pub); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	leafDER := parent.signCSR(t, csrDER, "Child Issuing CA")
	if err := s.CommitSubordinateCert(ctx, [][]byte{leafDER, parent.der}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return key, leaf
}

func staticLoader(signer crypto.Signer) node.KeyLoader {
	return func(context.Context) (crypto.Signer, func(), error) { return signer, func() {}, nil }
}

func TestRenewalCSRUsesCurrentKeyAndSubject(t *testing.T) {
	s, ctx := newRekeyStore(t)
	parent := newRekeyParent(t)
	key, leaf := establishRenewable(t, s, ctx, parent)

	r, err := newRenewer(s, staticLoader(key), nopAccepter{})
	if err != nil {
		t.Fatalf("newRenewer: %v", err)
	}
	csrDER, err := r.RenewalCSR(ctx)
	if err != nil {
		t.Fatalf("RenewalCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("renewal CSR signature: %v", err)
	}
	if !bytes.Equal(csr.RawSubject, leaf.RawSubject) {
		t.Errorf("CSR subject %q, want the current CA subject %q byte for byte", csr.Subject, leaf.Subject)
	}
	gotPub, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	wantPub, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if !bytes.Equal(gotPub, wantPub) {
		t.Error("renewal CSR does not carry the current CA key")
	}

	// Nothing was staged: no rotation slot, no subordinate phase change.
	if _, ok, _ := s.RotationCSR(ctx); ok {
		t.Error("RenewalCSR staged a rotation")
	}
	if phase, _ := s.Phase(ctx); phase != node.PhaseIdentityEstablished {
		t.Errorf("phase after RenewalCSR = %q, want %q", phase, node.PhaseIdentityEstablished)
	}
}

func TestRenewalCSRRequiresIdentity(t *testing.T) {
	s, ctx := newRekeyStore(t)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	r, err := newRenewer(s, staticLoader(key), nopAccepter{})
	if err != nil {
		t.Fatalf("newRenewer: %v", err)
	}
	if _, err := r.RenewalCSR(ctx); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("RenewalCSR with no identity: code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestRenewalCSRRefusesKeyCertificateMismatch(t *testing.T) {
	s, ctx := newRekeyStore(t)
	parent := newRekeyParent(t)
	establishRenewable(t, s, ctx, parent)

	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	r, err := newRenewer(s, staticLoader(other), nopAccepter{})
	if err != nil {
		t.Fatalf("newRenewer: %v", err)
	}
	if _, err := r.RenewalCSR(ctx); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("RenewalCSR with a key that is not the certificate's: code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestNewRenewerRequiresDependencies(t *testing.T) {
	s, _ := newRekeyStore(t)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := newRenewer(nil, staticLoader(key), nopAccepter{}); err == nil {
		t.Error("newRenewer(nil store) = nil error")
	}
	if _, err := newRenewer(s, nil, nopAccepter{}); err == nil {
		t.Error("newRenewer(nil loader) = nil error")
	}
	if _, err := newRenewer(s, staticLoader(key), nil); err == nil {
		t.Error("newRenewer(nil accepter) = nil error")
	}
}
