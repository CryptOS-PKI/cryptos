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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
)

const renewCN = "Child Issuing CA"

// renewProfile is the subordinate-CA profile the renewal tests sign under. The
// knobs a test flips (subject, pathLen, IsCA, CDP) are set per call.
type renewProfile struct {
	cn      string
	pathLen *int
	notCA   bool
	cdp     []string
}

func intPtr(v int) *int { return &v }

// sign issues a subordinate certificate for subjectPub from the parent.
func (p *parentFixture) signRenewal(t *testing.T, subjectPub crypto.PublicKey, rp renewProfile) []byte {
	t.Helper()
	now := time.Now()
	ku := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if rp.notCA {
		ku = x509.KeyUsageDigitalSignature
	}
	der, _, err := ca.Sign(ca.Profile{
		Subject:               pkix.Name{CommonName: rp.cn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(12 * time.Hour),
		IsCA:                  !rp.notCA,
		PathLen:               rp.pathLen,
		KeyUsage:              ku,
		CRLDistributionPoints: rp.cdp,
	}, subjectPub, p.cert, p.key)
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	return der
}

// establishForRenewal commits a first subordinate identity (pathLen 0, no CDP)
// and returns the CA key and the committed leaf DER.
func establishForRenewal(t *testing.T, s *Store, ctx context.Context, parent *parentFixture) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: renewCN},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if err := s.StageSubordinate(ctx, csrDER, []byte("blob"), []byte("pub")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	leafDER := parent.signRenewal(t, &key.PublicKey, renewProfile{cn: renewCN, pathLen: intPtr(0)})
	if err := s.CommitSubordinateCert(ctx, [][]byte{leafDER, parent.der}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}
	return key, leafDER
}

func newRenewEnroller(t *testing.T, s *Store, parent *parentFixture) *SubordinateEnroller {
	t.Helper()
	trust, err := bootstrap.LoadTrust(pemOf(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	e, err := NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	return e
}

func TestAcceptRenewalSwapsCertificateKeepsKey(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	e := newRenewEnroller(t, s, parent)
	key, oldLeaf := establishForRenewal(t, s, ctx, parent)
	oldPriv, oldPub, _, _ := s.RootKeyBlobs(ctx)

	newLeaf := parent.signRenewal(t, &key.PublicKey, renewProfile{
		cn: renewCN, pathLen: intPtr(0), cdp: []string{"http://pki.example.test/crl"},
	})
	id, err := e.AcceptRenewal(ctx, [][]byte{newLeaf, parent.der})
	if err != nil {
		t.Fatalf("AcceptRenewal: %v", err)
	}
	if len(id.GetChainDer()) != 2 || string(id.GetChainDer()[0]) != string(newLeaf) {
		t.Fatal("identity after renewal is not the renewed leaf-first chain")
	}

	// The served chain and the mirrored CA certificate are the renewed ones.
	served, err := s.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if string(served.GetChainDer()[0]) != string(newLeaf) {
		t.Error("Identity does not serve the renewed certificate")
	}
	kv, ok, err := s.getKV(ctx, "/cryptos/identity/root/cert")
	if err != nil || !ok || string(kv.Value) != string(newLeaf) {
		t.Error("KeyRootCert was not updated to the renewed certificate")
	}

	// The CA key is untouched.
	priv, pub, _, _ := s.RootKeyBlobs(ctx)
	if string(priv) != string(oldPriv) || string(pub) != string(oldPub) {
		t.Error("renewal changed the CA key blobs")
	}

	// The previous certificate is retained.
	hist, err := s.CertificateHistory(ctx)
	if err != nil {
		t.Fatalf("CertificateHistory: %v", err)
	}
	if len(hist) != 1 || string(hist[0]) != string(oldLeaf) {
		t.Fatalf("history = %d entries, want exactly the previous certificate", len(hist))
	}
	if phase, _ := s.Phase(ctx); phase != PhaseIdentityEstablished {
		t.Errorf("phase after renewal = %q, want %q", phase, PhaseIdentityEstablished)
	}
}

func TestAcceptRenewalIdempotentForCurrentCertificate(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	e := newRenewEnroller(t, s, parent)
	_, leaf := establishForRenewal(t, s, ctx, parent)

	if _, err := e.AcceptRenewal(ctx, [][]byte{leaf, parent.der}); err != nil {
		t.Fatalf("AcceptRenewal(current cert): %v", err)
	}
	hist, _ := s.CertificateHistory(ctx)
	if len(hist) != 0 {
		t.Errorf("history = %d entries after a no-op renewal, want 0", len(hist))
	}
}

func TestAcceptRenewalRejects(t *testing.T) {
	type tc struct {
		name  string
		chain func(t *testing.T, parent *parentFixture, key *ecdsa.PrivateKey) [][]byte
	}
	cases := []tc{
		{"different key", func(t *testing.T, p *parentFixture, _ *ecdsa.PrivateKey) [][]byte {
			other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			return [][]byte{p.signRenewal(t, &other.PublicKey, renewProfile{cn: renewCN, pathLen: intPtr(0)}), p.der}
		}},
		{"different subject", func(t *testing.T, p *parentFixture, k *ecdsa.PrivateKey) [][]byte {
			return [][]byte{p.signRenewal(t, &k.PublicKey, renewProfile{cn: "Someone Else CA", pathLen: intPtr(0)}), p.der}
		}},
		{"not rooted at the pinned anchor", func(t *testing.T, _ *parentFixture, k *ecdsa.PrivateKey) [][]byte {
			rogue := newParentFixture(t)
			return [][]byte{rogue.signRenewal(t, &k.PublicKey, renewProfile{cn: renewCN, pathLen: intPtr(0)}), rogue.der}
		}},
		{"not a CA certificate", func(t *testing.T, p *parentFixture, k *ecdsa.PrivateKey) [][]byte {
			return [][]byte{p.signRenewal(t, &k.PublicKey, renewProfile{cn: renewCN, notCA: true}), p.der}
		}},
		{"wider path length", func(t *testing.T, p *parentFixture, k *ecdsa.PrivateKey) [][]byte {
			return [][]byte{p.signRenewal(t, &k.PublicKey, renewProfile{cn: renewCN, pathLen: intPtr(1)}), p.der}
		}},
		{"unconstrained path length", func(t *testing.T, p *parentFixture, k *ecdsa.PrivateKey) [][]byte {
			return [][]byte{p.signRenewal(t, &k.PublicKey, renewProfile{cn: renewCN}), p.der}
		}},
		{"garbage", func(*testing.T, *parentFixture, *ecdsa.PrivateKey) [][]byte {
			return [][]byte{[]byte("not a certificate")}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, ctx := newTestStore(t)
			parent := newParentFixture(t)
			e := newRenewEnroller(t, s, parent)
			key, leaf := establishForRenewal(t, s, ctx, parent)

			_, err := e.AcceptRenewal(ctx, c.chain(t, parent, key))
			if err == nil {
				t.Fatal("AcceptRenewal accepted a chain it must reject")
			}
			if code := status.Code(err); code != codes.FailedPrecondition && code != codes.InvalidArgument {
				t.Errorf("code = %v, want FailedPrecondition or InvalidArgument", code)
			}
			id, _ := s.Identity(ctx)
			if string(id.GetChainDer()[0]) != string(leaf) {
				t.Error("a rejected renewal changed the served certificate")
			}
			if hist, _ := s.CertificateHistory(ctx); len(hist) != 0 {
				t.Error("a rejected renewal wrote history")
			}
		})
	}
}

func TestAcceptRenewalAllowsNarrowerPathLength(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	e := newRenewEnroller(t, s, parent)

	// Establish with pathLen 1 so a renewal at pathLen 0 is narrower.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: renewCN}}, key)
	if err := s.StageSubordinate(ctx, csrDER, []byte("blob"), []byte("pub")); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	first := parent.signRenewal(t, &key.PublicKey, renewProfile{cn: renewCN, pathLen: intPtr(1)})
	if err := s.CommitSubordinateCert(ctx, [][]byte{first, parent.der}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}

	narrower := parent.signRenewal(t, &key.PublicKey, renewProfile{cn: renewCN, pathLen: intPtr(0)})
	if _, err := e.AcceptRenewal(ctx, [][]byte{narrower, parent.der}); err != nil {
		t.Fatalf("AcceptRenewal(narrower pathLen): %v", err)
	}
}

func TestAcceptRenewalRequiresEstablishedIdentity(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	e := newRenewEnroller(t, s, parent)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leaf := parent.signRenewal(t, &key.PublicKey, renewProfile{cn: renewCN, pathLen: intPtr(0)})

	if _, err := e.AcceptRenewal(ctx, [][]byte{leaf, parent.der}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("AcceptRenewal on a node with no identity: code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := e.AcceptRenewal(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("AcceptRenewal(empty chain): code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestCommitRenewalGuardsOnCurrentCertificate(t *testing.T) {
	s, ctx := newTestStore(t)
	parent := newParentFixture(t)
	key, leaf := establishForRenewal(t, s, ctx, parent)
	renewed := parent.signRenewal(t, &key.PublicKey, renewProfile{cn: renewCN, pathLen: intPtr(0)})

	// A stale expected certificate (the CA certificate changed underneath) does
	// not apply.
	err := s.CommitRenewal(ctx, []byte("stale"), [][]byte{renewed, parent.der})
	if !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("CommitRenewal(stale) err = %v, want ErrIdentityChanged", err)
	}
	if err := s.CommitRenewal(ctx, leaf, [][]byte{renewed, parent.der}); err != nil {
		t.Fatalf("CommitRenewal: %v", err)
	}
	if err := s.CommitRenewal(ctx, leaf, nil); err == nil {
		t.Error("CommitRenewal(empty chain) = nil, want error")
	}
}
