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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// rekeyParent is an in-memory ECDSA-P384 parent CA used to sign both the
// first-boot subordinate leaf and the re-key leaf in the rekeyer tests.
type rekeyParent struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newRekeyParent(t *testing.T) *rekeyParent {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	der, _, err := ca.SelfSignRoot(ca.RootParams{
		Signer:    key,
		Subject:   pkix.Name{CommonName: "Rekey Parent Root CA"},
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
	return &rekeyParent{key: key, cert: cert, der: der}
}

// signCSR signs a subordinate-CA certificate for the CSR's public key.
func (p *rekeyParent) signCSR(t *testing.T, csrDER []byte, cn string) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	now := time.Now()
	pathLen := 0
	der, _, err := ca.Sign(ca.Profile{
		Subject:   pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(12 * time.Hour),
		IsCA:      true,
		PathLen:   &pathLen,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, csr.PublicKey, p.cert, p.key)
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	return der
}

// newRekeyStore spins up an embedded etcd and returns a node.Store plus context.
func newRekeyStore(t *testing.T) (*node.Store, context.Context) {
	t.Helper()
	srv, err := etcd.Open(t.TempDir())
	if err != nil {
		t.Fatalf("etcd.Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("etcd.Client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	s, err := node.New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return s, ctx
}

func rekeyConfig() *config.Config {
	c := &config.Config{}
	c.PKI.RootSubject.CommonName = "Child Issuing CA"
	c.PKI.RootSubject.Organization = "CryptOS"
	return c
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBeginRotationRequiresIdentity(t *testing.T) {
	s, ctx := newRekeyStore(t)
	parent := newRekeyParent(t)
	trust, err := bootstrap.LoadTrust(certPEM(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	enr, err := node.NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	r, err := newRekeyer(s, NewSoftRootBackend(), rekeyConfig(), enr)
	if err != nil {
		t.Fatalf("newRekeyer: %v", err)
	}

	// No identity yet: FailedPrecondition, and nothing staged.
	if _, err := r.BeginRotation(ctx); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("BeginRotation on no-identity node code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, ok, _ := s.RotationCSR(ctx); ok {
		t.Error("BeginRotation staged a rotation on a no-identity node")
	}
}

func TestNewRekeyerValidation(t *testing.T) {
	s, _ := newRekeyStore(t)
	parent := newRekeyParent(t)
	trust, _ := bootstrap.LoadTrust(certPEM(parent.der), "")
	enr, _ := node.NewSubordinateEnroller(s, trust)
	if _, err := newRekeyer(nil, NewSoftRootBackend(), rekeyConfig(), enr); err == nil {
		t.Error("newRekeyer(nil store) = nil, want error")
	}
	if _, err := newRekeyer(s, nil, rekeyConfig(), enr); err == nil {
		t.Error("newRekeyer(nil backend) = nil, want error")
	}
	if _, err := newRekeyer(s, NewSoftRootBackend(), nil, enr); err == nil {
		t.Error("newRekeyer(nil config) = nil, want error")
	}
	if _, err := newRekeyer(s, NewSoftRootBackend(), rekeyConfig(), nil); err == nil {
		t.Error("newRekeyer(nil accepter) = nil, want error")
	}
}

func TestRekeyerFullCycle(t *testing.T) {
	s, ctx := newRekeyStore(t)
	parent := newRekeyParent(t)
	backend := NewSoftRootBackend()
	trust, err := bootstrap.LoadTrust(certPEM(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	enr, err := node.NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}

	// Establish a first identity through the real first-boot staging path.
	if err := backend.ProvisionSRK(); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	created, err := backend.CreateKey(tpm.AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	signer, err := backend.LoadKey(created.Private, created.Public)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	firstCSR, err := buildSubordinateCSR(signer, subordinateSubject(rekeyConfig()))
	_ = signer.Close()
	if err != nil {
		t.Fatalf("buildSubordinateCSR: %v", err)
	}
	if err := s.StageSubordinate(ctx, firstCSR, created.Private, created.Public); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	firstLeaf := parent.signCSR(t, firstCSR, "Child Issuing CA")
	if _, err := enr.AcceptCertificate(ctx, [][]byte{firstLeaf, parent.der}); err != nil {
		t.Fatalf("AcceptCertificate: %v", err)
	}
	oldPriv, _, _, _ := s.RootKeyBlobs(ctx)

	// Re-key: begin, parent signs the new CSR, complete.
	r, err := newRekeyer(s, backend, rekeyConfig(), enr)
	if err != nil {
		t.Fatalf("newRekeyer: %v", err)
	}
	newCSR, err := r.BeginRotation(ctx)
	if err != nil {
		t.Fatalf("BeginRotation: %v", err)
	}
	if len(newCSR) == 0 {
		t.Fatal("BeginRotation returned an empty CSR")
	}

	// The active identity is still the original key while only staged.
	stillOld, _, _, _ := s.RootKeyBlobs(ctx)
	if string(stillOld) != string(oldPriv) {
		t.Error("CA key changed on BeginRotation; the swap must wait for CompleteRotation")
	}

	newLeaf := parent.signCSR(t, newCSR, "Child Issuing CA rekeyed")
	id, err := r.CompleteRotation(ctx, [][]byte{newLeaf, parent.der})
	if err != nil {
		t.Fatalf("CompleteRotation: %v", err)
	}
	if len(id.GetChainDer()) != 2 || string(id.GetChainDer()[0]) != string(newLeaf) {
		t.Fatalf("identity after rotation = %v, want new leaf-first chain", id.GetChainDer())
	}

	// The CA key was swapped away from the original, and the swapped key is the
	// one that signed the new leaf.
	newPriv, _, ok, err := s.RootKeyBlobs(ctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs after rotation ok=%v err=%v", ok, err)
	}
	if string(newPriv) == string(oldPriv) {
		t.Error("CA key was not swapped after CompleteRotation")
	}
	assertSwappedKeySignedLeaf(t, newPriv, newLeaf)
}

// assertSwappedKeySignedLeaf loads the swapped software CA key blob and checks
// its public key equals the new leaf certificate's public key, proving the node
// now holds the key it re-keyed to.
func assertSwappedKeySignedLeaf(t *testing.T, keyBlob, leafDER []byte) {
	t.Helper()
	priv, err := x509.ParseECPrivateKey(keyBlob)
	if err != nil {
		t.Fatalf("ParseECPrivateKey(swapped blob): %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate(new leaf): %v", err)
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf public key type = %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	if !priv.PublicKey.Equal(leafPub) {
		t.Error("swapped CA key public does not match the new leaf certificate")
	}
}
