package init

/*
Copyright The CryptOS Authors.

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/revocation"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// The caIssuers endpoint serves the node's own CA certificate exactly as it
// sits in the identity chain, and fails while the node has none.
func TestCACertFnServesIssuerDER(t *testing.T) {
	want := &x509.Certificate{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
	r := &nodeRevoker{issuer: func(context.Context) (*x509.Certificate, error) { return want, nil }}
	got, err := r.caCertFn()(context.Background())
	if err != nil {
		t.Fatalf("caCertFn: %v", err)
	}
	if !bytes.Equal(got, want.Raw) {
		t.Fatalf("caCertFn = %x, want %x", got, want.Raw)
	}

	r = &nodeRevoker{issuer: func(context.Context) (*x509.Certificate, error) { return nil, errors.New("no chain") }}
	if _, err := r.caCertFn()(context.Background()); err == nil {
		t.Fatal("caCertFn with no issuer certificate returned nil error")
	}
}

// issuedFixture is a revoker over a real embedded etcd store, with an
// issuing CA whose chain runs up to a root, and a leaf it issued recorded the
// way the signer records it.
type issuedFixture struct {
	revoker *nodeRevoker
	store   *revocation.Store
	chain   [][]byte
	leaf    *x509.Certificate
}

func newIssuedFixture(t *testing.T, leafNotAfter time.Time) issuedFixture {
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
	store := revocation.NewStore(cli)

	root, rootKey := testCert(t, "Example Root CA G1", nil, nil, true, time.Now().Add(24*time.Hour))
	issuing, issuingKey := testCert(t, "Example Issuing CA G1", root, rootKey, true, time.Now().Add(24*time.Hour))
	leaf, _ := testCert(t, "leaf.example.org", issuing, issuingKey, false, leafNotAfter)
	chain := [][]byte{issuing.Raw, root.Raw}

	if err := IssuedRecorder(store)(context.Background(), leaf.Raw, "server"); err != nil {
		t.Fatalf("record issued: %v", err)
	}
	r := &nodeRevoker{store: store, chain: func(context.Context) ([][]byte, error) { return chain, nil }}
	return issuedFixture{revoker: r, store: store, chain: chain, leaf: leaf}
}

func testCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

func TestGetIssuedCertificate_ReturnsTheIssuedDERAndChain(t *testing.T) {
	fx := newIssuedFixture(t, time.Now().Add(time.Hour))

	resp, err := fx.revoker.GetIssuedCertificate(context.Background(), fx.leaf.SerialNumber.Text(16))
	if err != nil {
		t.Fatalf("GetIssuedCertificate: %v", err)
	}
	if !bytes.Equal(resp.GetCertificateDer(), fx.leaf.Raw) {
		t.Error("certificate_der is not the DER that was issued")
	}
	if len(resp.GetChainDer()) != 2 || !bytes.Equal(resp.GetChainDer()[0], fx.chain[0]) || !bytes.Equal(resp.GetChainDer()[1], fx.chain[1]) {
		t.Error("chain_der is not the issuer-to-root chain")
	}
	if resp.GetStatus() != "valid" || resp.GetRevokedAt() != "" {
		t.Errorf("status = %q revoked_at = %q, want valid and empty", resp.GetStatus(), resp.GetRevokedAt())
	}
}

func TestGetIssuedCertificate_UnknownSerialIsNotIssued(t *testing.T) {
	fx := newIssuedFixture(t, time.Now().Add(time.Hour))

	_, err := fx.revoker.GetIssuedCertificate(context.Background(), "abcdef")
	if !errors.Is(err, revocation.ErrNotIssued) {
		t.Fatalf("err = %v, want revocation.ErrNotIssued", err)
	}
}

func TestGetIssuedCertificate_RevokedIsStillReturned(t *testing.T) {
	fx := newIssuedFixture(t, time.Now().Add(time.Hour))
	serial := fx.leaf.SerialNumber.Text(16)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if _, err := fx.store.Revoke(context.Background(), serial, 1, at); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	resp, err := fx.revoker.GetIssuedCertificate(context.Background(), serial)
	if err != nil {
		t.Fatalf("GetIssuedCertificate: %v", err)
	}
	if !bytes.Equal(resp.GetCertificateDer(), fx.leaf.Raw) {
		t.Error("a revoked certificate did not come back as issued")
	}
	if resp.GetStatus() != "revoked" || resp.GetRevokedAt() != "2026-03-04T05:06:07Z" {
		t.Errorf("status = %q revoked_at = %q, want revoked at 2026-03-04T05:06:07Z", resp.GetStatus(), resp.GetRevokedAt())
	}
}

func TestGetIssuedCertificate_PastNotAfterIsExpired(t *testing.T) {
	fx := newIssuedFixture(t, time.Now().Add(-time.Hour))

	resp, err := fx.revoker.GetIssuedCertificate(context.Background(), fx.leaf.SerialNumber.Text(16))
	if err != nil {
		t.Fatalf("GetIssuedCertificate: %v", err)
	}
	if resp.GetStatus() != "expired" || resp.GetRevokedAt() != "" {
		t.Errorf("status = %q revoked_at = %q, want expired and empty", resp.GetStatus(), resp.GetRevokedAt())
	}
}

// A record written before the certificate itself was kept has only its
// inventory fields.
func TestGetIssuedCertificate_RecordWithoutDER(t *testing.T) {
	fx := newIssuedFixture(t, time.Now().Add(time.Hour))
	if err := fx.store.RecordIssued(context.Background(), revocation.IssuedRecord{SerialHex: "0a", SubjectDN: "CN=old", NotAfter: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("RecordIssued: %v", err)
	}

	_, err := fx.revoker.GetIssuedCertificate(context.Background(), "0a")
	if !errors.Is(err, revocation.ErrCertificateNotStored) {
		t.Fatalf("err = %v, want revocation.ErrCertificateNotStored", err)
	}
}
