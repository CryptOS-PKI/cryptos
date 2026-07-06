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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// ocspResponderFixture builds a soft self-signed CA (issuer + key) and a
// node.Store backed by an embedded etcd, then returns a responder manager wired
// to load that CA key per use, mirroring the CRL/OCSP loader pattern.
type ocspResponderFixture struct {
	store    *node.Store
	issuer   *x509.Certificate
	caKey    crypto.Signer
	validity time.Duration
}

func newOCSPResponderFixture(t *testing.T, validity time.Duration) (*ocspResponderFixture, *ocspResponder, context.Context) {
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
	store, err := node.New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p := ca.Profile{
		Subject:   pkix.Name{CommonName: "CryptOS Test CA"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _, err := ca.Sign(p, caKey.Public(), nil, caKey)
	if err != nil {
		t.Fatalf("ca.Sign issuer: %v", err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate issuer: %v", err)
	}

	f := &ocspResponderFixture{store: store, issuer: issuer, caKey: caKey, validity: validity}
	load := func(context.Context) (crypto.Signer, func(), error) { return f.caKey, func() {}, nil }
	issuerFn := func(context.Context) (*x509.Certificate, error) { return f.issuer, nil }
	mgr := newOCSPResponder(store, load, issuerFn, validity)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return f, mgr, ctx
}

func hasOCSPNoCheck(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidOCSPNoCheck) {
			return true
		}
	}
	return false
}

func TestOCSPResponderEnsureMints(t *testing.T) {
	f, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)

	cert, key, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if key == nil {
		t.Fatal("ensure returned a nil key")
	}

	// OCSPSigning EKU present.
	foundEKU := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			foundEKU = true
		}
	}
	if !foundEKU {
		t.Error("responder cert missing ExtKeyUsageOCSPSigning")
	}
	// digitalSignature KU.
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("responder cert missing KeyUsageDigitalSignature")
	}
	// id-pkix-ocsp-nocheck present.
	if !hasOCSPNoCheck(cert) {
		t.Error("responder cert missing id-pkix-ocsp-nocheck extension")
	}
	// Not a CA.
	if cert.IsCA {
		t.Error("responder cert is a CA, want end-entity")
	}
	// Chains to the issuer.
	roots := x509.NewCertPool()
	roots.AddCert(f.issuer)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}); err != nil {
		t.Errorf("responder cert does not chain to issuer: %v", err)
	}
	// Public key of the returned signer matches the cert.
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("responder cert public key type %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	keyPub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("returned key public type %T, want *ecdsa.PublicKey", key.Public())
	}
	if !certPub.Equal(keyPub) {
		t.Error("returned key does not match responder cert public key")
	}
}

func TestOCSPResponderEnsureReusesFresh(t *testing.T) {
	_, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)

	first, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	second, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Errorf("ensure re-minted a still-fresh responder: serials %s != %s", first.SerialNumber, second.SerialNumber)
	}
}

func TestOCSPResponderEnsureRenewsWithinWindow(t *testing.T) {
	f, mgr, ctx := newOCSPResponderFixture(t, 7*24*time.Hour)

	first, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	// Persist a stored responder whose remaining life is inside the renewal
	// window (less than half the validity), which forces a re-mint. Mint it
	// with a NotAfter close to now so remaining life < validity/2.
	staleKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey stale: %v", err)
	}
	now := time.Now()
	p := responderProfile(f.issuer, now, now.Add(time.Hour)) // ~1h left, well inside 3.5d window
	der, _, err := ca.Sign(p, staleKey.Public(), f.issuer, f.caKey)
	if err != nil {
		t.Fatalf("ca.Sign stale: %v", err)
	}
	blob, err := x509.MarshalECPrivateKey(staleKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(staleKey.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if err := f.store.PutOCSPResponder(ctx, der, blob, pub); err != nil {
		t.Fatalf("PutOCSPResponder stale: %v", err)
	}

	renewed, _, err := mgr.ensure(ctx)
	if err != nil {
		t.Fatalf("renew ensure: %v", err)
	}
	staleCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate stale: %v", err)
	}
	if renewed.SerialNumber.Cmp(staleCert.SerialNumber) == 0 {
		t.Error("ensure returned the stale responder instead of re-minting")
	}
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("ensure re-used the first responder instead of re-minting")
	}
}
