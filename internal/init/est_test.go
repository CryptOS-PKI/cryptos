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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

// estTestCA is a throwaway issuing CA plus the loader and issuer closures the
// EST server-certificate manager expects.
type estTestCA struct {
	key    crypto.Signer
	cert   *x509.Certificate
	closed int
}

func newESTTestCA(t *testing.T) *estTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	return newESTTestCAWithKey(t, key)
}

// newESTTestCAWithKey is newESTTestCA over a CA key the caller chooses, so the
// RSA-CA cases can drive the same wiring.
func newESTTestCAWithKey(t *testing.T, key crypto.Signer) *estTestCA {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "EST Init Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	return &estTestCA{key: key, cert: cert}
}

func (c *estTestCA) loader() node.KeyLoader {
	return func(context.Context) (crypto.Signer, func(), error) {
		return c.key, func() { c.closed++ }, nil
	}
}

func (c *estTestCA) issuerFunc() node.IssuerFunc {
	return func(context.Context) (*x509.Certificate, error) { return c.cert, nil }
}

// TestESTServerCertIsIssuedByTheCA is the property that makes the listener
// verifiable: a client that trusts this CA must be able to verify the
// handshake without any extra trust anchor.
func TestESTServerCertIsIssuedByTheCA(t *testing.T) {
	ca := newESTTestCA(t)
	m := newESTServerCert(ca.loader(), ca.issuerFunc(), []string{"est.example.org", "10.0.0.10"}, config.RootKeyECDSAP384)
	m.logf = t.Logf

	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("the returned certificate has no parsed leaf")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("the listener certificate does not chain to the CA: %v", err)
	}
	// Hostnames become DNS SANs and IP literals become IP SANs, or a client
	// dialling by address cannot verify the name it used.
	if err := cert.Leaf.VerifyHostname("est.example.org"); err != nil {
		t.Fatalf("VerifyHostname: %v", err)
	}
	if len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.10")) {
		t.Fatalf("IP SANs = %v, want 10.0.0.10", cert.Leaf.IPAddresses)
	}
	// The issuer travels with the leaf so a client can build the chain.
	if len(cert.Certificate) != 2 {
		t.Fatalf("the presented chain has %d certificates, want the leaf and the issuer", len(cert.Certificate))
	}
	// The CA key must be released after minting, not held.
	if ca.closed != 1 {
		t.Fatalf("the CA key was released %d times, want 1", ca.closed)
	}
}

// A second handshake must reuse the certificate rather than loading the CA
// key again: the key is loaded per use precisely so it is not held, and
// re-minting on every connection would make that expensive and pointless.
func TestESTServerCertIsReused(t *testing.T) {
	ca := newESTTestCA(t)
	m := newESTServerCert(ca.loader(), ca.issuerFunc(), []string{"est.example.org"}, config.RootKeyECDSAP384)
	m.logf = t.Logf

	first, err := m.get(nil)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	second, err := m.get(nil)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if first != second {
		t.Fatal("a second handshake minted a new certificate")
	}
	if ca.closed != 1 {
		t.Fatalf("the CA key was loaded %d times, want 1", ca.closed)
	}
}

// Past the halfway point the certificate is replaced, so a serving node never
// presents one close to expiry.
func TestESTServerCertRenewsPastHalfLife(t *testing.T) {
	ca := newESTTestCA(t)
	m := newESTServerCert(ca.loader(), ca.issuerFunc(), []string{"est.example.org"}, config.RootKeyECDSAP384)
	m.logf = t.Logf
	m.validity = time.Hour

	first, err := m.get(nil)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	// Age the held certificate past its renewal window.
	aged := *first.Leaf
	aged.NotAfter = time.Now().Add(10 * time.Minute)
	m.cur = &tls.Certificate{Certificate: first.Certificate, PrivateKey: first.PrivateKey, Leaf: &aged}

	second, err := m.get(nil)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("an expiring certificate was served instead of being renewed")
	}
}

func TestESTTLSConfigAsksForAClientCert(t *testing.T) {
	ca := newESTTestCA(t)
	cfg := estTLSConfig(newESTServerCert(ca.loader(), ca.issuerFunc(), []string{"est.example.org"}, config.RootKeyECDSAP384))
	if cfg.ClientAuth != tls.RequestClientCert {
		t.Fatalf("ClientAuth = %v, want RequestClientCert so /cacerts stays reachable", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2 for the embedded clients EST serves", cfg.MinVersion)
	}
	if cfg.GetCertificate == nil {
		t.Fatal("the config has no certificate callback")
	}
}

func TestESTOptionsFromConfig(t *testing.T) {
	digest := sha256.Sum256([]byte("est-test-password-obviously-not-a-secret"))
	c := &config.EST{
		Hostnames:                 []string{"est.example.org"},
		Profile:                   "leaf-server",
		Label:                     "issuing",
		Realm:                     "acme corp est",
		AllowedIdentifierSuffixes: []string{"example.org"},
		EnrollCredentials: []config.ESTEnrollCredential{
			{Username: "switch-fleet", PasswordSHA256: hex.EncodeToString(digest[:])},
		},
	}
	opts, err := estOptions(c)
	if err != nil {
		t.Fatalf("estOptions: %v", err)
	}
	if opts.Label != "issuing" || opts.Realm != "acme corp est" {
		t.Fatalf("opts = %+v", opts)
	}
	if opts.EnrollAuth == nil {
		t.Fatal("credentials were configured but simpleenroll is disabled")
	}
	if !opts.EnrollAuth("switch-fleet", "est-test-password-obviously-not-a-secret") {
		t.Fatal("the configured credential was not accepted")
	}
	if opts.EnrollAuth("switch-fleet", "wrong") {
		t.Fatal("a wrong password was accepted")
	}
	if opts.EnrollAuth("nobody", "est-test-password-obviously-not-a-secret") {
		t.Fatal("an unknown user was accepted")
	}
}

// With no credentials configured, simpleenroll must stay closed rather than
// falling open.
func TestESTOptionsWithoutCredentialsDisablesEnroll(t *testing.T) {
	opts, err := estOptions(&config.EST{Hostnames: []string{"est.example.org"}, Profile: "leaf-server"})
	if err != nil {
		t.Fatalf("estOptions: %v", err)
	}
	if opts.EnrollAuth != nil {
		t.Fatal("simpleenroll is enabled with no credentials configured")
	}
}

// TestESTServerCertKeyFollowsAnRSACA: the EST listener's own key decides the
// handshake signature, so on an RSA CA an ECDSA listener key leaves an
// RSA-only client unable to complete the handshake even though it trusts the
// CA that signed the certificate (#200).
func TestESTServerCertKeyFollowsAnRSACA(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, nodeKeyRSABits)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	ca := newESTTestCAWithKey(t, caKey)
	m := newESTServerCert(ca.loader(), ca.issuerFunc(), []string{"est.example.org"}, config.RootKeyRSA3072)
	m.logf = t.Logf

	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("listener key type = %T, want *rsa.PrivateKey", cert.PrivateKey)
	}
	if bits := key.N.BitLen(); bits != nodeKeyRSABits {
		t.Errorf("listener key size = %d bits, want %d", bits, nodeKeyRSABits)
	}
	if !rsaSHA2SigAlgsInit[cert.Leaf.SignatureAlgorithm] {
		t.Errorf("listener cert SignatureAlgorithm = %v, want a SHA-2 RSA algorithm", cert.Leaf.SignatureAlgorithm)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("the listener certificate does not chain to the RSA CA: %v", err)
	}
}

// TestESTServerCertFollowsTheCAKeyOverTheConfig: the configured algorithm only
// decides what is pre-generated. If it has drifted from the key on disk the
// warm key is dropped, because the CA key is what the client's verification
// actually depends on.
func TestESTServerCertFollowsTheCAKeyOverTheConfig(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, nodeKeyRSABits)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	ca := newESTTestCAWithKey(t, caKey)
	m := newESTServerCert(ca.loader(), ca.issuerFunc(), []string{"est.example.org"}, config.RootKeyECDSAP384)
	m.logf = t.Logf

	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, ok := cert.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Errorf("listener key type = %T, want an RSA key to match the RSA CA", cert.PrivateKey)
	}
}

// TestESTServerCertKeepsECDSAForAnECDSACA pins the no-change half of #200.
func TestESTServerCertKeepsECDSAForAnECDSACA(t *testing.T) {
	ca := newESTTestCA(t)
	m := newESTServerCert(ca.loader(), ca.issuerFunc(), []string{"est.example.org"}, config.RootKeyECDSAP384)
	m.logf = t.Logf

	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("listener key type = %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
	if key.Curve != elliptic.P384() {
		t.Errorf("listener key curve = %v, want P-384", key.Curve.Params().Name)
	}
	if cert.Leaf.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("listener cert SignatureAlgorithm = %v, want ECDSAWithSHA384", cert.Leaf.SignatureAlgorithm)
	}
}
