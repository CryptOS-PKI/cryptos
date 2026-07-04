package ca

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

// p384Key returns a fresh P-384 ecdsa key for use as a subject or issuer key.
// ecdsa.PrivateKey satisfies crypto.Signer, so it doubles as the issuer signer.
func p384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// selfSignedIssuer mints a self-signed CA certificate via Sign and returns the
// parsed certificate plus the signer that holds its key.
func selfSignedIssuer(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := p384Key(t)
	now := time.Now().UTC().Truncate(time.Second)
	p := Profile{
		Subject:   pkix.Name{CommonName: "Test Issuer"},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _, err := Sign(p, &key.PublicKey, nil, key)
	if err != nil {
		t.Fatalf("Sign issuer: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate issuer: %v", err)
	}
	return cert, key
}

func TestParseKeyUsage(t *testing.T) {
	ku, err := ParseKeyUsage([]string{"cert_sign", "crl_sign", "digital_signature", "key_encipherment", "key_agreement"})
	if err != nil {
		t.Fatalf("ParseKeyUsage: %v", err)
	}
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
	if ku != want {
		t.Fatalf("ParseKeyUsage = %b, want %b", ku, want)
	}
	if _, err := ParseKeyUsage([]string{"bogus"}); err == nil {
		t.Fatal("ParseKeyUsage(bogus): expected error, got nil")
	}

	eku, err := ParseExtKeyUsage([]string{"server_auth", "client_auth"})
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}
	if len(eku) != 2 || eku[0] != x509.ExtKeyUsageServerAuth || eku[1] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ParseExtKeyUsage = %v, want [ServerAuth ClientAuth]", eku)
	}
	if _, err := ParseExtKeyUsage([]string{"bogus"}); err == nil {
		t.Fatal("ParseExtKeyUsage(bogus): expected error, got nil")
	}
}

func TestSignCA(t *testing.T) {
	issuerCert, issuerSigner := selfSignedIssuer(t)
	childKey := p384Key(t)
	now := time.Now().UTC().Truncate(time.Second)
	pathLen := 0
	p := Profile{
		Subject:   pkix.Name{CommonName: "Sub CA"},
		NotBefore: now,
		NotAfter:  now.Add(12 * time.Hour),
		IsCA:      true,
		PathLen:   &pathLen,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, pemBytes, err := Sign(p, &childKey.PublicKey, issuerCert, issuerSigner)
	if err != nil {
		t.Fatalf("Sign CA: %v", err)
	}
	if len(pemBytes) == 0 {
		t.Fatal("Sign CA: empty PEM")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("MaxPathLen=%d MaxPathLenZero=%v, want 0/true", cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if cert.KeyUsage != (x509.KeyUsageCertSign | x509.KeyUsageCRLSign) {
		t.Errorf("KeyUsage=%b, want CertSign|CRLSign", cert.KeyUsage)
	}
	if err := cert.CheckSignatureFrom(issuerCert); err != nil {
		t.Errorf("CheckSignatureFrom: %v", err)
	}
}

func TestSignLeaf(t *testing.T) {
	issuerCert, issuerSigner := selfSignedIssuer(t)
	leafKey := p384Key(t)
	now := time.Now().UTC().Truncate(time.Second)
	p := Profile{
		Subject:     pkix.Name{CommonName: "node.example"},
		NotBefore:   now,
		NotAfter:    now.Add(6 * time.Hour),
		IsCA:        false,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"node.example"},
	}
	der, _, err := Sign(p, &leafKey.PublicKey, issuerCert, issuerSigner)
	if err != nil {
		t.Fatalf("Sign leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.IsCA {
		t.Error("expected IsCA=false")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage=%v, want [ServerAuth]", cert.ExtKeyUsage)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "node.example" {
		t.Errorf("DNSNames=%v, want [node.example]", cert.DNSNames)
	}
	if err := cert.CheckSignatureFrom(issuerCert); err != nil {
		t.Errorf("CheckSignatureFrom: %v", err)
	}
}
