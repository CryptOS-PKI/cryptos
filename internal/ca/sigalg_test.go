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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

// rsaKey returns a fresh RSA key of the requested size. rsa.PrivateKey
// satisfies crypto.Signer, so it doubles as the issuer signer.
func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("GenerateKey RSA %d: %v", bits, err)
	}
	return key
}

// TestSelfSignRootRSAIssuer covers a Root whose own key is RSA. Platform CAs
// such as VMware VMCA accept only RSA signatures, and a certificate's
// signature algorithm comes from the issuer's key, so an RSA-signed chain
// requires an RSA Root: an RSA subordinate under an ECDSA Root still presents
// an ECDSA signature on the subordinate itself.
func TestSelfSignRootRSAIssuer(t *testing.T) {
	key := rsaKey(t, 3072)
	now := time.Now().UTC().Truncate(time.Second)
	der, _, err := SelfSignRoot(RootParams{
		Signer:    key,
		Subject:   pkix.Name{CommonName: "ACME RSA Root CA"},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.SignatureAlgorithm != x509.SHA384WithRSA {
		t.Errorf("SignatureAlgorithm = %v, want %v", cert.SignatureAlgorithm, x509.SHA384WithRSA)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("CheckSignatureFrom: %v", err)
	}
}

// TestSignRSAIssuerProducesRSASignature signs a subordinate CA with an RSA
// issuer key. The issued certificate must carry an RSA signature so a platform
// CA that rejects ECDSA signatures can verify its own chain.
func TestSignRSAIssuerProducesRSASignature(t *testing.T) {
	issuerKey := rsaKey(t, 3072)
	now := time.Now().UTC().Truncate(time.Second)
	issuerDER, _, err := SelfSignRoot(RootParams{
		Signer:    issuerKey,
		Subject:   pkix.Name{CommonName: "ACME RSA Root CA"},
		NotBefore: now,
		NotAfter:  now.Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("ParseCertificate issuer: %v", err)
	}

	subject := rsaKey(t, 3072)
	pathLen := 0
	p := Profile{
		Subject:   pkix.Name{CommonName: "ACME Subordinate CA"},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		IsCA:      true,
		PathLen:   &pathLen,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _, err := Sign(p, &subject.PublicKey, issuer, issuerKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.SignatureAlgorithm != x509.SHA384WithRSA {
		t.Errorf("SignatureAlgorithm = %v, want %v", cert.SignatureAlgorithm, x509.SHA384WithRSA)
	}
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		t.Errorf("CheckSignatureFrom: %v", err)
	}
}

// TestSignatureAlgorithmFor pins the issuer-key rules: which keys may sign at
// all, and which digest each is paired with. The RSA digest steps up at
// RSASHA384MinBits so a larger modulus is not capped at SHA-256.
func TestSignatureAlgorithmFor(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P-256: %v", err)
	}
	tests := []struct {
		name    string
		pub     crypto.PublicKey
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{name: "ecdsa p384", pub: &p384Key(t).PublicKey, want: x509.ECDSAWithSHA384},
		{name: "rsa 2048", pub: &rsaKey(t, 2048).PublicKey, want: x509.SHA256WithRSA},
		{name: "rsa 3072", pub: &rsaKey(t, 3072).PublicKey, want: x509.SHA384WithRSA},
		{name: "ecdsa p256 rejected", pub: &p256.PublicKey, wantErr: true},
		{name: "rsa 1024 below minimum", pub: &rsaKey(t, 1024).PublicKey, wantErr: true},
		{name: "unsupported type", pub: "not a key", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SignatureAlgorithmFor(tc.pub)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("SignatureAlgorithmFor(%s): want error, got %v", tc.name, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SignatureAlgorithmFor(%s): unexpected error: %v", tc.name, err)
			}
			if got != tc.want {
				t.Errorf("SignatureAlgorithmFor(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
