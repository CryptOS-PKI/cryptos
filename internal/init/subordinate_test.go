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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

// TestBuildSubordinateCSR checks that buildSubordinateCSR produces a
// PKCS#10 request that parses, carries the requested subject, is signed with
// ECDSAWithSHA384 over a P-384 key, and self-verifies.
func TestBuildSubordinateCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	subject := pkix.Name{
		CommonName:   "Issuing CA 1",
		Organization: []string{"CryptOS"},
		Country:      []string{"US"},
	}

	der, err := buildSubordinateCSR(key, subject)
	if err != nil {
		t.Fatalf("buildSubordinateCSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	if csr.Subject.CommonName != subject.CommonName {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, subject.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "CryptOS" {
		t.Errorf("Organization = %v, want [CryptOS]", csr.Subject.Organization)
	}
	if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "US" {
		t.Errorf("Country = %v, want [US]", csr.Subject.Country)
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSAWithSHA384", csr.SignatureAlgorithm)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *ecdsa.PublicKey", csr.PublicKey)
	}
	if pub.Curve != elliptic.P384() {
		t.Errorf("curve = %v, want P-384", pub.Curve)
	}
	if !pub.Equal(&key.PublicKey) {
		t.Error("CSR public key does not match the signing key")
	}
}

// TestBuildSubordinateCSRNilSigner rejects a nil signer.
func TestBuildSubordinateCSRNilSigner(t *testing.T) {
	if _, err := buildSubordinateCSR(nil, pkix.Name{CommonName: "x"}); err == nil {
		t.Fatal("expected an error for a nil signer")
	}
}
