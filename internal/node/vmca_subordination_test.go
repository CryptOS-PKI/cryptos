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

// Subordinating VMware's VMCA under a CryptOS CA (#109).
//
// vCenter's rules are strict and documented, and the cost of getting one wrong
// is discovering it during a production certificate-manager run: the import
// fails after vCenter has already begun replacing certificates. These tests
// encode the published requirements against the real signing path, so the
// answer to "will vCenter accept what we issue" comes from CI rather than from
// a maintenance window.
//
// Requirements, from vSphere 8.0 "Certificate Requirements for Different
// Solution Paths" (the vSphere 9.0 page is identical on the ECDSA point):
//
//   - RSA only. "vSphere deploys only RSA certificates for server
//     authentication and does not support generating ECDSA certificates."
//   - Key size 2048 to 8192 bits.
//   - x509 version 3.
//   - basicConstraints critical, CA:true, and certificate signing in keyUsage.
//   - CRL signing enabled.
//   - Extended key usage empty, or Server Authentication only.
//   - Not more than one DNS name.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// rsaSHA2 is the set vCenter accepts. A certificate's signature algorithm is a
// property of its *issuer's* key, so every certificate in the chain has to be
// RSA-signed -- an RSA sub-CA under an ECDSA root still presents an
// ecdsa-with-SHA384 signature on the intermediate and is refused.
var rsaSHA2 = map[x509.SignatureAlgorithm]bool{
	x509.SHA256WithRSA: true,
	x509.SHA384WithRSA: true,
	x509.SHA512WithRSA: true,
}

// newRSASignerFixture is newSignerFixture with an RSA CA key, which is what an
// RSA-rooted hierarchy means in practice.
func newRSASignerFixture(t *testing.T) *signerFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("GenerateKey RSA issuer: %v", err)
	}
	now := time.Now()
	der, _, err := ca.SelfSignRoot(ca.RootParams{
		Signer:    key,
		Subject:   pkix.Name{CommonName: "Example RSA Root CA"},
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

	return &signerFixture{issuerCert: cert, issuerKey: key}
}

// vmcaCSR is the request vCenter's certificate-manager emits: an RSA-3072 key,
// a single common name, and no SANs. Measured on vcenter-01, 2026-09-17.
func vmcaCSR(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("GenerateKey VMCA: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	return der
}

// TestVMCASubordination_UnderAnRSACA is the acceptance test for #109: an RSA
// CryptOS CA signs VMCA's own CSR into a subordinate CA certificate that meets
// every published vCenter requirement.
func TestVMCASubordination_UnderAnRSACA(t *testing.T) {
	f := newRSASignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIntermediate), &closed)
	s := NewCASigner(load, issuer, get)

	chainDER, chainPEM, err := s.SignSubordinate(
		context.Background(),
		vmcaCSR(t, "vsphere.esxi.example.org"),
		"sub-ca",
	)
	if err != nil {
		t.Fatalf("SignSubordinate: %v", err)
	}
	if chainPEM == "" {
		t.Fatal("no chain PEM returned; certificate-manager is given the chain, not just the leaf")
	}

	// The whole chain must be RSA-signed, not just the VMCA certificate.
	for i, der := range chainDER {
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			t.Fatalf("chain[%d]: %v", i, parseErr)
		}
		if !rsaSHA2[cert.SignatureAlgorithm] {
			t.Errorf("chain[%d] (%s) SignatureAlgorithm = %v, which vCenter rejects",
				i, cert.Subject.CommonName, cert.SignatureAlgorithm)
		}
	}

	vmca, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse the issued VMCA certificate: %v", err)
	}

	if vmca.Version != 3 {
		t.Errorf("Version = %d, want 3", vmca.Version)
	}
	if !vmca.BasicConstraintsValid || !vmca.IsCA {
		t.Error("basicConstraints must be present and CA:true for intermediate CA mode")
	}
	if vmca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("keyUsage is missing certificate signing")
	}
	if vmca.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("keyUsage is missing CRL signing, which vCenter requires enabled")
	}
	// "Extended Key Usage can be either empty or contain Server Authentication."
	for _, eku := range vmca.ExtKeyUsage {
		if eku != x509.ExtKeyUsageServerAuth {
			t.Errorf("ExtKeyUsage contains %v; vCenter allows only serverAuth or none", eku)
		}
	}
	// "Certificates with wildcards or with more than one DNS name are not supported."
	if len(vmca.DNSNames) > 1 {
		t.Errorf("DNSNames = %v, want at most one", vmca.DNSNames)
	}

	pub, ok := vmca.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("subject key is %T, want RSA", vmca.PublicKey)
	}
	if bits := pub.N.BitLen(); bits < 2048 || bits > 8192 {
		t.Errorf("subject key is %d bits, outside vCenter's 2048-8192 range", bits)
	}

	// It must also actually verify as a chain, not merely carry the right bits.
	roots := x509.NewCertPool()
	roots.AddCert(f.issuerCert)
	if _, err := vmca.Verify(x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	}); err != nil {
		t.Errorf("the issued chain does not verify: %v", err)
	}
}

// TestVMCASubordination_UnderAnECDSACARejected pins why the hierarchy has to be
// RSA end to end, so nobody later "simplifies" this by reusing the existing
// ECDSA root.
//
// The signing succeeds -- CryptOS is happy to certify an RSA subject key from
// an ECDSA CA -- and the result is still unusable, because the signature on it
// comes from the issuer's ECDSA key. That silent success is exactly the trap,
// and it is why this is asserted rather than assumed.
func TestVMCASubordination_UnderAnECDSACARejected(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIntermediate), &closed)
	s := NewCASigner(load, issuer, get)

	chainDER, _, err := s.SignSubordinate(
		context.Background(),
		vmcaCSR(t, "vsphere.esxi.example.org"),
		"sub-ca",
	)
	if err != nil {
		t.Fatalf("SignSubordinate: %v", err)
	}

	vmca, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rsaSHA2[vmca.SignatureAlgorithm] {
		t.Fatalf("an ECDSA CA produced %v; this test is no longer describing reality",
			vmca.SignatureAlgorithm)
	}
	if vmca.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("SignatureAlgorithm = %v, want ecdsa-with-SHA384 from an ECDSA P-384 issuer",
			vmca.SignatureAlgorithm)
	}
}
