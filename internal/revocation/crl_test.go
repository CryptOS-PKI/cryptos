package revocation

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
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
)

// selfSignedCA mints a self-signed P-384 CA certificate suitable for signing a
// CRL (KeyUsageCertSign | KeyUsageCRLSign) and returns the parsed certificate
// alongside its private key.
func selfSignedCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p := ca.Profile{
		Subject:   pkix.Name{CommonName: "CryptOS Test CA"},
		NotBefore: time.Unix(0, 0).UTC(),
		NotAfter:  time.Unix(1<<31, 0).UTC(),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _, err := ca.Sign(p, key.Public(), nil, key)
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

func TestBuildCRLListsRevokedNotExpired(t *testing.T) {
	s, ctx := newRevStore(t)
	issuer, key := selfSignedCA(t) // helper: reuse ca.Sign to mint a CA cert + P-384 key
	now := time.Unix(500, 0).UTC()
	// one live revoked, one expired revoked (must be pruned)
	_ = s.RecordIssued(ctx, IssuedRecord{SerialHex: "0a", NotAfter: now.Add(time.Hour)})
	_ = s.RecordIssued(ctx, IssuedRecord{SerialHex: "0b", NotAfter: now.Add(-time.Hour)})
	_, _ = s.Revoke(ctx, "0a", 1, now.Add(-time.Minute))
	_, _ = s.Revoke(ctx, "0b", 1, now.Add(-2*time.Hour))

	der, err := NewCRLBuilder(s, 168*time.Hour).Build(ctx, issuer, key, now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("entries=%d, want 1 (expired pruned)", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != "a" {
		t.Fatalf("wrong serial: %s", crl.RevokedCertificateEntries[0].SerialNumber.Text(16))
	}
	if !crl.NextUpdate.Equal(now.Add(168 * time.Hour)) {
		t.Fatalf("nextUpdate=%s", crl.NextUpdate)
	}
}
