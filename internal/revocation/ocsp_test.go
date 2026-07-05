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

	"golang.org/x/crypto/ocsp"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
)

// issueLeaf mints a leaf certificate signed by issuer and returns its serial in
// the base-16 form the store keys on (big.Int.Text(16)) alongside the parsed
// certificate.
func issueLeaf(t *testing.T, issuer *x509.Certificate, issuerKey crypto.Signer) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p := ca.Profile{
		Subject:     pkix.Name{CommonName: "leaf.acme.example"},
		NotBefore:   time.Unix(0, 0).UTC(),
		NotAfter:    time.Unix(1<<31, 0).UTC(),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _, err := ca.Sign(p, key.Public(), issuer, issuerKey)
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert.SerialNumber.Text(16), cert
}

func TestOCSPGoodRevokedUnknown(t *testing.T) {
	s, ctx := newRevStore(t)
	issuer, key := selfSignedCA(t)
	goodSerial, goodCert := issueLeaf(t, issuer, key)
	revSerial, revCert := issueLeaf(t, issuer, key)
	_ = s.RecordIssued(ctx, IssuedRecord{SerialHex: goodSerial, NotAfter: goodCert.NotAfter})
	_ = s.RecordIssued(ctx, IssuedRecord{SerialHex: revSerial, NotAfter: revCert.NotAfter})
	_, _ = s.Revoke(ctx, revSerial, ocsp.KeyCompromise, time.Now())

	resp := NewOCSPResponder(s)
	for _, tc := range []struct {
		cert *x509.Certificate
		want int
	}{
		{goodCert, ocsp.Good}, {revCert, ocsp.Revoked},
	} {
		reqDER, _ := ocsp.CreateRequest(tc.cert, issuer, nil)
		respDER, err := resp.Respond(ctx, reqDER, issuer, key, time.Now())
		if err != nil {
			t.Fatalf("Respond: %v", err)
		}
		parsed, err := ocsp.ParseResponse(respDER, issuer)
		if err != nil {
			t.Fatalf("ParseResponse: %v", err)
		}
		if parsed.Status != tc.want {
			t.Fatalf("status=%d want %d", parsed.Status, tc.want)
		}
	}
	// unknown serial: a leaf not recorded in the store
	_, unknownCert := issueLeaf(t, issuer, key)
	reqDER, _ := ocsp.CreateRequest(unknownCert, issuer, nil)
	respDER, _ := resp.Respond(ctx, reqDER, issuer, key, time.Now())
	parsed, _ := ocsp.ParseResponse(respDER, issuer)
	if parsed.Status != ocsp.Unknown {
		t.Fatalf("unknown serial status=%d want %d", parsed.Status, ocsp.Unknown)
	}
}
