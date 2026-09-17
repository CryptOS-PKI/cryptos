package e2e

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

// Revocation half of the RSA CA path (#194). An RSA-rooted chain is only usable
// by a relying party that rejects the ECDSA family if the revocation material
// it fetches is RSA-signed too: a chain it can verify plus a CRL it cannot is
// still a failed validation. rsa_chain_e2e_test.go covers the certificates;
// this file covers the CRL and the OCSP response.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/revocation"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// rsaSHA2SigAlgs is the set a relying party that accepts only SHA-2 RSA will
// verify. SHA-1 is deliberately absent.
var rsaSHA2SigAlgs = map[x509.SignatureAlgorithm]bool{
	x509.SHA256WithRSA: true,
	x509.SHA384WithRSA: true,
	x509.SHA512WithRSA: true,
}

// oidOCSPNoCheckE2E is id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1), stamped on a
// delegated responder certificate so a client does not try to check the
// responder's own revocation status.
var oidOCSPNoCheckE2E = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// newRevocationStore spins up an embedded etcd in a temp dir and returns a
// revocation store backed by it.
func newRevocationStore(t *testing.T) (*revocation.Store, context.Context) {
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
	return revocation.NewStore(cli), context.Background()
}

// rsaSubjectKey returns an RSA key usable as a certificate subject key.
// MinRSASubjectKeyBits is the floor ca.ValidateSubjectKey enforces.
func rsaSubjectKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, ca.MinRSASubjectKeyBits)
	if err != nil {
		t.Fatalf("GenerateKey subject: %v", err)
	}
	return key
}

// TestRSACARevocationIsRSASigned drives the real CRL builder and OCSP responder
// with an RSA CA key and asserts every signature they produce is SHA-2 RSA and
// verifies against the CA.
func TestRSACARevocationIsRSASigned(t *testing.T) {
	store, ctx := newRevocationStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	caKey := newRSACAKey(t, config.RootKeyRSA3072)
	caDER, _, err := ca.SelfSignRoot(ca.RootParams{
		Signer:    caKey,
		Subject:   pkix.Name{CommonName: "ACME RSA Issuing CA", Organization: []string{"ACME"}},
		NotBefore: now,
		NotAfter:  now.AddDate(10, 0, 0),
	})
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}

	// A leaf to revoke, issued by the RSA CA so the CRL has real material.
	leafDER, _, err := ca.Sign(ca.Profile{
		Subject:     pkix.Name{CommonName: "leaf.acme.example"},
		NotBefore:   now,
		NotAfter:    now.AddDate(0, 0, 90),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, rsaSubjectKey(t).Public(), caCert, caKey)
	if err != nil {
		t.Fatalf("Sign leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}
	serialHex := leafCert.SerialNumber.Text(16)

	if err := store.RecordIssued(ctx, revocation.IssuedRecord{
		SerialHex: serialHex,
		NotAfter:  leafCert.NotAfter,
	}); err != nil {
		t.Fatalf("RecordIssued: %v", err)
	}
	if _, err := store.Revoke(ctx, serialHex, ocsp.KeyCompromise, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	t.Run("CRL", func(t *testing.T) {
		crlDER, err := revocation.NewCRLBuilder(store, 168*time.Hour).Build(ctx, caCert, caKey, now.Add(time.Minute))
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		if !rsaSHA2SigAlgs[crl.SignatureAlgorithm] {
			t.Errorf("CRL SignatureAlgorithm = %v, want a SHA-2 RSA algorithm", crl.SignatureAlgorithm)
		}
		if err := crl.CheckSignatureFrom(caCert); err != nil {
			t.Errorf("CheckSignatureFrom: %v", err)
		}
		if len(crl.RevokedCertificateEntries) != 1 {
			t.Fatalf("entries = %d, want 1", len(crl.RevokedCertificateEntries))
		}
		if got := crl.RevokedCertificateEntries[0].SerialNumber.Text(16); got != serialHex {
			t.Errorf("revoked serial = %s, want %s", got, serialHex)
		}
	})

	t.Run("OCSP", func(t *testing.T) {
		// The responder key is supplied per Respond call, so an RSA CA can
		// delegate to an RSA responder. Whether the node's own responder
		// mints an RSA key is separate (issue #200).
		responderKey := rsaSubjectKey(t)
		responderDER, _, err := ca.Sign(ca.Profile{
			Subject:     pkix.Name{CommonName: "ACME RSA Issuing CA OCSP Responder"},
			NotBefore:   now,
			NotAfter:    now.AddDate(0, 0, 7),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			ExtraExtensions: []pkix.Extension{{
				Id:    oidOCSPNoCheckE2E,
				Value: []byte{0x05, 0x00},
			}},
		}, responderKey.Public(), caCert, caKey)
		if err != nil {
			t.Fatalf("Sign responder: %v", err)
		}
		responderCert, err := x509.ParseCertificate(responderDER)
		if err != nil {
			t.Fatalf("ParseCertificate responder: %v", err)
		}
		if !rsaSHA2SigAlgs[responderCert.SignatureAlgorithm] {
			t.Errorf("responder cert SignatureAlgorithm = %v, want a SHA-2 RSA algorithm", responderCert.SignatureAlgorithm)
		}

		reqDER, err := ocsp.CreateRequest(leafCert, caCert, nil)
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		var responderSigner crypto.Signer = responderKey
		respDER, err := revocation.NewOCSPResponder(store).Respond(
			ctx, reqDER, caCert, responderCert, responderSigner, now.Add(time.Minute))
		if err != nil {
			t.Fatalf("Respond: %v", err)
		}
		// ParseResponse verifies the response signature against the embedded
		// delegated responder certificate, so a signature an RSA-only client
		// could not verify fails here rather than silently passing.
		resp, err := ocsp.ParseResponse(respDER, caCert)
		if err != nil {
			t.Fatalf("ParseResponse: %v", err)
		}
		if !rsaSHA2SigAlgs[resp.SignatureAlgorithm] {
			t.Errorf("OCSP SignatureAlgorithm = %v, want a SHA-2 RSA algorithm", resp.SignatureAlgorithm)
		}
		if resp.Status != ocsp.Revoked {
			t.Errorf("Status = %d, want Revoked (%d)", resp.Status, ocsp.Revoked)
		}
	})
}
