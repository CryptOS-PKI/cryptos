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

// This file proves the RSA CA path end to end with the real code: the
// configured key algorithm reaches the software key backend, the root
// self-signs with an RSA key, an intermediate is signed beneath it, and a leaf
// is issued from the intermediate. Every signature in the resulting chain must
// be SHA-2 RSA, because a platform CA that rejects the ECDSA family cannot
// verify a chain containing even one ECDSA-signed certificate.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	cinit "github.com/CryptOS-PKI/cryptos/internal/init"
)

// newRSACAKey generates a CA key through the real software backend, driven by
// the config vocabulary rather than by calling crypto/rsa directly, so the
// config-to-key-algorithm mapping is part of what is under test.
func newRSACAKey(t *testing.T, alg config.RootKeyAlg) crypto.Signer {
	t.Helper()
	keyAlg, err := alg.KeyAlgorithm()
	if err != nil {
		t.Fatalf("KeyAlgorithm(%s): %v", alg, err)
	}
	backend := cinit.NewSoftRootBackend()
	created, err := backend.CreateKey(keyAlg)
	if err != nil {
		t.Fatalf("CreateKey(%s): %v", alg, err)
	}
	signer, err := backend.LoadKey(created.Private, created.Public)
	if err != nil {
		t.Fatalf("LoadKey(%s): %v", alg, err)
	}
	t.Cleanup(func() { _ = signer.Close() })
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		t.Fatalf("Public() type = %T, want *rsa.PublicKey", signer.Public())
	}
	return signer
}

func TestRSAChainIsRSASignedEndToEnd(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	rootKey := newRSACAKey(t, config.RootKeyRSA4096)
	rootDER, _, err := ca.SelfSignRoot(ca.RootParams{
		Signer:    rootKey,
		Subject:   pkix.Name{CommonName: "ACME RSA Root CA", Organization: []string{"ACME"}},
		NotBefore: now,
		NotAfter:  now.AddDate(10, 0, 0),
	})
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate root: %v", err)
	}

	// The intermediate stands in for a platform CA being subordinated: it
	// brings its own RSA key and is handed a CA certificate.
	interKey := newRSACAKey(t, config.RootKeyRSA3072)
	pathLen := 0
	interDER, _, err := ca.Sign(ca.Profile{
		Subject:   pkix.Name{CommonName: "ACME RSA Intermediate CA", Organization: []string{"ACME"}},
		NotBefore: now,
		NotAfter:  now.AddDate(5, 0, 0),
		IsCA:      true,
		PathLen:   &pathLen,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, interKey.Public(), rootCert, rootKey)
	if err != nil {
		t.Fatalf("Sign intermediate: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("ParseCertificate intermediate: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("GenerateKey leaf: %v", err)
	}
	leafDER, _, err := ca.Sign(ca.Profile{
		Subject:     pkix.Name{CommonName: "host.acme.example"},
		NotBefore:   now,
		NotAfter:    now.AddDate(0, 0, 90),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"host.acme.example"},
	}, &leafKey.PublicKey, interCert, interKey)
	if err != nil {
		t.Fatalf("Sign leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}

	// Every signature in the chain must be SHA-2 RSA. One ECDSA signature
	// anywhere is enough for a platform CA that rejects the family to refuse
	// the whole chain.
	rsaSigAlgs := map[x509.SignatureAlgorithm]bool{
		x509.SHA256WithRSA: true,
		x509.SHA384WithRSA: true,
		x509.SHA512WithRSA: true,
	}
	for _, c := range []struct {
		name string
		cert *x509.Certificate
	}{
		{"root", rootCert},
		{"intermediate", interCert},
		{"leaf", leafCert},
	} {
		if !rsaSigAlgs[c.cert.SignatureAlgorithm] {
			t.Errorf("%s SignatureAlgorithm = %v, want a SHA-2 RSA algorithm", c.name, c.cert.SignatureAlgorithm)
		}
	}

	// The chain must actually verify, not merely carry the right OIDs.
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(interCert)
	chains, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now.AddDate(0, 0, 1),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(chains) != 1 || len(chains[0]) != 3 {
		t.Fatalf("chain shape = %d chains, first of length %d, want 1 chain of 3", len(chains), len(chains[0]))
	}

	// The intermediate must be usable as a CA: CA:TRUE with pathlen 0 and the
	// signing key usages, which is what a subordinated platform CA needs.
	if !interCert.IsCA {
		t.Error("intermediate IsCA = false, want true")
	}
	if interCert.MaxPathLen != 0 || !interCert.MaxPathLenZero {
		t.Errorf("intermediate pathLen = %d (zero=%v), want 0 (zero=true)", interCert.MaxPathLen, interCert.MaxPathLenZero)
	}
	if interCert.KeyUsage&x509.KeyUsageCertSign == 0 || interCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Errorf("intermediate KeyUsage = %v, want certSign and crlSign", interCert.KeyUsage)
	}
}
