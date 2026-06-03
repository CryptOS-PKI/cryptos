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
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	zlintx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// newTPMRootSigner is a test helper that returns a TPM-backed
// crypto.Signer holding a freshly-created Root key in the simulator.
func newTPMRootSigner(t *testing.T) *tpm.Key {
	t.Helper()
	tp, err := tpm.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	if err := tp.ProvisionSRK(); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	priv, pub, err := tp.CreateKey(tpm.AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	key, err := tp.LoadKey(priv, pub)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	t.Cleanup(func() { _ = key.Close() })
	return key
}

func defaultParams(signer *tpm.Key) RootParams {
	now := time.Now().UTC().Truncate(time.Second)
	return RootParams{
		Signer: signer,
		Subject: pkix.Name{
			CommonName:   "CryptOS Root CA — Test",
			Organization: []string{"Acme Corp"},
			Country:      []string{"US"},
		},
		NotBefore:         now,
		NotAfter:          now.AddDate(20, 0, 0),
		PathLenConstraint: 2,
	}
}

func TestSelfSignRoot_StructureMatchesPhase1(t *testing.T) {
	signer := newTPMRootSigner(t)
	der, pemBytes, err := SelfSignRoot(defaultParams(signer))
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	if len(der) == 0 || len(pemBytes) == 0 {
		t.Fatalf("empty der/pem returned: %d/%d", len(der), len(pemBytes))
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Version
	if cert.Version != 3 {
		t.Fatalf("Version = %d, want 3", cert.Version)
	}
	// Serial: positive, ≤ 20 octets DER
	if cert.SerialNumber.Sign() <= 0 {
		t.Fatalf("SerialNumber must be positive")
	}
	if cert.SerialNumber.BitLen() > 159 {
		t.Fatalf("SerialNumber bit length %d > 159", cert.SerialNumber.BitLen())
	}
	// SignatureAlgorithm
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Fatalf("SignatureAlgorithm = %v, want ECDSAWithSHA384", cert.SignatureAlgorithm)
	}
	// Issuer == Subject
	if cert.Issuer.String() != cert.Subject.String() {
		t.Fatalf("Issuer (%q) != Subject (%q)", cert.Issuer, cert.Subject)
	}
	// BasicConstraints
	if !cert.IsCA {
		t.Fatalf("IsCA must be true")
	}
	if cert.MaxPathLen != 2 {
		t.Fatalf("MaxPathLen = %d, want 2", cert.MaxPathLen)
	}
	if cert.MaxPathLenZero {
		t.Fatalf("MaxPathLenZero must be false when PathLenConstraint=2")
	}
	// KeyUsage = certSign | crlSign only
	wantKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage != wantKU {
		t.Fatalf("KeyUsage = 0x%x, want 0x%x", cert.KeyUsage, wantKU)
	}
	// No extKeyUsage on a Root
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
		t.Fatalf("Root cert must not have ExtKeyUsage; got %v / %v", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	// No subjectAltName on a Root
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 ||
		len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
		t.Fatalf("Root cert must not have SANs; got DNS=%v IP=%v Email=%v URI=%v",
			cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs)
	}
	// SKI / AKI
	if len(cert.SubjectKeyId) != 20 {
		t.Fatalf("SubjectKeyId length %d, want 20 (SHA-1)", len(cert.SubjectKeyId))
	}
	if string(cert.AuthorityKeyId) != string(cert.SubjectKeyId) {
		t.Fatalf("AuthorityKeyId != SubjectKeyId (self-signed)")
	}
}

func TestSelfSignRoot_VerifiesAgainstItself(t *testing.T) {
	signer := newTPMRootSigner(t)
	der, _, err := SelfSignRoot(defaultParams(signer))
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool})
	if err != nil {
		t.Fatalf("stdlib Verify rejected the self-signed Root: %v", err)
	}
}

func TestSelfSignRoot_ZLintCleanRoot(t *testing.T) {
	signer := newTPMRootSigner(t)
	der, _, err := SelfSignRoot(defaultParams(signer))
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}

	// zlint operates on zcrypto/x509's parser.
	zcert, err := zlintx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("zcrypto ParseCertificate: %v", err)
	}

	// CryptOS is an internal/private PKI, not a public web CA. CABF /
	// Mozilla / Apple / Chrome / ETSI lints encode public-CA-only
	// requirements (e.g., CABF requires digitalSignature on ECC certs
	// — irrelevant for a Root that signs only sub-CAs and CRLs). Limit
	// the bar to RFC-source lints, which cover the actual cert-format
	// correctness we care about.
	registry, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		IncludeSources: lint.SourceList{
			lint.RFC3279,
			lint.RFC5280,
			lint.RFC5480,
			lint.RFC5891,
			lint.RFC6960,
			lint.RFC6962,
			lint.RFC8813,
		},
	})
	if err != nil {
		t.Fatalf("zlint Filter: %v", err)
	}
	results := zlint.LintCertificateEx(zcert, registry)
	if results == nil {
		t.Fatalf("zlint returned nil results")
	}

	var errs, warns []string
	for name, r := range results.Results {
		switch r.Status {
		case lint.Error, lint.Fatal:
			errs = append(errs, name+": "+r.Details)
		case lint.Warn:
			warns = append(warns, name+": "+r.Details)
		}
	}
	if len(errs) != 0 {
		t.Fatalf("zlint RFC-source errors:\n%s", strings.Join(errs, "\n"))
	}
	if len(warns) != 0 {
		t.Fatalf("zlint RFC-source warnings:\n%s", strings.Join(warns, "\n"))
	}
}

func TestSelfSignRoot_PathLenZero(t *testing.T) {
	signer := newTPMRootSigner(t)
	p := defaultParams(signer)
	p.PathLenConstraint = 0
	der, _, err := SelfSignRoot(p)
	if err != nil {
		t.Fatalf("SelfSignRoot: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Fatalf("MaxPathLen=%d MaxPathLenZero=%v, want 0/true", cert.MaxPathLen, cert.MaxPathLenZero)
	}
}

func TestSelfSignRoot_RejectsBadInputs(t *testing.T) {
	signer := newTPMRootSigner(t)
	now := time.Now()
	cases := []struct {
		name   string
		params RootParams
	}{
		{
			name:   "nil signer",
			params: RootParams{NotBefore: now, NotAfter: now.AddDate(1, 0, 0)},
		},
		{
			name:   "zero validity",
			params: RootParams{Signer: signer},
		},
		{
			name: "inverted validity",
			params: RootParams{
				Signer:    signer,
				NotBefore: now.AddDate(1, 0, 0),
				NotAfter:  now,
			},
		},
		{
			name: "negative path len",
			params: RootParams{
				Signer:            signer,
				NotBefore:         now,
				NotAfter:          now.AddDate(1, 0, 0),
				PathLenConstraint: -1,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := SelfSignRoot(tc.params); err == nil {
				t.Fatalf("SelfSignRoot should have failed")
			}
		})
	}
}
