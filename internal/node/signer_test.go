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

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// signerFixture bundles an in-memory ECDSA-P384 CA signer with its
// self-signed issuer certificate, avoiding any TPM dependency.
type signerFixture struct {
	issuerKey  *ecdsa.PrivateKey
	issuerCert *x509.Certificate
}

func newSignerFixture(t *testing.T) *signerFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	der, _, err := ca.SelfSignRoot(ca.RootParams{
		Signer:    key,
		Subject:   pkix.Name{CommonName: "Test Root CA"},
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
	return &signerFixture{issuerKey: key, issuerCert: cert}
}

// loaders returns a KeyLoader (in-memory signer), IssuerFunc, and ConfigFunc
// over the given config, tracking whether the signer was closed.
func (f *signerFixture) loaders(cfg *config.Config, closed *bool) (KeyLoader, IssuerFunc, ConfigFunc) {
	load := func(ctx context.Context) (crypto.Signer, func(), error) {
		return f.issuerKey, func() { *closed = true }, nil
	}
	issuer := func(ctx context.Context) (*x509.Certificate, error) {
		return f.issuerCert, nil
	}
	get := func(ctx context.Context) (*config.Config, error) {
		return cfg, nil
	}
	return load, issuer, get
}

// makeCSR generates a fresh P-384 key and returns a CSR DER for it.
func makeCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

func caProfileConfig(role config.RoleKind) *config.Config {
	pathLen := uint32(0)
	return &config.Config{
		Role: config.Role{Kind: role},
		PKI: config.PKI{
			Profiles: []config.CertificateProfile{
				{
					Name:             "sub-ca",
					KeyAlg:           config.RootKeyECDSAP384,
					Subject:          config.Subject{CommonName: "Issuing CA"},
					ValidityDays:     3650,
					BasicConstraints: config.BasicConstraints{IsCA: true, PathLen: &pathLen},
					KeyUsage:         []string{"cert_sign", "crl_sign"},
				},
				{
					Name:             "leaf-server",
					KeyAlg:           config.RootKeyECDSAP384,
					Subject:          config.Subject{CommonName: "leaf"},
					ValidityDays:     90,
					BasicConstraints: config.BasicConstraints{IsCA: false},
					KeyUsage:         []string{"digital_signature"},
					ExtKeyUsage:      []string{"server_auth"},
					SANs:             config.SubjectAltNames{DNS: []string{"node.example"}},
				},
			},
		},
	}
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("error code: got %s, want %s (err=%v)", got, want, err)
	}
}

func TestSignSubordinate(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIntermediate), &closed)
	s := NewCASigner(load, issuer, get)

	csr := makeCSR(t, "Child Issuing CA")
	chainDER, chainPEM, err := s.SignSubordinate(context.Background(), csr, "sub-ca")
	if err != nil {
		t.Fatalf("SignSubordinate: %v", err)
	}
	if !closed {
		t.Fatal("SignSubordinate did not Close the loaded signer")
	}
	if len(chainDER) < 2 {
		t.Fatalf("chain length: got %d, want leaf + issuer", len(chainDER))
	}
	if chainPEM == "" {
		t.Fatal("empty chain PEM")
	}

	child, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse child: %v", err)
	}
	if !child.IsCA {
		t.Fatal("child certificate is not a CA")
	}
	// PathLen clamped: profile asked for 0, issuer (root) is unconstrained,
	// so the effective value is the profile's 0 (MaxPathLenZero).
	if !child.MaxPathLenZero || child.MaxPathLen != 0 {
		t.Fatalf("pathLen: got MaxPathLen=%d MaxPathLenZero=%v, want 0/true", child.MaxPathLen, child.MaxPathLenZero)
	}

	// The issuer must be the second element and the child must verify to it.
	if want := f.issuerCert.Raw; string(chainDER[len(chainDER)-1]) != string(want) {
		t.Fatal("last chain element is not the issuer certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.issuerCert)
	if _, err := child.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("child does not verify against issuer: %v", err)
	}
}

func TestSignSubordinateRejectsNonCAProfile(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIntermediate), &closed)
	s := NewCASigner(load, issuer, get)

	_, _, err := s.SignSubordinate(context.Background(), makeCSR(t, "x"), "leaf-server")
	wantCode(t, err, codes.InvalidArgument)
}

func TestSignSubordinateRejectsBadCSR(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIntermediate), &closed)
	s := NewCASigner(load, issuer, get)

	_, _, err := s.SignSubordinate(context.Background(), []byte("not a csr"), "sub-ca")
	wantCode(t, err, codes.InvalidArgument)
}

func TestIssueLeaf(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), &closed)
	s := NewCASigner(load, issuer, get)

	certDER, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if !closed {
		t.Fatal("IssueLeaf did not Close the loaded signer")
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.IsCA {
		t.Fatal("leaf certificate must not be a CA")
	}
}

func TestIssueLeafRejectsCAProfile(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), &closed)
	s := NewCASigner(load, issuer, get)

	_, err := s.IssueLeaf(context.Background(), makeCSR(t, "x"), "sub-ca")
	wantCode(t, err, codes.InvalidArgument)
}

func TestIssueLeafRootWithoutAck(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleRoot), &closed)
	s := NewCASigner(load, issuer, get)

	_, err := s.IssueLeaf(context.Background(), makeCSR(t, "x"), "leaf-server")
	wantCode(t, err, codes.FailedPrecondition)
}

func TestIssueLeafRootWithAck(t *testing.T) {
	f := newSignerFixture(t)
	cfg := caProfileConfig(config.RoleRoot)
	cfg.PKI.RootLeafIssuance = config.RootLeafIssuanceAcknowledged
	var closed bool
	load, issuer, get := f.loaders(cfg, &closed)
	s := NewCASigner(load, issuer, get)

	if _, err := s.IssueLeaf(context.Background(), makeCSR(t, "x"), "leaf-server"); err != nil {
		t.Fatalf("IssueLeaf with ack: %v", err)
	}
}

func TestIssueLeafRecordsIssuedCert(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), &closed)

	var gotDER []byte
	var gotProfile string
	s := NewCASigner(load, issuer, get).WithRecorder(func(_ context.Context, der []byte, profileName string) error {
		gotDER = der
		gotProfile = profileName
		return nil
	})

	certDER, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if string(gotDER) != string(certDER) {
		t.Fatal("recorder did not receive the minted certificate DER")
	}
	if gotProfile != "leaf-server" {
		t.Fatalf("recorder profile = %q, want leaf-server", gotProfile)
	}
}

func TestIssueLeafFailsWhenRecorderFails(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), &closed)
	s := NewCASigner(load, issuer, get).WithRecorder(func(context.Context, []byte, string) error {
		return errors.New("etcd unavailable")
	})

	certDER, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server")
	if err == nil {
		t.Fatal("IssueLeaf must fail when recording fails")
	}
	if certDER != nil {
		t.Fatal("IssueLeaf must not return a certificate when recording fails")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("error code = %s, want Internal", got)
	}
}

func TestSignSubordinateRecordsIssuedCert(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIntermediate), &closed)

	var recorded bool
	s := NewCASigner(load, issuer, get).WithRecorder(func(context.Context, []byte, string) error {
		recorded = true
		return nil
	})

	if _, _, err := s.SignSubordinate(context.Background(), makeCSR(t, "Child CA"), "sub-ca"); err != nil {
		t.Fatalf("SignSubordinate: %v", err)
	}
	if !recorded {
		t.Fatal("SignSubordinate did not record the minted subordinate certificate")
	}
}

func TestIssueLeafStampsCDPAndAIA(t *testing.T) {
	f := newSignerFixture(t)
	cfg := caProfileConfig(config.RoleIssuing)
	cfg.PKI.RevocationBaseURL = "http://pki.acme.example"
	var closed bool
	load, issuer, get := f.loaders(cfg, &closed)
	s := NewCASigner(load, issuer, get).WithPreflight(func(context.Context) bool { return true })

	certDER, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != "http://pki.acme.example/crl" {
		t.Fatalf("CRLDistributionPoints = %v, want [http://pki.acme.example/crl]", leaf.CRLDistributionPoints)
	}
	if len(leaf.OCSPServer) != 1 || leaf.OCSPServer[0] != "http://pki.acme.example/ocsp" {
		t.Fatalf("OCSPServer = %v, want [http://pki.acme.example/ocsp]", leaf.OCSPServer)
	}
}

func TestIssueLeafFailsClosedWhenPreflightFailing(t *testing.T) {
	f := newSignerFixture(t)
	cfg := caProfileConfig(config.RoleIssuing)
	cfg.PKI.RevocationBaseURL = "http://pki.acme.example"
	var closed bool
	load, issuer, get := f.loaders(cfg, &closed)
	s := NewCASigner(load, issuer, get).WithPreflight(func(context.Context) bool { return false })

	_, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server")
	wantCode(t, err, codes.FailedPrecondition)
}

func TestIssueLeafOverrideIssuesWhenPreflightFailing(t *testing.T) {
	f := newSignerFixture(t)
	cfg := caProfileConfig(config.RoleIssuing)
	cfg.PKI.RevocationBaseURL = "http://pki.acme.example"
	cfg.PKI.AllowUnverifiedRevocationURL = true
	var closed bool
	load, issuer, get := f.loaders(cfg, &closed)
	s := NewCASigner(load, issuer, get).WithPreflight(func(context.Context) bool { return false })

	certDER, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server")
	if err != nil {
		t.Fatalf("IssueLeaf with override: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.CRLDistributionPoints) != 1 || len(leaf.OCSPServer) != 1 {
		t.Fatalf("override issuance must still stamp CDP/AIA: cdp=%v aia=%v", leaf.CRLDistributionPoints, leaf.OCSPServer)
	}
}
