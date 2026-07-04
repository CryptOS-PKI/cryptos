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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// KeyLoader reloads this node's CA private key as a crypto.Signer. The CA key
// is never held after boot; the signing service loads it per request and
// invokes closeFn to release the backing resource (the TPM handle in tpm mode)
// once signing completes.
type KeyLoader func(ctx context.Context) (signer crypto.Signer, closeFn func(), err error)

// IssuerFunc returns this node's own CA certificate (the issuer of everything
// this service signs).
type IssuerFunc func(ctx context.Context) (*x509.Certificate, error)

// ConfigFunc returns the node's current validated configuration, which carries
// the named certificate profiles and the ROOT leaf-issuance acknowledgement.
type ConfigFunc func(ctx context.Context) (*config.Config, error)

// CASigner signs subordinate-CA and leaf certificates with this node's CA key,
// reloading the key per request. It is intentionally decoupled from the gRPC
// layer: it takes small loader/getter functions so it is testable with an
// in-memory signer and imports no transport code.
type CASigner struct {
	load   KeyLoader
	issuer IssuerFunc
	cfg    ConfigFunc
}

// NewCASigner constructs a CASigner from a key loader, an issuer-cert getter,
// and a config getter.
func NewCASigner(load KeyLoader, issuer IssuerFunc, cfg ConfigFunc) *CASigner {
	return &CASigner{load: load, issuer: issuer, cfg: cfg}
}

// SignSubordinate parses and verifies csrDER, resolves the named profile (which
// must be a CA profile), builds a ca.Profile using the CSR subject and the
// profile's extensions, clamps the pathLenConstraint to the parent's remaining
// budget, and signs a CA certificate with this node's CA key. It returns the
// chain leaf-first (child, then this node's issuer chain) in DER and PEM.
func (s *CASigner) SignSubordinate(ctx context.Context, csrDER []byte, profileName string) (chainDER [][]byte, chainPEM string, err error) {
	csr, err := parseAndVerifyCSR(csrDER)
	if err != nil {
		return nil, "", err
	}

	cfg, err := s.currentConfig(ctx)
	if err != nil {
		return nil, "", err
	}
	prof := cfg.ProfileByName(profileName)
	if prof == nil {
		return nil, "", status.Errorf(codes.InvalidArgument, "node: unknown profile %q", profileName)
	}
	if !prof.BasicConstraints.IsCA {
		return nil, "", status.Errorf(codes.InvalidArgument, "node: profile %q is not a CA profile", profileName)
	}

	issuerCert, err := s.issuer(ctx)
	if err != nil {
		return nil, "", status.Errorf(codes.FailedPrecondition, "node: load issuer certificate: %v", err)
	}
	if issuerCert == nil {
		return nil, "", status.Error(codes.FailedPrecondition, "node: no issuer certificate available")
	}

	p, err := profileToCA(prof, csr.Subject)
	if err != nil {
		return nil, "", err
	}
	p.PathLen = clampPathLen(prof, issuerCert)

	der, pemBytes, err := s.sign(ctx, p, csr.PublicKey, issuerCert)
	if err != nil {
		return nil, "", err
	}

	chainDER = [][]byte{der}
	var sb strings.Builder
	sb.Write(pemBytes)
	for _, c := range issuerChain(issuerCert) {
		chainDER = append(chainDER, c.Raw)
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return chainDER, sb.String(), nil
}

// IssueLeaf parses and verifies csrDER, resolves the named profile (which must
// be a non-CA profile), and signs an end-entity certificate with this node's CA
// key. A ROOT-role node refuses unless the config carries the irreversible
// leaf-issuance acknowledgement. It returns the leaf DER.
func (s *CASigner) IssueLeaf(ctx context.Context, csrDER []byte, profileName string) (certDER []byte, err error) {
	csr, err := parseAndVerifyCSR(csrDER)
	if err != nil {
		return nil, err
	}

	cfg, err := s.currentConfig(ctx)
	if err != nil {
		return nil, err
	}
	prof := cfg.ProfileByName(profileName)
	if prof == nil {
		return nil, status.Errorf(codes.InvalidArgument, "node: unknown profile %q", profileName)
	}
	if prof.BasicConstraints.IsCA {
		return nil, status.Errorf(codes.InvalidArgument, "node: profile %q is a CA profile, not a leaf profile", profileName)
	}

	if cfg.Role.Kind == config.RoleRoot && cfg.PKI.RootLeafIssuance != config.RootLeafIssuanceAcknowledged {
		return nil, status.Error(codes.FailedPrecondition,
			"node: a ROOT node refuses to issue leaf certificates without the irreversible acknowledgement")
	}

	issuerCert, err := s.issuer(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "node: load issuer certificate: %v", err)
	}
	if issuerCert == nil {
		return nil, status.Error(codes.FailedPrecondition, "node: no issuer certificate available")
	}

	p, err := profileToCA(prof, csr.Subject)
	if err != nil {
		return nil, err
	}

	der, _, err := s.sign(ctx, p, csr.PublicKey, issuerCert)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// sign loads the CA key, signs the built profile, and always closes the loaded
// signer.
func (s *CASigner) sign(ctx context.Context, p ca.Profile, subjectPub crypto.PublicKey, issuer *x509.Certificate) (der, pemBytes []byte, err error) {
	signer, closeFn, err := s.load(ctx)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "node: load CA key: %v", err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	if signer == nil {
		return nil, nil, status.Error(codes.Internal, "node: CA key loader returned a nil signer")
	}
	der, pemBytes, err = ca.Sign(p, subjectPub, issuer, signer)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "node: sign: %v", err)
	}
	return der, pemBytes, nil
}

func (s *CASigner) currentConfig(ctx context.Context) (*config.Config, error) {
	cfg, err := s.cfg(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "node: load config: %v", err)
	}
	if cfg == nil {
		return nil, status.Error(codes.FailedPrecondition, "node: no config available")
	}
	return cfg, nil
}

// parseAndVerifyCSR parses csrDER and verifies its self-signature.
func parseAndVerifyCSR(csrDER []byte) (*x509.CertificateRequest, error) {
	if len(csrDER) == 0 {
		return nil, status.Error(codes.InvalidArgument, "node: empty CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node: parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node: CSR signature is invalid: %v", err)
	}
	// The subject key must be ECDSA P-384 (Phase-2 key alg). Reject a client's
	// unsupported key as InvalidArgument here, rather than letting ca.Sign fail
	// deeper and surface as Internal.
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P384() {
		return nil, status.Error(codes.InvalidArgument, "node: CSR public key must be ECDSA P-384")
	}
	return csr, nil
}

// profileToCA maps a config.CertificateProfile plus the resolved subject onto a
// ca.Profile. The subject comes from the CSR; the extensions come from the
// profile so the issuer, not the requester, dictates usage.
func profileToCA(prof *config.CertificateProfile, subject pkix.Name) (ca.Profile, error) {
	ku, err := ca.ParseKeyUsage(prof.KeyUsage)
	if err != nil {
		return ca.Profile{}, status.Errorf(codes.InvalidArgument, "node: profile key usage: %v", err)
	}
	eku, err := ca.ParseExtKeyUsage(prof.ExtKeyUsage)
	if err != nil {
		return ca.Profile{}, status.Errorf(codes.InvalidArgument, "node: profile extended key usage: %v", err)
	}
	ips, err := parseIPs(prof.SANs.IP)
	if err != nil {
		return ca.Profile{}, err
	}
	uris, err := parseURIs(prof.SANs.URI)
	if err != nil {
		return ca.Profile{}, err
	}

	now := time.Now()
	p := ca.Profile{
		Subject:         subject,
		NotBefore:       now,
		NotAfter:        now.Add(time.Duration(prof.ValidityDays) * 24 * time.Hour),
		IsCA:            prof.BasicConstraints.IsCA,
		KeyUsage:        ku,
		ExtKeyUsage:     eku,
		DNSNames:        prof.SANs.DNS,
		IPAddresses:     ips,
		EmailAddresses:  prof.SANs.Email,
		URIs:            uris,
		ExtraExtensions: extraExtensions(prof.ExtraExtensions),
	}
	return p, nil
}

// clampPathLen returns the effective pathLenConstraint for a subordinate CA:
// the profile's requested value, further bounded by the parent's remaining
// budget when the parent is itself pathLen-constrained. A parent budget of N
// permits a child pathLen of at most N-1. When the parent is unconstrained
// (MaxPathLen omitted) the profile value stands unchanged.
func clampPathLen(prof *config.CertificateProfile, issuer *x509.Certificate) *int {
	var requested *int
	if prof.BasicConstraints.PathLen != nil {
		v := int(*prof.BasicConstraints.PathLen)
		requested = &v
	}
	// Parent constrained only when basicConstraints carried a pathLen: either a
	// positive MaxPathLen or MaxPathLenZero (an explicit 0).
	if issuer.MaxPathLen <= 0 && !issuer.MaxPathLenZero {
		return requested
	}
	budget := issuer.MaxPathLen - 1
	if budget < 0 {
		budget = 0
	}
	if requested == nil || *requested > budget {
		return &budget
	}
	return requested
}

// issuerChain returns the chain to append after a freshly signed certificate:
// the issuer itself. A deeper chain is appended by the caller layer when the
// issuer carries intermediates; here we have only this node's own CA cert.
func issuerChain(issuer *x509.Certificate) []*x509.Certificate {
	return []*x509.Certificate{issuer}
}

func extraExtensions(in []config.X509Extension) []pkix.Extension {
	if len(in) == 0 {
		return nil
	}
	out := make([]pkix.Extension, 0, len(in))
	for _, e := range in {
		out = append(out, pkix.Extension{
			Id:       parseOID(e.OID),
			Critical: e.Critical,
			Value:    e.Value,
		})
	}
	return out
}

// parseOID converts a validated dotted OID string into an asn1.ObjectIdentifier.
// The config layer has already validated the arcs, so a parse issue here is a
// programmer error rather than untrusted input.
func parseOID(s string) asn1.ObjectIdentifier {
	arcs := strings.Split(s, ".")
	out := make(asn1.ObjectIdentifier, 0, len(arcs))
	for _, a := range arcs {
		n := 0
		for _, r := range a {
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

func parseIPs(in []string) ([]net.IP, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]net.IP, 0, len(in))
	for _, s := range in {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, status.Errorf(codes.InvalidArgument, "node: invalid SAN IP %q", s)
		}
		out = append(out, ip)
	}
	return out, nil
}

func parseURIs(in []string) ([]*url.URL, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]*url.URL, 0, len(in))
	for _, s := range in {
		u, err := url.Parse(s)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "node: invalid SAN URI %q: %v", s, err)
		}
		out = append(out, u)
	}
	return out, nil
}
