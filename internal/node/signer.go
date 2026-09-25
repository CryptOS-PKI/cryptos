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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"slices"
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

	// preflightOK reports whether the revocation base URL currently resolves and
	// its /crl, /ocsp and /ca.cer endpoints answer, re-checking on demand when the cached
	// result is not OK (revocation.Preflight.Ensure). It is nil until
	// WithPreflight wires the node's revocation.Preflight in; a nil accessor is
	// treated as failing so a management boot that forgot to run preflight fails
	// closed rather than stamping an unverified pointer.
	preflightOK func(ctx context.Context) bool

	// recordIssued persists a freshly minted certificate into the revocation
	// issued set so it can later be revoked and appear on the CRL/OCSP. It is nil
	// until WithRecorder wires the node's revocation store in; a nil recorder
	// means "do not record" (used by tests and any boot without a revocation
	// store). When set it is called after a successful Sign but BEFORE the
	// certificate is returned: if recording fails, issuance fails and the
	// certificate is NOT returned, so every returned certificate is tracked.
	recordIssued func(ctx context.Context, der []byte, profileName string) error
}

// NewCASigner constructs a CASigner from a key loader, an issuer-cert getter,
// and a config getter. Call WithPreflight to enable CDP/AIA stamping under a
// fail-closed revocation preflight.
func NewCASigner(load KeyLoader, issuer IssuerFunc, cfg ConfigFunc) *CASigner {
	return &CASigner{load: load, issuer: issuer, cfg: cfg}
}

// WithPreflight wires the revocation preflight accessor and returns the same
// CASigner for chaining. When set and the config carries a RevocationBaseURL,
// issuance stamps CDP/AIA pointers and refuses (FailedPrecondition) if the
// preflight is failing unless the config overrides with
// AllowUnverifiedRevocationURL.
func (s *CASigner) WithPreflight(ok func(ctx context.Context) bool) *CASigner {
	s.preflightOK = ok
	return s
}

// WithRecorder wires the issued-certificate recorder and returns the same
// CASigner for chaining. When set, IssueLeaf and SignSubordinate record every
// minted certificate before returning it; if recording fails the issuance
// fails and no certificate is returned, so the issued set never drifts from
// what a caller actually received.
func (s *CASigner) WithRecorder(record func(ctx context.Context, der []byte, profileName string) error) *CASigner {
	s.recordIssued = record
	return s
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
	if err := s.applyRevocation(ctx, &p, cfg); err != nil {
		return nil, "", err
	}

	der, pemBytes, err := s.sign(ctx, p, csr.PublicKey, issuerCert)
	if err != nil {
		return nil, "", err
	}
	if err := s.record(ctx, der, profileName); err != nil {
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
	der, _, _, err := s.issueLeaf(ctx, csrDER, profileName, nil, false)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// maxRequestDNSNames bounds the operator-asserted DNS names on one request.
const maxRequestDNSNames = 100

// IssueLeafWithRequestSANs is IssueLeaf with optional operator-asserted DNS
// names, the IssueLeafRequest.dns_names path. Non-empty dnsNames replace the
// profile's SAN set exactly as IssueLeafForNames does for ACME and EST, but
// here the caller asserts the names rather than proving control of them, so
// the profile must opt in with allow_request_sans. Without the opt-in the call
// is refused (FailedPrecondition) before the CA key is loaded. The names are
// validated as fully qualified host names (no wildcards, no duplicates, at
// most maxRequestDNSNames) and stamped lower-case. An empty dnsNames is
// IssueLeaf unchanged.
func (s *CASigner) IssueLeafWithRequestSANs(ctx context.Context, csrDER []byte, profileName string, dnsNames []string) (certDER []byte, err error) {
	names, err := normalizeRequestDNSNames(dnsNames)
	if err != nil {
		return nil, err
	}
	der, _, _, err := s.issueLeaf(ctx, csrDER, profileName, names, len(names) > 0)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// normalizeRequestDNSNames lower-cases and validates operator-asserted DNS
// names. The rules match the ACME and EST adapters: at least two labels, each
// 1-63 letters, digits or hyphens with no hyphen at either end, 253 characters
// in all, and no wildcard.
func normalizeRequestDNSNames(in []string) ([]string, error) {
	if len(in) > maxRequestDNSNames {
		return nil, status.Errorf(codes.InvalidArgument, "node: %d DNS names requested, at most %d allowed", len(in), maxRequestDNSNames)
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		name := strings.ToLower(raw)
		if err := validateHostName(name); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "node: DNS name %q: %v", raw, err)
		}
		if slices.Contains(out, name) {
			return nil, status.Errorf(codes.InvalidArgument, "node: DNS name %q requested twice", raw)
		}
		out = append(out, name)
	}
	return out, nil
}

// validateHostName checks a lower-case fully qualified host name.
func validateHostName(name string) error {
	if strings.Contains(name, "*") {
		return errors.New("wildcards are not issued")
	}
	if len(name) > 253 {
		return errors.New("longer than 253 characters")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return errors.New("not a fully qualified domain name")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return errors.New("empty or over-long label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("label starts or ends with a hyphen")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return errors.New("character not allowed in a host name")
			}
		}
	}
	return nil
}

// IssueLeafForNames issues a leaf exactly as IssueLeaf does, but takes the
// subject alternative names from dnsNames instead of from the profile, and
// returns the full chain leaf-first in DER and PEM.
//
// The SAN override exists for the enrolment protocols. IssueLeaf stamps the
// profile's static SAN list, which is right for an operator minting a
// certificate for a known host, but an ACME or EST client asks for names the
// profile cannot know in advance. The caller is then the authority on those
// names and must have proved control of every one of them before calling:
// internal/acme only reaches here with identifiers whose challenges are valid.
// Everything else about the certificate -- key usage, extended key usage,
// validity, extra extensions, CDP and AIA -- still comes from the profile, so
// this widens exactly one field and no more.
//
// A nil or empty dnsNames leaves the profile's SANs in place, which makes this
// identical to IssueLeaf plus the chain.
func (s *CASigner) IssueLeafForNames(ctx context.Context, csrDER []byte, profileName string, dnsNames []string) (chainDER [][]byte, chainPEM string, err error) {
	der, pemBytes, issuerCert, err := s.issueLeaf(ctx, csrDER, profileName, dnsNames, false)
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

// issueLeaf is the shared body of IssueLeaf, IssueLeafForNames and
// IssueLeafWithRequestSANs. When dnsNames is non-empty it replaces the
// profile's SAN set outright -- DNS, IP, email, URI and otherName alike --
// rather than merging: a merge would silently carry a name the caller neither
// asked for nor validated onto a certificate it did prove control of.
// requireOptIn marks operator-asserted names, which the profile must allow.
func (s *CASigner) issueLeaf(ctx context.Context, csrDER []byte, profileName string, dnsNames []string, requireOptIn bool) (der, pemBytes []byte, issuerCert *x509.Certificate, err error) {
	csr, err := parseAndVerifyCSR(csrDER)
	if err != nil {
		return nil, nil, nil, err
	}

	cfg, err := s.currentConfig(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	prof := cfg.ProfileByName(profileName)
	if prof == nil {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument, "node: unknown profile %q", profileName)
	}
	if prof.BasicConstraints.IsCA {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument, "node: profile %q is a CA profile, not a leaf profile", profileName)
	}
	if requireOptIn && !prof.AllowRequestSANs {
		return nil, nil, nil, status.Errorf(codes.FailedPrecondition,
			"node: profile %q does not set allow_request_sans; it stamps only its own SANs", profileName)
	}

	if cfg.Role.Kind == config.RoleRoot && cfg.PKI.RootLeafIssuance != config.RootLeafIssuanceAcknowledged {
		return nil, nil, nil, status.Error(codes.FailedPrecondition,
			"node: a ROOT node refuses to issue leaf certificates without the irreversible acknowledgement")
	}

	issuerCert, err = s.issuer(ctx)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.FailedPrecondition, "node: load issuer certificate: %v", err)
	}
	if issuerCert == nil {
		return nil, nil, nil, status.Error(codes.FailedPrecondition, "node: no issuer certificate available")
	}

	p, err := profileToCA(prof, csr.Subject)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(dnsNames) > 0 {
		p.DNSNames = dnsNames
		p.IPAddresses = nil
		p.EmailAddresses = nil
		p.URIs = nil
		p.OtherNames = nil
	}
	if err := s.applyRevocation(ctx, &p, cfg); err != nil {
		return nil, nil, nil, err
	}

	der, pemBytes, err = s.sign(ctx, p, csr.PublicKey, issuerCert)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := s.record(ctx, der, profileName); err != nil {
		return nil, nil, nil, err
	}
	return der, pemBytes, issuerCert, nil
}

// record persists der into the revocation issued set via the wired recorder.
// A nil recorder is a no-op (a boot without a revocation store). A recorder
// error is surfaced as Internal so the caller sees the issuance fail rather
// than receiving a certificate the node did not track.
func (s *CASigner) record(ctx context.Context, der []byte, profileName string) error {
	if s.recordIssued == nil {
		return nil
	}
	if err := s.recordIssued(ctx, der, profileName); err != nil {
		return status.Errorf(codes.Internal, "node: record issued certificate: %v", err)
	}
	return nil
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
	// Reject a client's unsupported subject key as InvalidArgument here, rather
	// than letting ca.Sign fail deeper and surface as Internal. ca.Sign applies
	// the same rule; this keeps the gRPC status code accurate.
	if err := ca.ValidateSubjectKey(csr.PublicKey); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node: %v", err)
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
	eku, unknownEKU, err := ca.ParseExtKeyUsage(prof.ExtKeyUsage)
	if err != nil {
		return ca.Profile{}, status.Errorf(codes.InvalidArgument, "node: profile extended key usage: %v", err)
	}
	otherNames, err := prof.SANs.OtherNames()
	if err != nil {
		return ca.Profile{}, status.Errorf(codes.InvalidArgument, "node: profile %v", err)
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
		Subject:            subject,
		NotBefore:          now,
		NotAfter:           now.Add(time.Duration(prof.ValidityDays) * 24 * time.Hour),
		IsCA:               prof.BasicConstraints.IsCA,
		KeyUsage:           ku,
		ExtKeyUsage:        eku,
		UnknownExtKeyUsage: unknownEKU,
		DNSNames:           prof.SANs.DNS,
		IPAddresses:        ips,
		EmailAddresses:     prof.SANs.Email,
		URIs:               uris,
		OtherNames:         otherNames,
		ExtraExtensions:    extraExtensions(prof.ExtraExtensions),
	}
	return p, nil
}

// applyRevocation stamps the CDP, AIA-OCSP and AIA caIssuers pointers onto p
// when the config carries a RevocationBaseURL. The caIssuers URI names this
// node's own certificate, served as DER by the revocation listener, so a
// relying party that holds only the root can still build the chain. It fails
// closed: when the preflight is not passing and the config does not set
// AllowUnverifiedRevocationURL, it returns a FailedPrecondition error rather
// than stamping a pointer that will not resolve. A nil preflight accessor counts as not-passing. When no base URL is
// configured it leaves p untouched.
func (s *CASigner) applyRevocation(ctx context.Context, p *ca.Profile, cfg *config.Config) error {
	base := strings.TrimRight(cfg.PKI.RevocationBaseURL, "/")
	if base == "" {
		return nil
	}
	if !cfg.PKI.AllowUnverifiedRevocationURL {
		if s.preflightOK == nil || !s.preflightOK(ctx) {
			return status.Error(codes.FailedPrecondition,
				"node: revocation preflight failing for configured revocation_base_url; issuance blocked (set allow_unverified_revocation_url to override)")
		}
	}
	p.CRLDistributionPoints = []string{base + "/crl"}
	p.OCSPServer = []string{base + "/ocsp"}
	p.IssuingCertificateURL = []string{base + "/ca.cer"}
	return nil
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
