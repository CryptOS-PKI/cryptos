package config

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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
)

// APIVersion is the only api/kind pair accepted in Phase 1. Validator
// rejects any other value with no silent migration.
const (
	APIVersion = "cryptos.dev/v1alpha1"
	Kind       = "MachineConfig"
)

// RoleKind enumerates the supported node roles (root, and the Phase-2
// subordinate roles intermediate and issuing).
type RoleKind string

const (
	RoleRoot         RoleKind = "root"
	RoleIntermediate RoleKind = "intermediate" // Phase 2
	RoleIssuing      RoleKind = "issuing"      // Phase 2
)

// RootKeyAlg enumerates the supported Root key algorithms. Phase 1
// fixes this to ECDSA P-384; if a target TPM cannot satisfy it, PID 1
// fails to boot rather than silently downgrading.
type RootKeyAlg string

const (
	RootKeyECDSAP384 RootKeyAlg = "ECDSA-P384"
)

// Config is the validated, in-memory representation of a machine config.
type Config struct {
	APIVersion string    `yaml:"apiVersion"`
	Kind       string    `yaml:"kind"`
	Metadata   Metadata  `yaml:"metadata"`
	Role       Role      `yaml:"role"`
	Network    Network   `yaml:"network"`
	Bootstrap  Bootstrap `yaml:"bootstrap"`
	PKI        PKI       `yaml:"pki"`
	Install    Install   `yaml:"install"`
}

// Install declares how the node provisions itself to persistent storage during
// the maintenance-mode install. Absent on an already-installed node.
type Install struct {
	Disk string `yaml:"disk"`
}

// Metadata carries operator-facing identifiers (not used for trust).
type Metadata struct {
	Name string `yaml:"name"`
}

// Role declares the CA role this node boots into.
type Role struct {
	Kind RoleKind `yaml:"kind"`
}

// Network declares the static network configuration. DHCP is Phase 2.
type Network struct {
	Interface string `yaml:"interface"`
	Address   string `yaml:"address"` // CIDR, e.g. "10.0.0.10/24"
	Gateway   string `yaml:"gateway"`
}

// Bootstrap carries the administrator credential trusted on first boot.
// Exactly one of AdminCertPEM or AdminCertSHA256 must be set.
type Bootstrap struct {
	AdminCertPEM    string `yaml:"admin_cert_pem"`
	AdminCertSHA256 string `yaml:"admin_cert_sha256"`
}

// PKI declares the CA's cryptographic parameters and naming.
type PKI struct {
	RootKeyAlg        RootKeyAlg `yaml:"root_key_alg"`
	RootSubject       Subject    `yaml:"root_subject"`
	RootValidityYears uint32     `yaml:"root_validity_years"`
	// PathLenConstraint is RESERVED for intermediate/issuing CAs (Phase 2).
	// It is NOT applied to the Phase 1 Root: per RFC 5280 §4.2.1.9 a Root is
	// left unconstrained (any depth); path depth is bounded at sub-CAs.
	PathLenConstraint uint32 `yaml:"path_len_constraint"`
	// Profiles are the operator-defined certificate profiles (Phase 2) this
	// node may generate a CSR from or stamp when signing. Referenced by name
	// from the issuance flows. Empty on Phase 1 configs.
	Profiles []CertificateProfile `yaml:"profiles"`
	// RootLeafIssuance is the explicit, irreversible operator acknowledgement
	// required before a ROOT-role node will issue end-entity (leaf)
	// certificates directly. A best-practice PKI issues leaves from an
	// issuing CA, never the offline Root; a Root that has signed a leaf can
	// no longer credibly claim to have signed only CAs. The signing service
	// refuses IssueLeaf on a ROOT node unless this equals
	// RootLeafIssuanceAcknowledged. It is deliberately not carried in the
	// proto MachineConfig: it lives only in the on-node machine.yaml.
	RootLeafIssuance string `yaml:"root_leaf_issuance"`
	// RevocationBaseURL is the operator-visible base URL under which this node
	// publishes its CRL and OCSP responder. When set, issuance stamps a CDP
	// pointer at <base>/crl and an AIA-OCSP pointer at <base>/ocsp, and the node
	// starts an anonymous HTTP listener serving those paths on a management boot.
	// It is on-node behaviour, not part of the wire MachineConfig, so it is
	// yaml-only (mirroring RootLeafIssuance) and not carried in the proto.
	RevocationBaseURL string `yaml:"revocation_base_url"`
	// AllowUnverifiedRevocationURL overrides the fail-closed revocation preflight:
	// when true the node still issues even if the configured base URL does not
	// resolve or its /crl and /ocsp endpoints are unreachable. Intended for an
	// isolated lab where DNS is not yet wired; production leaves it false so a
	// misconfigured URL blocks issuance rather than stamping a dead pointer.
	AllowUnverifiedRevocationURL bool `yaml:"allow_unverified_revocation_url"`
	// CRLNextUpdateHours is the CRL validity window: nextUpdate is thisUpdate
	// plus this many hours. Zero means the caller's default (168h / one week).
	CRLNextUpdateHours uint32 `yaml:"crl_next_update_hours"`
	// RevocationHTTPPort is the TCP port the anonymous CRL/OCSP HTTP listener
	// binds on a management boot. Zero means the caller's default.
	RevocationHTTPPort uint32 `yaml:"revocation_http_port"`
	// Parent is the trust anchor a subordinate CA pins for its issuer: the
	// parent CA it verifies a handed-back signed chain against during the
	// first-boot ceremony. Required on an intermediate/issuing node, absent
	// (nil) on a Root.
	Parent *Parent `yaml:"parent"`
}

// Parent is the pinned issuer trust anchor for a subordinate CA. Exactly one
// of CACertPEM or CACertSHA256 must be set, mirroring the bootstrap admin
// credential shape.
type Parent struct {
	CACertPEM    string `yaml:"ca_cert_pem"`
	CACertSHA256 string `yaml:"ca_cert_sha256"`
}

// RootLeafIssuanceAcknowledged is the exact RootLeafIssuance value that
// unlocks direct leaf issuance from a ROOT-role node.
const RootLeafIssuanceAcknowledged = "acknowledged-irreversible"

// CertificateProfile is an operator-defined template for CSR generation and
// certificate signing: key parameters, subject, validity, and a covering
// subset of X.509 extensions plus a raw-OID escape hatch (ExtraExtensions).
type CertificateProfile struct {
	Name             string           `yaml:"name"`
	KeyAlg           RootKeyAlg       `yaml:"key_alg"`
	Subject          Subject          `yaml:"subject"`
	ValidityDays     uint32           `yaml:"validity_days"`
	BasicConstraints BasicConstraints `yaml:"basic_constraints"`
	KeyUsage         []string         `yaml:"key_usage"`
	ExtKeyUsage      []string         `yaml:"ext_key_usage"`
	SANs             SubjectAltNames  `yaml:"sans"`
	ExtraExtensions  []X509Extension  `yaml:"extra_extensions"`
}

// BasicConstraints models the RFC 5280 basicConstraints extension. PathLen
// applies only when IsCA: a non-nil zero means no CAs may be issued below
// (leaf-only issuing CA); nil means unconstrained depth.
type BasicConstraints struct {
	IsCA    bool    `yaml:"is_ca"`
	PathLen *uint32 `yaml:"path_len"`
}

// SubjectAltNames carries the typed subjectAltName entries for a profile.
type SubjectAltNames struct {
	DNS   []string `yaml:"dns"`
	IP    []string `yaml:"ip"`
	Email []string `yaml:"email"`
	URI   []string `yaml:"uri"`
}

// X509Extension is the raw escape hatch: a dotted OID, criticality flag, and
// the DER-encoded extension value, for extensions not yet typed.
type X509Extension struct {
	OID      string `yaml:"oid"`
	Critical bool   `yaml:"critical"`
	Value    []byte `yaml:"value"`
}

// Subject is the X.500 Distinguished Name for the Root certificate.
type Subject struct {
	CommonName   string `yaml:"common_name"`
	Organization string `yaml:"organization"`
	Country      string `yaml:"country"`
}

// Parse parses a machine-config YAML document and runs every Phase 1
// validation rule. The returned Config is safe to apply.
func Parse(raw []byte) (*Config, error) {
	if len(raw) == 0 {
		return nil, errors.New("config: empty input")
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse YAML: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate runs every Phase 1 schema rule against c. The error wraps
// the field path so callers can surface it via INVALID_ARGUMENT details
// on the gRPC layer.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config: nil config")
	}
	if c.APIVersion != APIVersion {
		return fmt.Errorf("config: apiVersion: expected %q, got %q", APIVersion, c.APIVersion)
	}
	if c.Kind != Kind {
		return fmt.Errorf("config: kind: expected %q, got %q", Kind, c.Kind)
	}
	switch c.Role.Kind {
	case RoleRoot, RoleIntermediate, RoleIssuing:
	default:
		return fmt.Errorf("config: role.kind: must be one of %q/%q/%q, got %q",
			RoleRoot, RoleIntermediate, RoleIssuing, c.Role.Kind)
	}
	if c.Network.Interface == "" {
		return errors.New("config: network.interface: required")
	}
	if _, err := netip.ParsePrefix(c.Network.Address); err != nil {
		return fmt.Errorf("config: network.address: must be CIDR: %w", err)
	}
	if _, err := netip.ParseAddr(c.Network.Gateway); err != nil {
		return fmt.Errorf("config: network.gateway: must be IP: %w", err)
	}
	if err := validateBootstrap(c.Bootstrap); err != nil {
		return err
	}
	if c.PKI.RootKeyAlg != RootKeyECDSAP384 {
		return fmt.Errorf("config: pki.root_key_alg: Phase 1 requires %q, got %q", RootKeyECDSAP384, c.PKI.RootKeyAlg)
	}
	if c.PKI.RootValidityYears < 1 || c.PKI.RootValidityYears > 30 {
		return fmt.Errorf("config: pki.root_validity_years: must be in [1, 30], got %d", c.PKI.RootValidityYears)
	}
	if c.PKI.PathLenConstraint > 5 {
		return fmt.Errorf("config: pki.path_len_constraint: must be in [0, 5], got %d", c.PKI.PathLenConstraint)
	}
	if c.PKI.RootSubject.CommonName == "" {
		return errors.New("config: pki.root_subject.common_name: required")
	}
	if err := validateProfiles(c.PKI.Profiles); err != nil {
		return err
	}
	if err := validateRevocationBaseURL(c.PKI.RevocationBaseURL); err != nil {
		return err
	}
	if err := validateParent(c.Role.Kind, c.PKI.Parent); err != nil {
		return err
	}
	return nil
}

// validateRevocationBaseURL enforces that a configured revocation base URL is a
// well-formed http(s) URL with a host. DNS resolution is deliberately NOT done
// here: the box may validate its config before the network is up. Reachability
// is a runtime preflight (see internal/revocation). An empty value is allowed.
func validateRevocationBaseURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("config: pki.revocation_base_url: must be an http(s) URL")
	}
	return nil
}

// validateParent enforces the subordinate parent-anchor rules: a Root must not
// carry a parent; an intermediate/issuing node must carry exactly one of the
// parent PEM or SHA-256.
func validateParent(role RoleKind, p *Parent) error {
	isSubordinate := role == RoleIntermediate || role == RoleIssuing
	if !isSubordinate {
		if p != nil {
			return errors.New("config: pki.parent: must not be set on a root node")
		}
		return nil
	}
	if p == nil {
		return errors.New("config: pki.parent: required on an intermediate/issuing node")
	}
	hasPEM := p.CACertPEM != ""
	hasSHA := p.CACertSHA256 != ""
	if hasPEM == hasSHA {
		return errors.New("config: pki.parent: exactly one of ca_cert_pem or ca_cert_sha256 is required")
	}
	if hasSHA {
		if len(p.CACertSHA256) != 64 {
			return fmt.Errorf("config: pki.parent.ca_cert_sha256: must be 64 hex characters, got %d", len(p.CACertSHA256))
		}
		if _, err := hex.DecodeString(p.CACertSHA256); err != nil {
			return fmt.Errorf("config: pki.parent.ca_cert_sha256: not hex: %w", err)
		}
		return nil
	}
	block, rest := pem.Decode([]byte(p.CACertPEM))
	if block == nil {
		return errors.New("config: pki.parent.ca_cert_pem: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("config: pki.parent.ca_cert_pem: PEM type %q, want CERTIFICATE", block.Type)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("config: pki.parent.ca_cert_pem: must contain exactly one PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("config: pki.parent.ca_cert_pem: parse: %w", err)
	}
	return nil
}

// ParentTrust builds a bootstrap.Trust from the pinned parent anchor. It
// returns nil (no error) when no parent is configured (a Root). Validate must
// have accepted the config first; a mis-shaped parent surfaces as an error.
func (c *Config) ParentTrust() (*bootstrap.Trust, error) {
	if c == nil || c.PKI.Parent == nil {
		return nil, nil
	}
	return bootstrap.LoadTrust(c.PKI.Parent.CACertPEM, c.PKI.Parent.CACertSHA256)
}

// validateProfiles enforces the Phase 2 certificate-profile rules. An empty
// slice is allowed (Phase 1 configs carry no profiles).
func validateProfiles(profiles []CertificateProfile) error {
	seen := make(map[string]struct{}, len(profiles))
	for i, p := range profiles {
		if p.Name == "" {
			return fmt.Errorf("config: pki.profiles[%d].name: required", i)
		}
		if _, dup := seen[p.Name]; dup {
			return fmt.Errorf("config: pki.profiles[%d].name: duplicate name %q", i, p.Name)
		}
		seen[p.Name] = struct{}{}
		if p.KeyAlg != RootKeyECDSAP384 {
			return fmt.Errorf("config: pki.profiles[%d].key_alg: Phase 2 requires %q, got %q", i, RootKeyECDSAP384, p.KeyAlg)
		}
		if p.ValidityDays == 0 {
			return fmt.Errorf("config: pki.profiles[%d].validity_days: must be greater than 0", i)
		}
		if _, err := ca.ParseKeyUsage(p.KeyUsage); err != nil {
			return fmt.Errorf("config: pki.profiles[%d].key_usage: %w", i, err)
		}
		if _, err := ca.ParseExtKeyUsage(p.ExtKeyUsage); err != nil {
			return fmt.Errorf("config: pki.profiles[%d].ext_key_usage: %w", i, err)
		}
		for j, ext := range p.ExtraExtensions {
			if err := validateOID(ext.OID); err != nil {
				return fmt.Errorf("config: pki.profiles[%d].extra_extensions[%d].oid: %w", i, j, err)
			}
		}
	}
	return nil
}

// validateOID accepts a dotted OID of at least two numeric arcs.
func validateOID(oid string) error {
	arcs := strings.Split(oid, ".")
	if len(arcs) < 2 {
		return fmt.Errorf("invalid OID %q: need at least two arcs", oid)
	}
	for _, arc := range arcs {
		if arc == "" {
			return fmt.Errorf("invalid OID %q: empty arc", oid)
		}
		for _, r := range arc {
			if r < '0' || r > '9' {
				return fmt.Errorf("invalid OID %q: non-numeric arc %q", oid, arc)
			}
		}
	}
	return nil
}

// NodeRole maps the configured RoleKind to the API NodeRole.
func (c *Config) NodeRole() cryptosv1.NodeRole {
	switch c.Role.Kind {
	case RoleIntermediate:
		return cryptosv1.NodeRole_NODE_ROLE_INTERMEDIATE
	case RoleIssuing:
		return cryptosv1.NodeRole_NODE_ROLE_ISSUING
	default:
		return cryptosv1.NodeRole_NODE_ROLE_ROOT
	}
}

// ProfileByName returns the certificate profile with the given name, or nil
// when no profile carries that name. It is a linear scan over PKI.Profiles.
func (c *Config) ProfileByName(name string) *CertificateProfile {
	if c == nil {
		return nil
	}
	for i := range c.PKI.Profiles {
		if c.PKI.Profiles[i].Name == name {
			return &c.PKI.Profiles[i]
		}
	}
	return nil
}

func validateBootstrap(b Bootstrap) error {
	hasPEM := b.AdminCertPEM != ""
	hasSHA := b.AdminCertSHA256 != ""
	if hasPEM == hasSHA {
		return errors.New("config: bootstrap: exactly one of admin_cert_pem or admin_cert_sha256 is required")
	}
	if hasSHA {
		if len(b.AdminCertSHA256) != 64 {
			return fmt.Errorf("config: bootstrap.admin_cert_sha256: must be 64 hex characters, got %d", len(b.AdminCertSHA256))
		}
		if _, err := hex.DecodeString(b.AdminCertSHA256); err != nil {
			return fmt.Errorf("config: bootstrap.admin_cert_sha256: not hex: %w", err)
		}
		return nil
	}
	block, rest := pem.Decode([]byte(b.AdminCertPEM))
	if block == nil {
		return errors.New("config: bootstrap.admin_cert_pem: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("config: bootstrap.admin_cert_pem: PEM type %q, want CERTIFICATE", block.Type)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("config: bootstrap.admin_cert_pem: must contain exactly one PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("config: bootstrap.admin_cert_pem: parse: %w", err)
	}
	return nil
}

// Digest returns the SHA-256 digest of the canonical (JSON, sorted
// keys) encoding of the config. Stable across whitespace and comment
// changes in the source YAML.
func (c *Config) Digest() ([]byte, error) {
	canon, err := canonicalJSON(c)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}

func canonicalJSON(c *Config) ([]byte, error) {
	// json.Marshal sorts map keys but not struct fields. Round-trip
	// through a map[string]interface{} to enforce sorted-keys output.
	intermediate, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("config: canonicalize: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(intermediate, &m); err != nil {
		return nil, fmt.Errorf("config: canonicalize roundtrip: %w", err)
	}
	return marshalSorted(m)
}

func marshalSorted(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			sb.Write(kb)
			sb.WriteByte(':')
			vb, err := marshalSorted(t[k])
			if err != nil {
				return nil, err
			}
			sb.Write(vb)
		}
		sb.WriteByte('}')
		return []byte(sb.String()), nil
	case []interface{}:
		var sb strings.Builder
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			eb, err := marshalSorted(e)
			if err != nil {
				return nil, err
			}
			sb.Write(eb)
		}
		sb.WriteByte(']')
		return []byte(sb.String()), nil
	default:
		return json.Marshal(t)
	}
}

// Marshal renders c as the canonical machine.yaml document.
func (c *Config) Marshal() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromProto converts a proto MachineConfig back to a Config. It is the
// inverse of ToProto. Guard against sparse protos; each nested message
// is checked for nil before dereference.
func FromProto(pb *cryptosv1.MachineConfig) (*Config, error) {
	if pb == nil {
		return nil, errors.New("config: FromProto: nil proto")
	}
	c := &Config{
		APIVersion: pb.ApiVersion,
		Kind:       pb.Kind,
	}
	if pb.Metadata != nil {
		c.Metadata.Name = pb.Metadata.Name
	}
	if pb.Role != nil {
		c.Role.Kind = RoleKind(pb.Role.Kind)
	}
	if pb.Network != nil {
		c.Network.Interface = pb.Network.Interface
		c.Network.Address = pb.Network.Address
		c.Network.Gateway = pb.Network.Gateway
	}
	if pb.Bootstrap != nil {
		c.Bootstrap.AdminCertPEM = pb.Bootstrap.AdminCertPem
		c.Bootstrap.AdminCertSHA256 = pb.Bootstrap.AdminCertSha256
	}
	if pb.Pki != nil {
		c.PKI.RootKeyAlg = RootKeyAlg(pb.Pki.RootKeyAlg)
		c.PKI.RootValidityYears = pb.Pki.RootValidityYears
		c.PKI.PathLenConstraint = pb.Pki.PathLenConstraint
		if pb.Pki.RootSubject != nil {
			c.PKI.RootSubject.CommonName = pb.Pki.RootSubject.CommonName
			c.PKI.RootSubject.Organization = pb.Pki.RootSubject.Organization
			c.PKI.RootSubject.Country = pb.Pki.RootSubject.Country
		}
		c.PKI.Profiles = profilesFromProto(pb.Pki.Profiles)
		c.PKI.RevocationBaseURL = pb.Pki.RevocationBaseUrl
		c.PKI.AllowUnverifiedRevocationURL = pb.Pki.AllowUnverifiedRevocationUrl
		c.PKI.CRLNextUpdateHours = pb.Pki.CrlNextUpdateHours
		c.PKI.RevocationHTTPPort = pb.Pki.RevocationHttpPort
		if pb.Pki.Parent != nil {
			c.PKI.Parent = &Parent{
				CACertPEM:    pb.Pki.Parent.CaCertPem,
				CACertSHA256: pb.Pki.Parent.CaCertSha256,
			}
		}
	}
	if pb.Install != nil {
		c.Install.Disk = pb.Install.Disk
	}
	return c, nil
}

// ToProto adapts the validated Config to the api/ proto MachineConfig
// for the gRPC layer. Only the Phase 1 subset is populated.
func (c *Config) ToProto() *cryptosv1.MachineConfig {
	pki := &cryptosv1.Pki{
		RootKeyAlg: string(c.PKI.RootKeyAlg),
		RootSubject: &cryptosv1.Subject{
			CommonName:   c.PKI.RootSubject.CommonName,
			Organization: c.PKI.RootSubject.Organization,
			Country:      c.PKI.RootSubject.Country,
		},
		RootValidityYears:            c.PKI.RootValidityYears,
		PathLenConstraint:            c.PKI.PathLenConstraint,
		Profiles:                     profilesToProto(c.PKI.Profiles),
		RevocationBaseUrl:            c.PKI.RevocationBaseURL,
		AllowUnverifiedRevocationUrl: c.PKI.AllowUnverifiedRevocationURL,
		CrlNextUpdateHours:           c.PKI.CRLNextUpdateHours,
		RevocationHttpPort:           c.PKI.RevocationHTTPPort,
	}
	if c.PKI.Parent != nil {
		pki.Parent = &cryptosv1.Parent{
			CaCertPem:    c.PKI.Parent.CACertPEM,
			CaCertSha256: c.PKI.Parent.CACertSHA256,
		}
	}
	return &cryptosv1.MachineConfig{
		ApiVersion: c.APIVersion,
		Kind:       c.Kind,
		Metadata: &cryptosv1.Metadata{
			Name: c.Metadata.Name,
		},
		Role: &cryptosv1.Role{
			Kind: string(c.Role.Kind),
		},
		Network: &cryptosv1.Network{
			Interface: c.Network.Interface,
			Address:   c.Network.Address,
			Gateway:   c.Network.Gateway,
		},
		Bootstrap: &cryptosv1.Bootstrap{
			AdminCertPem:    c.Bootstrap.AdminCertPEM,
			AdminCertSha256: c.Bootstrap.AdminCertSHA256,
		},
		Pki: pki,
		Install: &cryptosv1.Install{
			Disk: c.Install.Disk,
		},
	}
}

// profilesToProto maps the Go certificate profiles to their proto form. A nil
// or empty input yields a nil slice so the round-trip is stable.
func profilesToProto(in []CertificateProfile) []*cryptosv1.CertificateProfile {
	if len(in) == 0 {
		return nil
	}
	out := make([]*cryptosv1.CertificateProfile, len(in))
	for i, p := range in {
		out[i] = &cryptosv1.CertificateProfile{
			Name:   p.Name,
			KeyAlg: string(p.KeyAlg),
			Subject: &cryptosv1.Subject{
				CommonName:   p.Subject.CommonName,
				Organization: p.Subject.Organization,
				Country:      p.Subject.Country,
			},
			ValidityDays: p.ValidityDays,
			BasicConstraints: &cryptosv1.BasicConstraints{
				IsCa:    p.BasicConstraints.IsCA,
				PathLen: p.BasicConstraints.PathLen,
			},
			KeyUsage:    p.KeyUsage,
			ExtKeyUsage: p.ExtKeyUsage,
			Sans: &cryptosv1.SubjectAltNames{
				Dns:   p.SANs.DNS,
				Ip:    p.SANs.IP,
				Email: p.SANs.Email,
				Uri:   p.SANs.URI,
			},
			ExtraExtensions: extraExtensionsToProto(p.ExtraExtensions),
		}
	}
	return out
}

func extraExtensionsToProto(in []X509Extension) []*cryptosv1.X509Extension {
	if len(in) == 0 {
		return nil
	}
	out := make([]*cryptosv1.X509Extension, len(in))
	for i, e := range in {
		out[i] = &cryptosv1.X509Extension{
			Oid:      e.OID,
			Critical: e.Critical,
			Value:    e.Value,
		}
	}
	return out
}

// profilesFromProto is the inverse of profilesToProto. Nil nested messages are
// guarded so a sparse proto does not panic.
func profilesFromProto(in []*cryptosv1.CertificateProfile) []CertificateProfile {
	if len(in) == 0 {
		return nil
	}
	out := make([]CertificateProfile, len(in))
	for i, p := range in {
		if p == nil {
			continue
		}
		prof := CertificateProfile{
			Name:         p.Name,
			KeyAlg:       RootKeyAlg(p.KeyAlg),
			ValidityDays: p.ValidityDays,
			KeyUsage:     p.KeyUsage,
			ExtKeyUsage:  p.ExtKeyUsage,
		}
		if p.Subject != nil {
			prof.Subject.CommonName = p.Subject.CommonName
			prof.Subject.Organization = p.Subject.Organization
			prof.Subject.Country = p.Subject.Country
		}
		if p.BasicConstraints != nil {
			prof.BasicConstraints.IsCA = p.BasicConstraints.IsCa
			prof.BasicConstraints.PathLen = p.BasicConstraints.PathLen
		}
		if p.Sans != nil {
			prof.SANs.DNS = p.Sans.Dns
			prof.SANs.IP = p.Sans.Ip
			prof.SANs.Email = p.Sans.Email
			prof.SANs.URI = p.Sans.Uri
		}
		prof.ExtraExtensions = extraExtensionsFromProto(p.ExtraExtensions)
		out[i] = prof
	}
	return out
}

func extraExtensionsFromProto(in []*cryptosv1.X509Extension) []X509Extension {
	if len(in) == 0 {
		return nil
	}
	out := make([]X509Extension, len(in))
	for i, e := range in {
		if e == nil {
			continue
		}
		out[i] = X509Extension{
			OID:      e.Oid,
			Critical: e.Critical,
			Value:    e.Value,
		}
	}
	return out
}
