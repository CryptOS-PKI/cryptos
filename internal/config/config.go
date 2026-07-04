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
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
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
	}
	if pb.Install != nil {
		c.Install.Disk = pb.Install.Disk
	}
	return c, nil
}

// ToProto adapts the validated Config to the api/ proto MachineConfig
// for the gRPC layer. Only the Phase 1 subset is populated.
func (c *Config) ToProto() *cryptosv1.MachineConfig {
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
		Pki: &cryptosv1.Pki{
			RootKeyAlg: string(c.PKI.RootKeyAlg),
			RootSubject: &cryptosv1.Subject{
				CommonName:   c.PKI.RootSubject.CommonName,
				Organization: c.PKI.RootSubject.Organization,
				Country:      c.PKI.RootSubject.Country,
			},
			RootValidityYears: c.PKI.RootValidityYears,
			PathLenConstraint: c.PKI.PathLenConstraint,
		},
		Install: &cryptosv1.Install{
			Disk: c.Install.Disk,
		},
	}
}
