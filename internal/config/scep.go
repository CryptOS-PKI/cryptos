package config

/*
Copyright The CryptOS Authors.

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
	"errors"
	"fmt"
	"strings"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// SCEP configures the node's RFC 8894 server (pki.scep). Nil is off, the
// default. It follows the protocol-block rules of the api's MachineConfig: an
// explicit enabled flag on the wire, a Root refuses it, and every change takes
// effect at the next boot.
//
// There is no static challenge setting on purpose. Initial enrolment is
// authorized by one-time challenges an admin mints over the API, and renewal
// by the certificate the device already holds; one secret configured for every
// device would let anyone who lifts it from one device enrol as any other.
type SCEP struct {
	// HTTPPort is the TCP port the SCEP listener binds. Zero means the node
	// default, which shares the plain-HTTP CRL/OCSP listener's port.
	HTTPPort uint32 `yaml:"http_port"`
	// Profiles are the certificate profiles SCEP issues from. A challenge
	// names one; a renewal reuses the profile of the certificate it renews.
	Profiles []SCEPProfile `yaml:"profiles"`
	// AllowedIdentifierSuffixes bounds the names an initial enrolment may
	// request: every DNS name and the subject common name must equal, or be
	// a subdomain of, one of these. Required, because a challenge proves
	// nothing about control of a name. Renewal names stay pinned to the
	// certificate being renewed.
	AllowedIdentifierSuffixes []string `yaml:"allowed_identifier_suffixes"`
	// RA tunes the RA certificate that decrypts requests and signs replies.
	RA SCEPRA `yaml:"ra"`
}

// SCEPProfile is one certificate profile SCEP may issue from.
type SCEPProfile struct {
	// Profile names a non-CA profile in pki.profiles.
	Profile string `yaml:"profile"`
	// MinRSAKeyBits is the smallest RSA subject key accepted over SCEP for
	// this profile. Zero means the node-wide 3072; 2048 is the lowest allowed,
	// for devices such as Cisco IOS and IOS-XE trustpoints that cannot hold a
	// larger key. Stronger RSA and ECDSA P-384 keys are always accepted.
	MinRSAKeyBits uint32 `yaml:"min_rsa_key_bits"`
	// RequireApproval holds every initial enrolment for an admin decision
	// (PENDING). Renewals are never held.
	RequireApproval bool `yaml:"require_approval"`
}

// SCEPRA tunes the RA certificate. The key is always RSA 3072.
type SCEPRA struct {
	// ValidityDays is the RA certificate lifetime. Zero means 365, which is
	// also the most.
	ValidityDays uint32 `yaml:"validity_days"`
	// RotationOverlapDays is how long before expiry the successor is minted;
	// both RAs decrypt during the overlap. Zero means 30.
	RotationOverlapDays uint32 `yaml:"rotation_overlap_days"`
}

const (
	scepDefaultRSAFloor     = 3072
	scepLowestRSAFloor      = 2048
	scepHighestRSAFloor     = 16384
	scepDefaultRAValidity   = 365
	scepMaxRAValidity       = 365
	scepDefaultRAOverlap    = 30
	maxTCPPort              = 65535
	scepAllowlistFieldLabel = "config: pki.scep.allowed_identifier_suffixes"
)

// Profile returns the SCEP profile with the given name, or nil.
func (s *SCEP) Profile(name string) *SCEPProfile {
	if s == nil {
		return nil
	}
	for i := range s.Profiles {
		if s.Profiles[i].Profile == name {
			return &s.Profiles[i]
		}
	}
	return nil
}

// RSAFloor is the effective RSA subject-key floor in bits.
func (p SCEPProfile) RSAFloor() int {
	if p.MinRSAKeyBits == 0 {
		return scepDefaultRSAFloor
	}
	return int(p.MinRSAKeyBits)
}

// Validity is the effective RA certificate lifetime.
func (r SCEPRA) Validity() time.Duration {
	d := r.ValidityDays
	if d == 0 {
		d = scepDefaultRAValidity
	}
	return time.Duration(d) * 24 * time.Hour
}

// Overlap is the effective RA rotation overlap.
func (r SCEPRA) Overlap() time.Duration {
	d := r.RotationOverlapDays
	if d == 0 {
		d = scepDefaultRAOverlap
	}
	return time.Duration(d) * 24 * time.Hour
}

// validateSCEP enforces the pki.scep rules. A nil block is off and passes.
func validateSCEP(role RoleKind, s *SCEP, profiles []CertificateProfile) error {
	if s == nil {
		return nil
	}
	if role == RoleRoot {
		return errors.New("config: pki.scep: must not be set on a root node; a root serves no " +
			"enrolment protocol, so serve SCEP from an intermediate or issuing node")
	}
	if s.HTTPPort > maxTCPPort {
		return fmt.Errorf("config: pki.scep.http_port: %d is not a TCP port", s.HTTPPort)
	}
	if len(s.Profiles) == 0 {
		return errors.New("config: pki.scep.profiles: at least one profile is required when pki.scep is set")
	}
	seen := make(map[string]bool, len(s.Profiles))
	for i, p := range s.Profiles {
		field := fmt.Sprintf("config: pki.scep.profiles[%d]", i)
		if p.Profile == "" {
			return fmt.Errorf("%s.profile: required", field)
		}
		if seen[p.Profile] {
			return fmt.Errorf("%s.profile: %q appears more than once", field, p.Profile)
		}
		seen[p.Profile] = true
		var prof *CertificateProfile
		for j := range profiles {
			if profiles[j].Name == p.Profile {
				prof = &profiles[j]
				break
			}
		}
		if prof == nil {
			return fmt.Errorf("%s.profile: no profile named %q in pki.profiles", field, p.Profile)
		}
		if prof.BasicConstraints.IsCA {
			return fmt.Errorf("%s.profile: %q is a CA profile; SCEP issues end-entity certificates only", field, p.Profile)
		}
		if p.MinRSAKeyBits != 0 && (p.MinRSAKeyBits < scepLowestRSAFloor || p.MinRSAKeyBits > scepHighestRSAFloor) {
			return fmt.Errorf("%s.min_rsa_key_bits: %d is out of range; use 0 for the node-wide %d, "+
				"or a value from %d to %d", field, p.MinRSAKeyBits, scepDefaultRSAFloor, scepLowestRSAFloor, scepHighestRSAFloor)
		}
	}
	if len(s.AllowedIdentifierSuffixes) == 0 {
		return errors.New(scepAllowlistFieldLabel + ": required when pki.scep is set; " +
			"a one-time challenge proves nothing about control of a name")
	}
	for i, suffix := range s.AllowedIdentifierSuffixes {
		trimmed := strings.TrimSpace(suffix)
		if trimmed == "" || strings.ContainsAny(trimmed, "*/ ") {
			return fmt.Errorf("%s[%d]: %q is not a DNS suffix", scepAllowlistFieldLabel, i, suffix)
		}
	}
	if s.RA.ValidityDays > scepMaxRAValidity {
		return fmt.Errorf("config: pki.scep.ra.validity_days: %d is more than the %d-day maximum", s.RA.ValidityDays, scepMaxRAValidity)
	}
	if s.RA.Overlap() >= s.RA.Validity() {
		return fmt.Errorf("config: pki.scep.ra.rotation_overlap_days: the overlap (%s) must be shorter than the RA validity (%s)",
			s.RA.Overlap(), s.RA.Validity())
	}
	return nil
}

// KeepStoredSCEPWhenAbsent applies the protocol-block rule for an apply that
// leaves pki.scep out: the stored block is kept, so a client that predates the
// block cannot switch SCEP off by omission. An explicit enabled=false has
// already become nil in FromProto and stays off.
func (c *Config) KeepStoredSCEPWhenAbsent(pb *cryptosv1.MachineConfig, prev *Config) {
	if prev == nil || pb.GetPki().GetScep() != nil {
		return
	}
	c.PKI.SCEP = prev.PKI.SCEP
}

func scepToProto(s *SCEP) *cryptosv1.Scep {
	if s == nil {
		return &cryptosv1.Scep{Enabled: false}
	}
	pb := &cryptosv1.Scep{
		Enabled:                   true,
		HttpPort:                  s.HTTPPort,
		AllowedIdentifierSuffixes: s.AllowedIdentifierSuffixes,
	}
	for _, p := range s.Profiles {
		pb.Profiles = append(pb.Profiles, &cryptosv1.ScepProfile{
			Profile:         p.Profile,
			MinRsaKeyBits:   p.MinRSAKeyBits,
			RequireApproval: p.RequireApproval,
		})
	}
	if s.RA != (SCEPRA{}) {
		pb.Ra = &cryptosv1.ScepRa{ValidityDays: s.RA.ValidityDays, RotationOverlapDays: s.RA.RotationOverlapDays}
	}
	return pb
}

func scepFromProto(pb *cryptosv1.Scep) *SCEP {
	if !pb.GetEnabled() {
		return nil
	}
	s := &SCEP{
		HTTPPort:                  pb.GetHttpPort(),
		AllowedIdentifierSuffixes: pb.GetAllowedIdentifierSuffixes(),
		RA: SCEPRA{
			ValidityDays:        pb.GetRa().GetValidityDays(),
			RotationOverlapDays: pb.GetRa().GetRotationOverlapDays(),
		},
	}
	for _, p := range pb.GetProfiles() {
		s.Profiles = append(s.Profiles, SCEPProfile{
			Profile:         p.GetProfile(),
			MinRSAKeyBits:   p.GetMinRsaKeyBits(),
			RequireApproval: p.GetRequireApproval(),
		})
	}
	return s
}
