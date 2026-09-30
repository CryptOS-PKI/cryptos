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
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func scepTestProfiles() []CertificateProfile {
	return append(acmeTestProfiles(), CertificateProfile{
		Name: "cisco-device", KeyAlg: RootKeyECDSAP384, ValidityDays: 365,
		KeyUsage: []string{"digital_signature", "key_encipherment"}, ExtKeyUsage: []string{"client_auth", "server_auth"},
	})
}

// validSCEP is a block that must pass, so each rejection below differs from a
// passing config in exactly one way.
func validSCEP() *SCEP {
	return &SCEP{
		Profiles: []SCEPProfile{
			{Profile: "cisco-device", MinRSAKeyBits: 2048},
			{Profile: "leaf-server", RequireApproval: true},
		},
		AllowedIdentifierSuffixes: []string{"example.com"},
	}
}

// issuingConfig is validYAML turned into an issuing node, the role that
// serves enrolment protocols.
func issuingConfig(t *testing.T) *Config {
	t.Helper()
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.Role.Kind = RoleIssuing
	cfg.PKI.Parent = &Parent{CACertSHA256: strings.Repeat("ab", 32)}
	cfg.PKI.Profiles = scepTestProfiles()
	return cfg
}

func TestValidateSCEPAccepts(t *testing.T) {
	cfg := issuingConfig(t)
	cfg.PKI.SCEP = validSCEP()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid SCEP block was rejected: %v", err)
	}
}

func TestValidateSCEPAbsentIsFine(t *testing.T) {
	cfg := issuingConfig(t)
	if cfg.PKI.SCEP != nil {
		t.Fatal("SCEP must default to off")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// Root Mode shuts every service-plane listener, so a Root cannot carry SCEP.
func TestValidateSCEPRefusedOnRoot(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = scepTestProfiles()
	cfg.PKI.SCEP = validSCEP()
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "pki.scep") || !strings.Contains(err.Error(), "root") {
		t.Fatalf("Validate on a Root with SCEP = %v, want a pki.scep root refusal", err)
	}
}

func TestValidateSCEPRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*SCEP)
		expect string
	}{
		{"no profiles", func(s *SCEP) { s.Profiles = nil }, "pki.scep.profiles"},
		{"blank profile name", func(s *SCEP) { s.Profiles[0].Profile = "" }, "pki.scep.profiles[0].profile"},
		{"unknown profile", func(s *SCEP) { s.Profiles[0].Profile = "nope" }, "no profile named"},
		{"ca profile", func(s *SCEP) { s.Profiles[0].Profile = "sub-ca" }, "CA profile"},
		{"duplicate profile", func(s *SCEP) { s.Profiles[1].Profile = "cisco-device" }, "appears more than once"},
		{"floor below 2048", func(s *SCEP) { s.Profiles[0].MinRSAKeyBits = 1024 }, "min_rsa_key_bits"},
		{"floor absurdly high", func(s *SCEP) { s.Profiles[0].MinRSAKeyBits = 65536 }, "min_rsa_key_bits"},
		{"no allowlist", func(s *SCEP) { s.AllowedIdentifierSuffixes = nil }, "allowed_identifier_suffixes"},
		{"blank suffix", func(s *SCEP) { s.AllowedIdentifierSuffixes = []string{" "} }, "allowed_identifier_suffixes[0]"},
		{"wildcard suffix", func(s *SCEP) { s.AllowedIdentifierSuffixes = []string{"*.example.com"} }, "allowed_identifier_suffixes[0]"},
		{"ra validity over a year", func(s *SCEP) { s.RA.ValidityDays = 400 }, "pki.scep.ra.validity_days"},
		{"overlap as long as the validity", func(s *SCEP) { s.RA.ValidityDays = 30; s.RA.RotationOverlapDays = 30 }, "rotation_overlap_days"},
		{"overlap longer than the default validity", func(s *SCEP) { s.RA.RotationOverlapDays = 365 }, "rotation_overlap_days"},
		{"port out of range", func(s *SCEP) { s.HTTPPort = 70000 }, "http_port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := issuingConfig(t)
			s := validSCEP()
			tc.mutate(s)
			cfg.PKI.SCEP = s
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("Validate = %v, want an error mentioning %q", err, tc.expect)
			}
		})
	}
}

func TestSCEPDefaults(t *testing.T) {
	var p SCEPProfile
	if got := p.RSAFloor(); got != 3072 {
		t.Fatalf("zero min_rsa_key_bits floor = %d, want 3072", got)
	}
	p.MinRSAKeyBits = 2048
	if got := p.RSAFloor(); got != 2048 {
		t.Fatalf("floor = %d, want 2048", got)
	}
	var ra SCEPRA
	if ra.Validity() != 365*24*time.Hour || ra.Overlap() != 30*24*time.Hour {
		t.Fatalf("RA defaults = %v / %v, want 365 days / 30 days", ra.Validity(), ra.Overlap())
	}
	s := validSCEP()
	if s.Profile("leaf-server") == nil || s.Profile("nope") != nil {
		t.Fatal("Profile lookup by name is wrong")
	}
}

func TestSCEPParsesFromYAML(t *testing.T) {
	raw := string(validYAML(t)) + `  scep:
    http_port: 8080
    profiles:
      - profile: cisco-device
        min_rsa_key_bits: 2048
        require_approval: true
    allowed_identifier_suffixes: [example.com]
    ra:
      validity_days: 180
      rotation_overlap_days: 14
`
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("a Root with pki.scep parsed; Parse validates and must refuse it")
	}
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := &SCEP{
		HTTPPort:                  8080,
		Profiles:                  []SCEPProfile{{Profile: "cisco-device", MinRSAKeyBits: 2048, RequireApproval: true}},
		AllowedIdentifierSuffixes: []string{"example.com"},
		RA:                        SCEPRA{ValidityDays: 180, RotationOverlapDays: 14},
	}
	if !reflect.DeepEqual(cfg.PKI.SCEP, want) {
		t.Fatalf("parsed SCEP = %+v, want %+v", cfg.PKI.SCEP, want)
	}
}

func TestSCEPProtoRoundTrip(t *testing.T) {
	cfg := issuingConfig(t)
	cfg.PKI.SCEP = validSCEP()
	cfg.PKI.SCEP.HTTPPort = 8080
	cfg.PKI.SCEP.RA = SCEPRA{ValidityDays: 180, RotationOverlapDays: 14}

	pb := cfg.ToProto()
	if !pb.GetPki().GetScep().GetEnabled() {
		t.Fatal("ToProto of a configured SCEP block must send enabled=true")
	}
	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if !reflect.DeepEqual(back.PKI.SCEP, cfg.PKI.SCEP) {
		t.Fatalf("round trip = %+v, want %+v", back.PKI.SCEP, cfg.PKI.SCEP)
	}
}

// An off protocol is explicit on the wire, and enabled=false or a missing
// block both come back as nil, this package's single spelling of "off".
func TestSCEPProtoOff(t *testing.T) {
	cfg := issuingConfig(t)
	pb := cfg.ToProto()
	if pb.GetPki().GetScep() == nil || pb.GetPki().GetScep().GetEnabled() {
		t.Fatalf("ToProto of an off SCEP = %v, want an explicit enabled=false block", pb.GetPki().GetScep())
	}
	pb.Pki.Scep = &cryptosv1.Scep{Enabled: false, Profiles: []*cryptosv1.ScepProfile{{Profile: "cisco-device"}}}
	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if back.PKI.SCEP != nil {
		t.Fatalf("enabled=false came back as %+v, want nil", back.PKI.SCEP)
	}
}

func TestKeepStoredSCEPWhenAbsent(t *testing.T) {
	prev := issuingConfig(t)
	prev.PKI.SCEP = validSCEP()

	pb := issuingConfig(t).ToProto()
	pb.Pki.Scep = nil
	next, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	next.KeepStoredSCEPWhenAbsent(pb, prev)
	if !reflect.DeepEqual(next.PKI.SCEP, prev.PKI.SCEP) {
		t.Fatalf("an apply without a scep block dropped the stored one: got %+v", next.PKI.SCEP)
	}

	pb.Pki.Scep = &cryptosv1.Scep{Enabled: false}
	next, err = FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	next.KeepStoredSCEPWhenAbsent(pb, prev)
	if next.PKI.SCEP != nil {
		t.Fatal("enabled=false must switch SCEP off, not keep the stored block")
	}

	next.KeepStoredSCEPWhenAbsent(pb, nil)
}

func TestSCEPChangeNeedsReboot(t *testing.T) {
	old := issuingConfig(t)
	on := issuingConfig(t)
	on.PKI.SCEP = validSCEP()
	if !NeedsReboot(old, on) {
		t.Fatal("switching SCEP on must need a reboot: the listener starts only at boot")
	}
	changed := issuingConfig(t)
	changed.PKI.SCEP = validSCEP()
	changed.PKI.SCEP.Profiles[0].MinRSAKeyBits = 3072
	if !NeedsReboot(on, changed) {
		t.Fatal("changing a SCEP profile floor must need a reboot")
	}
}
