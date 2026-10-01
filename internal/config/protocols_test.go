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
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// issuingWithProtocols is a valid issuing-node config serving both protocols,
// with one secret in each credential list.
func issuingWithProtocols(t *testing.T) *Config {
	t.Helper()
	c, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c.Role.Kind = RoleIssuing
	c.PKI.Parent = &Parent{CACertSHA256: strings.Repeat("ab", 32)}
	c.PKI.Profiles = acmeTestProfiles()
	c.PKI.ACME = &ACME{
		BaseURL:                   "https://ca.example.org/acme",
		HTTPPort:                  8555,
		Profile:                   "leaf-server",
		TermsOfService:            "https://ca.example.org/tos",
		Website:                   "https://ca.example.org",
		ExternalAccountKeys:       []ExternalAccountKey{{KeyID: "ops", HMACKeyBase64: validEABKey()}},
		AllowedIdentifierSuffixes: []string{"example.org"},
		OrderTTLHours:             12,
	}
	c.PKI.EST = &EST{
		Hostnames:                 []string{"est.example.org"},
		HTTPPort:                  8443,
		Profile:                   "leaf-server",
		Label:                     "devices",
		Realm:                     "cryptos",
		AllowedIdentifierSuffixes: []string{"devices.example.org"},
		EnrollCredentials:         []ESTEnrollCredential{{Username: "router", PasswordSHA256: testPasswordDigest()}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("fixture does not validate: %v", err)
	}
	return c
}

// issuingYAML is validYAML for an issuing node, the role an enrolment protocol
// runs on. The pki block stays last, so a test can append to it.
func issuingYAML(t *testing.T) []byte {
	t.Helper()
	s := strings.Replace(string(validYAML(t)), "  kind: root\n", "  kind: issuing\n", 1)
	return []byte(s + "  parent:\n    ca_cert_sha256: \"" + strings.Repeat("ab", 32) + "\"\n")
}

func otherEABKey() string {
	return base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
}

func TestValidateRejectsProtocolsOnRoot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		expect string
	}{
		{"acme", func(c *Config) { c.PKI.EST = nil }, "pki.acme"},
		{"est", func(c *Config) { c.PKI.ACME = nil }, "pki.est"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := issuingWithProtocols(t)
			tc.mutate(c)
			c.Role.Kind = RoleRoot
			c.PKI.Parent = nil
			c.PKI.RootValidityYears = 20
			err := c.Validate()
			if err == nil {
				t.Fatal("a root node with an enrolment protocol switched on validated")
			}
			if !strings.Contains(err.Error(), tc.expect) || !strings.Contains(err.Error(), "root") {
				t.Errorf("error %q does not name %s and the root role", err, tc.expect)
			}
		})
	}
}

func TestParseRejectsProtocolsOnRoot(t *testing.T) {
	raw := string(validYAML(t)) + `  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
  acme:
    base_url: https://ca.example.org/acme
    profile: leaf-server
    allow_anonymous_accounts: true
`
	if _, err := Parse([]byte(raw)); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("Parse of a root config serving ACME = %v, want a root-role rejection", err)
	}
}

func TestProtoRoundTripCarriesProtocols(t *testing.T) {
	c := issuingWithProtocols(t)
	got, err := FromProto(c.ToProto())
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if !reflect.DeepEqual(got.PKI.ACME, c.PKI.ACME) {
		t.Errorf("ACME after the round trip = %+v, want %+v", got.PKI.ACME, c.PKI.ACME)
	}
	if !reflect.DeepEqual(got.PKI.EST, c.PKI.EST) {
		t.Errorf("EST after the round trip = %+v, want %+v", got.PKI.EST, c.PKI.EST)
	}
}

func TestToProtoMarksProtocolsEnabled(t *testing.T) {
	c := issuingWithProtocols(t)
	pb := c.ToProto()
	if !pb.GetPki().GetAcme().GetEnabled() || !pb.GetPki().GetEst().GetEnabled() {
		t.Fatalf("a configured protocol went out with enabled=false: acme=%v est=%v",
			pb.GetPki().GetAcme(), pb.GetPki().GetEst())
	}

	// An off protocol is sent as an explicit enabled=false block, not left
	// out: an absent block means "keep what the node has", so a config that
	// leaves a protocol out could never switch it off.
	c.PKI.ACME, c.PKI.EST = nil, nil
	pb = c.ToProto()
	if a := pb.GetPki().GetAcme(); a == nil || a.GetEnabled() {
		t.Errorf("an off ACME went out as %v, want an explicit enabled=false block", a)
	}
	if e := pb.GetPki().GetEst(); e == nil || e.GetEnabled() {
		t.Errorf("an off EST went out as %v, want an explicit enabled=false block", e)
	}
}

func TestFromProtoDisabledProtocolIsOff(t *testing.T) {
	c := issuingWithProtocols(t)
	pb := c.ToProto()
	pb.Pki.Acme.Enabled = false
	pb.Pki.Est.Enabled = false
	got, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if got.PKI.ACME != nil || got.PKI.EST != nil {
		t.Errorf("enabled=false left a protocol on: acme=%+v est=%+v", got.PKI.ACME, got.PKI.EST)
	}
}

func TestToProtoRedactedBlanksSecrets(t *testing.T) {
	c := issuingWithProtocols(t)
	pb := c.ToProtoRedacted()
	keys := pb.GetPki().GetAcme().GetExternalAccountKeys()
	if len(keys) != 1 || keys[0].GetKeyId() != "ops" || keys[0].GetHmacKeyBase64() != "" {
		t.Errorf("redacted ACME keys = %v, want key_id ops with an empty secret", keys)
	}
	creds := pb.GetPki().GetEst().GetEnrollCredentials()
	if len(creds) != 1 || creds[0].GetUsername() != "router" || creds[0].GetPasswordSha256() != "" {
		t.Errorf("redacted EST credentials = %v, want username router with an empty digest", creds)
	}
	if pb.GetPki().GetAcme().GetBaseUrl() != c.PKI.ACME.BaseURL {
		t.Error("redaction dropped a non-secret ACME field")
	}
	if c.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 == "" {
		t.Error("redaction blanked the secret in the config itself")
	}
}

func TestFromProtoOverAbsentBlockKeepsStored(t *testing.T) {
	prev := issuingWithProtocols(t)
	pb := prev.ToProto()
	pb.Pki.Acme = nil
	pb.Pki.Est = nil
	got, err := FromProtoOver(pb, prev)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	if !reflect.DeepEqual(got.PKI.ACME, prev.PKI.ACME) || !reflect.DeepEqual(got.PKI.EST, prev.PKI.EST) {
		t.Errorf("an apply without the blocks changed them: acme=%+v est=%+v", got.PKI.ACME, got.PKI.EST)
	}
}

func TestFromProtoOverDisabledSwitchesOff(t *testing.T) {
	prev := issuingWithProtocols(t)
	pb := prev.ToProto()
	pb.Pki.Acme = &nodev1.Acme{Enabled: false}
	got, err := FromProtoOver(pb, prev)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	if got.PKI.ACME != nil {
		t.Errorf("enabled=false left ACME on: %+v", got.PKI.ACME)
	}
	if got.PKI.EST == nil {
		t.Error("switching ACME off switched EST off too")
	}
}

func TestFromProtoOverBlankSecretKeepsStored(t *testing.T) {
	prev := issuingWithProtocols(t)
	got, err := FromProtoOver(prev.ToProtoRedacted(), prev)
	if err != nil {
		t.Fatalf("FromProtoOver of the redacted config: %v", err)
	}
	if !reflect.DeepEqual(got.PKI.ACME, prev.PKI.ACME) {
		t.Errorf("ACME after a redacted round trip = %+v, want the stored block", got.PKI.ACME)
	}
	if !reflect.DeepEqual(got.PKI.EST, prev.PKI.EST) {
		t.Errorf("EST after a redacted round trip = %+v, want the stored block", got.PKI.EST)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("the resolved config does not validate: %v", err)
	}
}

func TestFromProtoOverSetSecretReplacesStored(t *testing.T) {
	prev := issuingWithProtocols(t)
	pb := prev.ToProto()
	pb.Pki.Acme.ExternalAccountKeys[0].HmacKeyBase64 = otherEABKey()
	got, err := FromProtoOver(pb, prev)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	if got.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 != otherEABKey() {
		t.Error("a new secret for a known key_id did not replace the stored one")
	}
}

func TestFromProtoOverRemovedEntryIsRevoked(t *testing.T) {
	prev := issuingWithProtocols(t)
	pb := prev.ToProtoRedacted()
	pb.Pki.Acme.ExternalAccountKeys = nil
	pb.Pki.Acme.AllowAnonymousAccounts = true
	got, err := FromProtoOver(pb, prev)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	if len(got.PKI.ACME.ExternalAccountKeys) != 0 {
		t.Errorf("a key left out of the apply survived: %+v", got.PKI.ACME.ExternalAccountKeys)
	}
}

func TestFromProtoOverBlankSecretForUnknownIdentifierIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*nodev1.MachineConfig)
		expect string
	}{
		{
			name: "acme key_id",
			mutate: func(pb *nodev1.MachineConfig) {
				pb.Pki.Acme.ExternalAccountKeys = append(pb.Pki.Acme.ExternalAccountKeys,
					&nodev1.AcmeExternalAccountKey{KeyId: "new-team"})
			},
			expect: `"new-team"`,
		},
		{
			name: "est username",
			mutate: func(pb *nodev1.MachineConfig) {
				pb.Pki.Est.EnrollCredentials = append(pb.Pki.Est.EnrollCredentials,
					&nodev1.EstEnrollCredential{Username: "switch"})
			},
			expect: `"switch"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := issuingWithProtocols(t)
			pb := prev.ToProtoRedacted()
			tc.mutate(pb)
			_, err := FromProtoOver(pb, prev)
			if err == nil {
				t.Fatal("an empty secret for an unknown identifier was accepted")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error %q does not name the identifier %s", err, tc.expect)
			}
		})
	}
}

// With nothing stored (a maintenance install), every empty secret belongs to
// an identifier the node has never seen.
func TestFromProtoOverBlankSecretWithNothingStored(t *testing.T) {
	c := issuingWithProtocols(t)
	if _, err := FromProtoOver(c.ToProtoRedacted(), nil); err == nil {
		t.Fatal("a redacted config was accepted with nothing stored to fill its secrets from")
	}
	got, err := FromProtoOver(c.ToProto(), nil)
	if err != nil {
		t.Fatalf("FromProtoOver with full secrets and nothing stored: %v", err)
	}
	if !reflect.DeepEqual(got.PKI.ACME, c.PKI.ACME) {
		t.Errorf("ACME = %+v, want %+v", got.PKI.ACME, c.PKI.ACME)
	}
}

// config get prints secrets blank, and the operator feeds that YAML back to
// config apply. The client-side check has to accept the blanks the node will
// fill, while the node's own parse stays strict.
func TestParseForApplyAcceptsKeptSecrets(t *testing.T) {
	c := issuingWithProtocols(t)
	redacted, err := FromProto(c.ToProtoRedacted())
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	raw, err := redacted.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Parse(raw); err == nil {
		t.Error("the strict Parse accepted a config with empty secrets")
	}
	got, err := ParseForApply(raw)
	if err != nil {
		t.Fatalf("ParseForApply of a config with empty secrets: %v", err)
	}
	if got.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 != "" {
		t.Error("ParseForApply invented a secret")
	}

	// A secret that is set is still checked.
	redacted.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 = "short"
	raw, err = redacted.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := ParseForApply(raw); err == nil {
		t.Error("ParseForApply accepted a malformed secret")
	}
}

func TestNeedsRebootForEveryProtocolChange(t *testing.T) {
	base := issuingWithProtocols(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"acme off", func(c *Config) { c.PKI.ACME = nil }},
		{"est off", func(c *Config) { c.PKI.EST = nil }},
		{"acme setting", func(c *Config) { c.PKI.ACME.HTTPPort = 9000 }},
		{"est setting", func(c *Config) { c.PKI.EST.Hostnames = []string{"other.example.org"} }},
		{"acme secret", func(c *Config) { c.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 = otherEABKey() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := issuingWithProtocols(t)
			tc.mutate(next)
			if !NeedsReboot(base, next) {
				t.Error("a protocol change was classified as live")
			}
		})
	}
	off := issuingWithProtocols(t)
	off.PKI.ACME, off.PKI.EST = nil, nil
	if !NeedsReboot(off, base) {
		t.Error("switching the protocols on was classified as live")
	}
}
