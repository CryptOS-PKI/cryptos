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

	"google.golang.org/protobuf/proto"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// readBackOff is what the Fleet Manager applies to switch a protocol off: the
// node's redacted read-back with only enabled flipped.
func readBackOff(c *Config) *cryptosv1.MachineConfig {
	pb := c.ToProtoRedacted()
	pb.Pki.Acme.Enabled = false
	pb.Pki.Est.Enabled = false
	return pb
}

func TestDisabledBlockRoundTripsThroughProto(t *testing.T) {
	prev := issuingWithProtocols(t)
	got, err := FromProtoOver(readBackOff(prev), prev)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	if got.PKI.ACME != nil || got.PKI.EST != nil {
		t.Fatalf("enabled=false left a protocol on: acme=%+v est=%+v", got.PKI.ACME, got.PKI.EST)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("a config with disabled blocks does not validate: %v", err)
	}

	pb := got.ToProtoRedacted()
	a, e := pb.GetPki().GetAcme(), pb.GetPki().GetEst()
	if a.GetEnabled() || e.GetEnabled() {
		t.Fatalf("a disabled block read back as enabled: acme=%v est=%v", a, e)
	}
	if a.GetBaseUrl() != prev.PKI.ACME.BaseURL || a.GetProfile() != prev.PKI.ACME.Profile ||
		a.GetHttpPort() != prev.PKI.ACME.HTTPPort || a.GetOrderTtlHours() != prev.PKI.ACME.OrderTTLHours ||
		!reflect.DeepEqual(a.GetAllowedIdentifierSuffixes(), prev.PKI.ACME.AllowedIdentifierSuffixes) {
		t.Errorf("the disabled ACME block lost its settings: %v", a)
	}
	if len(a.GetExternalAccountKeys()) != 1 || a.GetExternalAccountKeys()[0].GetKeyId() != "ops" {
		t.Errorf("the disabled ACME block lost its key_id: %v", a.GetExternalAccountKeys())
	}
	if !reflect.DeepEqual(e.GetHostnames(), prev.PKI.EST.Hostnames) || e.GetProfile() != prev.PKI.EST.Profile ||
		e.GetLabel() != prev.PKI.EST.Label || e.GetRealm() != prev.PKI.EST.Realm || e.GetHttpPort() != prev.PKI.EST.HTTPPort {
		t.Errorf("the disabled EST block lost its settings: %v", e)
	}
	if len(e.GetEnrollCredentials()) != 1 || e.GetEnrollCredentials()[0].GetUsername() != "router" {
		t.Errorf("the disabled EST block lost its username: %v", e.GetEnrollCredentials())
	}
}

func TestDisabledBlockKeepsItsSecretsWriteOnly(t *testing.T) {
	prev := issuingWithProtocols(t)
	got, err := FromProtoOver(readBackOff(prev), prev)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	pb := got.ToProtoRedacted()
	if s := pb.GetPki().GetAcme().GetExternalAccountKeys()[0].GetHmacKeyBase64(); s != "" {
		t.Errorf("GetConfig returned a disabled block's EAB secret %q", s)
	}
	if s := pb.GetPki().GetEst().GetEnrollCredentials()[0].GetPasswordSha256(); s != "" {
		t.Errorf("GetConfig returned a disabled block's password digest %q", s)
	}

	// The node stores the kept secrets, so the block can be switched back on.
	full := got.ToProto()
	if full.GetPki().GetAcme().GetExternalAccountKeys()[0].GetHmacKeyBase64() != validEABKey() {
		t.Error("the disabled ACME block did not keep the stored EAB secret")
	}
	if full.GetPki().GetEst().GetEnrollCredentials()[0].GetPasswordSha256() != testPasswordDigest() {
		t.Error("the disabled EST block did not keep the stored password digest")
	}

	// A blank secret for an identifier the node never stored is still refused.
	bad := readBackOff(prev)
	bad.Pki.Acme.ExternalAccountKeys = append(bad.Pki.Acme.ExternalAccountKeys,
		&cryptosv1.AcmeExternalAccountKey{KeyId: "new-team"})
	if _, err := FromProtoOver(bad, prev); err == nil || !strings.Contains(err.Error(), `"new-team"`) {
		t.Errorf("a blank secret for an unknown key_id in a disabled block = %v, want a refusal naming it", err)
	}
}

// The Fleet Manager switches a protocol on by reading the config back and
// flipping enabled, so a read-back of a disabled block has to be enough.
func TestSwitchOnFromReadBack(t *testing.T) {
	on := issuingWithProtocols(t)
	off, err := FromProtoOver(readBackOff(on), on)
	if err != nil {
		t.Fatalf("FromProtoOver (off): %v", err)
	}

	pb := off.ToProtoRedacted()
	pb.Pki.Acme.Enabled = true
	pb.Pki.Est.Enabled = true
	got, err := FromProtoOver(pb, off)
	if err != nil {
		t.Fatalf("FromProtoOver (on from the read-back): %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("the switched-on config does not validate: %v", err)
	}
	if !reflect.DeepEqual(got.PKI.ACME, on.PKI.ACME) {
		t.Errorf("ACME after switching back on = %+v, want %+v", got.PKI.ACME, on.PKI.ACME)
	}
	if !reflect.DeepEqual(got.PKI.EST, on.PKI.EST) {
		t.Errorf("EST after switching back on = %+v, want %+v", got.PKI.EST, on.PKI.EST)
	}
	if !NeedsReboot(off, got) {
		t.Error("switching a protocol back on was classified as live")
	}
}

// An empty enabled=false block is still how a client switches a protocol off
// and drops its settings.
func TestEmptyDisabledBlockDropsSettings(t *testing.T) {
	prev := issuingWithProtocols(t)
	pb := prev.ToProto()
	pb.Pki.Acme = &cryptosv1.Acme{Enabled: false}
	got, err := FromProtoOver(pb, prev)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	if a := got.ToProto().GetPki().GetAcme(); a.GetEnabled() || a.GetBaseUrl() != "" || a.GetProfile() != "" {
		t.Errorf("an empty enabled=false block kept settings: %v", a)
	}
}

// An absent block keeps what the node stores, disabled settings included.
func TestAbsentBlockKeepsDisabledSettings(t *testing.T) {
	on := issuingWithProtocols(t)
	off, err := FromProtoOver(readBackOff(on), on)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	pb := off.ToProto()
	pb.Pki.Acme, pb.Pki.Est = nil, nil
	got, err := FromProtoOver(pb, off)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	if got.ToProto().GetPki().GetAcme().GetBaseUrl() != on.PKI.ACME.BaseURL ||
		got.ToProto().GetPki().GetEst().GetProfile() != on.PKI.EST.Profile {
		t.Error("an apply without the blocks dropped the disabled settings")
	}
}

func TestDisabledBlockRoundTripsThroughYAML(t *testing.T) {
	on := issuingWithProtocols(t)
	off, err := FromProtoOver(readBackOff(on), on)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	raw, err := off.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(raw), "enabled: false") {
		t.Fatalf("the stored YAML does not mark the disabled blocks:\n%s", raw)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse of the stored YAML: %v", err)
	}
	if got.PKI.ACME != nil || got.PKI.EST != nil {
		t.Fatalf("a stored disabled block parsed as on: acme=%+v est=%+v", got.PKI.ACME, got.PKI.EST)
	}
	if !proto.Equal(got.ToProto(), off.ToProto()) {
		t.Errorf("the YAML round trip changed the config:\n got %v\nwant %v", got.ToProto(), off.ToProto())
	}
}

func TestYAMLEnabledFlag(t *testing.T) {
	block := `  acme:
    enabled: %s
    base_url: https://ca.example.org/acme
    profile: leaf-server
    allow_anonymous_accounts: true
`
	withProfile := string(issuingYAML(t)) + `  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
`
	for _, tc := range []struct {
		flag string
		on   bool
	}{{"true", true}, {"false", false}} {
		t.Run(tc.flag, func(t *testing.T) {
			c, err := Parse([]byte(withProfile + strings.Replace(block, "%s", tc.flag, 1)))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if (c.PKI.ACME != nil) != tc.on {
				t.Errorf("enabled: %s parsed as on=%t", tc.flag, c.PKI.ACME != nil)
			}
		})
	}
	// A block without the flag is on, as stored configs written before the
	// flag existed are.
	noFlag := strings.Replace(block, "    enabled: %s\n", "", 1)
	c, err := Parse([]byte(withProfile + noFlag))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.PKI.ACME == nil {
		t.Error("an acme block without enabled parsed as off")
	}
	if _, err := Parse([]byte(withProfile + strings.Replace(block, "%s", "maybe", 1))); err == nil {
		t.Error("a non-boolean enabled was accepted")
	}
}

// Nothing reads a disabled block at boot, so changing only its settings is
// not a reboot.
func TestDisabledSettingsChangeIsLive(t *testing.T) {
	on := issuingWithProtocols(t)
	off, err := FromProtoOver(readBackOff(on), on)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	pb := off.ToProto()
	pb.Pki.Acme.HttpPort = 9000
	next, err := FromProtoOver(pb, off)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	if NeedsReboot(off, next) {
		t.Error("a settings change to a disabled block asked for a reboot")
	}
}

func TestRootStillRefusesAnEnabledProtocol(t *testing.T) {
	on := issuingWithProtocols(t)
	off, err := FromProtoOver(readBackOff(on), on)
	if err != nil {
		t.Fatalf("FromProtoOver: %v", err)
	}
	off.Role.Kind = RoleRoot
	off.PKI.Parent = nil
	off.PKI.RootValidityYears = 20
	if err := off.Validate(); err != nil {
		t.Fatalf("a root holding only disabled blocks was refused: %v", err)
	}

	for _, name := range []string{"acme", "est"} {
		t.Run(name, func(t *testing.T) {
			pb := off.ToProtoRedacted()
			if name == "acme" {
				pb.Pki.Acme.Enabled = true
			} else {
				pb.Pki.Est.Enabled = true
			}
			got, err := FromProtoOver(pb, off)
			if err != nil {
				t.Fatalf("FromProtoOver: %v", err)
			}
			err = got.Validate()
			if err == nil || !strings.Contains(err.Error(), "pki."+name) || !strings.Contains(err.Error(), "root") {
				t.Errorf("switching %s on at a root = %v, want a root-role refusal", name, err)
			}
		})
	}
}
