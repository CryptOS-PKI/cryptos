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
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// kdcProfile is a domain controller KDC certificate profile: dotted-OID EKUs
// for Smart Card Logon and KDC Authentication, and the krbtgt principal SAN.
func kdcProfile() CertificateProfile {
	return CertificateProfile{
		Name:         "kdc-dc01",
		KeyAlg:       RootKeyRSA3072,
		ValidityDays: 365,
		KeyUsage:     []string{"digital_signature", "key_encipherment"},
		ExtKeyUsage:  []string{"server_auth", "client_auth", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.5"},
		SANs: SubjectAltNames{
			DNS:           []string{"dc01.ad.example.org", "ad.example.org"},
			KRB5Principal: []string{"krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG"},
			UPN:           []string{"dc01$@ad.example.org"},
		},
	}
}

func TestSANsYAMLFieldNames(t *testing.T) {
	var s SubjectAltNames
	doc := "dns: [ad.example.org]\nkrb5_principal: [\"krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG\"]\nupn: [user@ad.example.org]\n"
	dec := yaml.NewDecoder(strings.NewReader(doc))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := SubjectAltNames{
		DNS:           []string{"ad.example.org"},
		KRB5Principal: []string{"krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG"},
		UPN:           []string{"user@ad.example.org"},
	}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("decoded %#v, want %#v", s, want)
	}
}

func TestKDCProfileValidatesAndSurvivesProtoRoundTrip(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = []CertificateProfile{kdcProfile()}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pb := cfg.ToProto()
	sans := pb.GetPki().GetProfiles()[0].GetSans()
	if !reflect.DeepEqual(sans.GetKrb5Principal(), kdcProfile().SANs.KRB5Principal) || !reflect.DeepEqual(sans.GetUpn(), kdcProfile().SANs.UPN) {
		t.Fatalf("ToProto sans = %v", sans)
	}
	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if !reflect.DeepEqual(back.PKI.Profiles, cfg.PKI.Profiles) {
		t.Fatalf("round-trip mismatch:\n got  %#v\n want %#v", back.PKI.Profiles, cfg.PKI.Profiles)
	}
}

func TestValidateProfileRejectsBadADFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*CertificateProfile)
		wantSub string
	}{
		{"malformed EKU OID", func(p *CertificateProfile) { p.ExtKeyUsage = []string{"1.3.6.01.5"} }, "ext_key_usage"},
		{"unknown EKU name", func(p *CertificateProfile) { p.ExtKeyUsage = []string{"kdc_auth"} }, "ext_key_usage"},
		{"duplicate EKU", func(p *CertificateProfile) { p.ExtKeyUsage = []string{"client_auth", "1.3.6.1.5.5.7.3.2"} }, "ext_key_usage"},
		{"principal without realm", func(p *CertificateProfile) { p.SANs.KRB5Principal = []string{"krbtgt/AD.EXAMPLE.ORG"} }, "sans.krb5_principal[0]"},
		{"principal with escape", func(p *CertificateProfile) { p.SANs.KRB5Principal = []string{`a\@b@AD.EXAMPLE.ORG`} }, "sans.krb5_principal[0]"},
		{"upn without suffix", func(p *CertificateProfile) { p.SANs.UPN = []string{"administrator"} }, "sans.upn[0]"},
		{"upn with space", func(p *CertificateProfile) { p.SANs.UPN = []string{"a b@ad.example.org"} }, "sans.upn[0]"},
		{"otherName with raw SAN extension", func(p *CertificateProfile) {
			p.ExtraExtensions = []X509Extension{{OID: "2.5.29.17", Value: []byte{0x30, 0x00}}}
		}, "subjectAltName"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			p := kdcProfile()
			tc.mutate(&p)
			cfg.PKI.Profiles = []CertificateProfile{p}
			err = cfg.Validate()
			if err == nil {
				t.Fatal("expected validation failure")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestAllowRequestSANsYAMLAndProtoRoundTrip(t *testing.T) {
	var p CertificateProfile
	dec := yaml.NewDecoder(strings.NewReader("name: ldaps-dc\nallow_request_sans: true\n"))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !p.AllowRequestSANs {
		t.Fatal("allow_request_sans did not decode")
	}

	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	leaf := kdcProfile()
	leaf.AllowRequestSANs = true
	cfg.PKI.Profiles = []CertificateProfile{leaf}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pb := cfg.ToProto()
	if !pb.GetPki().GetProfiles()[0].GetAllowRequestSans() {
		t.Fatal("ToProto dropped allow_request_sans")
	}
	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if !back.PKI.Profiles[0].AllowRequestSANs {
		t.Fatal("FromProto dropped allow_request_sans")
	}
}

// Operator-asserted SANs apply to leaf issuance only; a CA profile that opts
// in is a configuration mistake and is refused.
func TestAllowRequestSANsRejectedOnCAProfile(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = []CertificateProfile{{
		Name:             "sub-ca",
		KeyAlg:           RootKeyECDSAP384,
		ValidityDays:     365,
		BasicConstraints: BasicConstraints{IsCA: true},
		KeyUsage:         []string{"cert_sign", "crl_sign"},
		AllowRequestSANs: true,
	}}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "allow_request_sans") {
		t.Fatalf("Validate = %v, want an allow_request_sans error", err)
	}
}
