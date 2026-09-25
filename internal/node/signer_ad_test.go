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
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// kdcConfig returns the signer fixture config with its leaf profile turned into
// a KDC profile: Smart Card Logon and KDC Authentication by OID, and the
// krbtgt principal plus a UPN as otherName SANs next to the DNS names.
func kdcConfig() *config.Config {
	cfg := caProfileConfig(config.RoleIssuing)
	for i := range cfg.PKI.Profiles {
		if cfg.PKI.Profiles[i].Name == "leaf-server" {
			p := &cfg.PKI.Profiles[i]
			p.ExtKeyUsage = []string{"server_auth", "client_auth", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.5"}
			p.SANs.DNS = []string{"dc01.ad.example.org", "ad.example.org"}
			p.SANs.KRB5Principal = []string{"krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG"}
			p.SANs.UPN = []string{"dc01$@ad.example.org"}
		}
	}
	return cfg
}

// otherNameTypes decodes the SAN extension of cert and returns the type-id of
// every otherName entry, failing if there is not exactly one SAN extension.
func otherNameTypes(t *testing.T, cert *x509.Certificate) []asn1.ObjectIdentifier {
	t.Helper()
	var sans [][]byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			sans = append(sans, e.Value)
		}
	}
	if len(sans) != 1 {
		t.Fatalf("got %d subjectAltName extensions, want 1", len(sans))
	}
	var names []asn1.RawValue
	if _, err := asn1.Unmarshal(sans[0], &names); err != nil {
		t.Fatalf("decode SAN: %v", err)
	}
	var out []asn1.ObjectIdentifier
	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific || n.Tag != 0 {
			continue
		}
		var on struct {
			TypeID asn1.ObjectIdentifier
			Value  asn1.RawValue
		}
		if _, err := asn1.UnmarshalWithParams(n.FullBytes, &on, "tag:0"); err != nil {
			t.Fatalf("decode otherName: %v", err)
		}
		out = append(out, on.TypeID)
	}
	return out
}

func TestIssueLeafStampsKDCProfile(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(kdcConfig(), &closed)
	s := NewCASigner(load, issuer, get)

	certDER, err := s.IssueLeaf(context.Background(), makeCSR(t, "dc01.ad.example.org"), "leaf-server")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.ExtKeyUsage) != 2 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ExtKeyUsage = %v, want [ServerAuth ClientAuth]", leaf.ExtKeyUsage)
	}
	wantEKU := []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}, {1, 3, 6, 1, 5, 2, 3, 5}}
	if len(leaf.UnknownExtKeyUsage) != 2 || !leaf.UnknownExtKeyUsage[0].Equal(wantEKU[0]) || !leaf.UnknownExtKeyUsage[1].Equal(wantEKU[1]) {
		t.Fatalf("UnknownExtKeyUsage = %v, want %v", leaf.UnknownExtKeyUsage, wantEKU)
	}
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "dc01.ad.example.org" || leaf.DNSNames[1] != "ad.example.org" {
		t.Fatalf("DNSNames = %v", leaf.DNSNames)
	}
	types := otherNameTypes(t, leaf)
	if len(types) != 2 || !types[0].Equal(ca.OIDKRB5PrincipalName) || !types[1].Equal(ca.OIDMicrosoftUPN) {
		t.Fatalf("otherName types = %v, want [KRB5PrincipalName UPN]", types)
	}
}

// The enrolment override replaces the whole SAN set: an ACME or EST client
// proved control of DNS names, not of the profile's Kerberos principal or UPN.
func TestIssueLeafForNamesClearsOtherNames(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(kdcConfig(), &closed)
	s := NewCASigner(load, issuer, get)

	chainDER, _, err := s.IssueLeafForNames(context.Background(), makeCSR(t, "x"), "leaf-server", []string{"web.example.org"})
	if err != nil {
		t.Fatalf("IssueLeafForNames: %v", err)
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "web.example.org" {
		t.Fatalf("DNSNames = %v, want [web.example.org]", leaf.DNSNames)
	}
	if types := otherNameTypes(t, leaf); len(types) != 0 {
		t.Fatalf("otherNames survived the override: %v", types)
	}
}
