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
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// TestIssueLeafForNamesOverridesProfileSANs is the seam the enrolment
// protocols depend on: the profile's static SAN list is replaced by the names
// the caller validated, and nothing else about the certificate moves.
func TestIssueLeafForNamesOverridesProfileSANs(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), &closed)
	s := NewCASigner(load, issuer, get)

	want := []string{"web.example.org", "api.example.org"}
	chainDER, chainPEM, err := s.IssueLeafForNames(context.Background(), makeCSR(t, "ignored"), "leaf-server", want)
	if err != nil {
		t.Fatalf("IssueLeafForNames: %v", err)
	}
	if len(chainDER) < 1 {
		t.Fatal("IssueLeafForNames returned an empty chain")
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != want[0] || leaf.DNSNames[1] != want[1] {
		t.Fatalf("leaf SANs = %v, want %v", leaf.DNSNames, want)
	}
	// The profile's own SAN must be gone, not merged in alongside.
	for _, n := range leaf.DNSNames {
		if n == "node.example" {
			t.Fatal("the profile SAN survived the override")
		}
	}
	if leaf.IsCA {
		t.Fatal("leaf certificate must not be a CA")
	}
	// The profile still owns everything else.
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("extended key usage = %v, want serverAuth from the profile", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("key usage = %v, want digitalSignature from the profile", leaf.KeyUsage)
	}
	if !strings.Contains(chainPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("chain PEM does not look like PEM: %q", chainPEM)
	}
}

// A nil name list leaves the profile in charge, so IssueLeafForNames is a
// superset of IssueLeaf rather than a different policy.
func TestIssueLeafForNamesWithoutOverrideKeepsProfileSANs(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), &closed)
	s := NewCASigner(load, issuer, get)

	chainDER, _, err := s.IssueLeafForNames(context.Background(), makeCSR(t, "x"), "leaf-server", nil)
	if err != nil {
		t.Fatalf("IssueLeafForNames: %v", err)
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "node.example" {
		t.Fatalf("leaf SANs = %v, want the profile's [node.example]", leaf.DNSNames)
	}
}

// An override must not leave a stale IP, email or URI SAN behind: those come
// from the profile too, and the caller only vouched for DNS names.
func TestIssueLeafForNamesClearsOtherSANTypes(t *testing.T) {
	f := newSignerFixture(t)
	cfg := caProfileConfig(config.RoleIssuing)
	for i := range cfg.PKI.Profiles {
		if cfg.PKI.Profiles[i].Name == "leaf-server" {
			cfg.PKI.Profiles[i].SANs.IP = []string{"10.0.0.1"}
			cfg.PKI.Profiles[i].SANs.Email = []string{"ops@example.org"}
			cfg.PKI.Profiles[i].SANs.URI = []string{"https://example.org/id"}
		}
	}
	var closed bool
	load, issuer, get := f.loaders(cfg, &closed)
	s := NewCASigner(load, issuer, get)

	chainDER, _, err := s.IssueLeafForNames(context.Background(), makeCSR(t, "x"), "leaf-server",
		[]string{"web.example.org"})
	if err != nil {
		t.Fatalf("IssueLeafForNames: %v", err)
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		t.Fatalf("non-DNS SANs survived the override: ip=%v email=%v uri=%v",
			leaf.IPAddresses, leaf.EmailAddresses, leaf.URIs)
	}
}

// The override path shares every gate with IssueLeaf, so a CA profile is
// still refused through it.
func TestIssueLeafForNamesRejectsCAProfile(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), &closed)
	s := NewCASigner(load, issuer, get)

	_, _, err := s.IssueLeafForNames(context.Background(), makeCSR(t, "x"), "sub-ca", []string{"web.example.org"})
	wantCode(t, err, codes.InvalidArgument)
}

// A ROOT node must refuse leaf issuance through the override path too,
// without the irreversible acknowledgement.
func TestIssueLeafForNamesRefusedOnUnacknowledgedRoot(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleRoot), &closed)
	s := NewCASigner(load, issuer, get)

	_, _, err := s.IssueLeafForNames(context.Background(), makeCSR(t, "x"), "leaf-server",
		[]string{"web.example.org"})
	wantCode(t, err, codes.FailedPrecondition)
}
