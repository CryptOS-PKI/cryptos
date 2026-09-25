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
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// requestSANsConfig is kdcConfig with the leaf profile opted in (or not) to
// operator-asserted SANs, so an override has otherNames and typed SANs to clear.
func requestSANsConfig(allow bool) *config.Config {
	cfg := kdcConfig()
	for i := range cfg.PKI.Profiles {
		if cfg.PKI.Profiles[i].Name == "leaf-server" {
			cfg.PKI.Profiles[i].AllowRequestSANs = allow
			cfg.PKI.Profiles[i].SANs.IP = []string{"192.0.2.10"}
			cfg.PKI.Profiles[i].SANs.Email = []string{"pki@example.org"}
		}
	}
	return cfg
}

func TestIssueLeafWithRequestSANsReplacesProfileSANs(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(requestSANsConfig(true), &closed)
	s := NewCASigner(load, issuer, get)

	certDER, err := s.IssueLeafWithRequestSANs(context.Background(), makeCSR(t, "dc02.ad.example.org"), "leaf-server",
		[]string{"DC02.ad.example.org", "ad.example.org"})
	if err != nil {
		t.Fatalf("IssueLeafWithRequestSANs: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	// Exactly the requested names (DNS is case-insensitive; stamped lower-case),
	// and nothing from the profile's SAN set.
	if !slices.Equal(leaf.DNSNames, []string{"dc02.ad.example.org", "ad.example.org"}) {
		t.Fatalf("DNSNames = %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		t.Fatalf("profile SANs survived: ip=%v email=%v uri=%v", leaf.IPAddresses, leaf.EmailAddresses, leaf.URIs)
	}
	if types := otherNameTypes(t, leaf); len(types) != 0 {
		t.Fatalf("profile otherNames survived: %v", types)
	}
	// Everything else still comes from the profile.
	if len(leaf.UnknownExtKeyUsage) != 2 {
		t.Fatalf("UnknownExtKeyUsage = %v, want the profile's two", leaf.UnknownExtKeyUsage)
	}
}

// Without the opt-in, asserted names are refused before the CA key is touched,
// and existing profiles keep their behaviour.
func TestIssueLeafWithRequestSANsRequiresOptIn(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(requestSANsConfig(false), &closed)
	s := NewCASigner(load, issuer, get)

	_, err := s.IssueLeafWithRequestSANs(context.Background(), makeCSR(t, "x"), "leaf-server", []string{"dc02.ad.example.org"})
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "allow_request_sans") {
		t.Fatalf("error %q does not name allow_request_sans", err)
	}
	if closed {
		t.Fatal("the CA key was loaded for a refused request")
	}
}

// No names means the profile's SANs, with or without the opt-in.
func TestIssueLeafWithRequestSANsWithoutNamesKeepsProfile(t *testing.T) {
	for _, allow := range []bool{false, true} {
		f := newSignerFixture(t)
		var closed bool
		load, issuer, get := f.loaders(requestSANsConfig(allow), &closed)
		s := NewCASigner(load, issuer, get)

		certDER, err := s.IssueLeafWithRequestSANs(context.Background(), makeCSR(t, "x"), "leaf-server", nil)
		if err != nil {
			t.Fatalf("allow=%v: %v", allow, err)
		}
		leaf, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		if !slices.Equal(leaf.DNSNames, []string{"dc01.ad.example.org", "ad.example.org"}) || len(otherNameTypes(t, leaf)) != 2 {
			t.Fatalf("allow=%v: profile SANs not stamped: dns=%v", allow, leaf.DNSNames)
		}
	}
}

func TestIssueLeafWithRequestSANsRejectsBadNames(t *testing.T) {
	tooMany := make([]string, maxRequestDNSNames+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("h%d.example.org", i)
	}
	for _, tc := range []struct {
		name  string
		names []string
	}{
		{"empty", []string{""}},
		{"wildcard", []string{"*.ad.example.org"}},
		{"single label", []string{"dc02"}},
		{"trailing dot", []string{"dc02.ad.example.org."}},
		{"underscore", []string{"dc_02.ad.example.org"}},
		{"leading hyphen", []string{"-dc02.ad.example.org"}},
		{"long label", []string{strings.Repeat("a", 64) + ".example.org"}},
		{"duplicate", []string{"dc02.ad.example.org", "DC02.ad.example.org"}},
		{"too many", tooMany},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSignerFixture(t)
			var closed bool
			load, issuer, get := f.loaders(requestSANsConfig(true), &closed)
			s := NewCASigner(load, issuer, get)
			_, err := s.IssueLeafWithRequestSANs(context.Background(), makeCSR(t, "x"), "leaf-server", tc.names)
			wantCode(t, err, codes.InvalidArgument)
			if closed {
				t.Fatal("the CA key was loaded for a rejected request")
			}
		})
	}
}
