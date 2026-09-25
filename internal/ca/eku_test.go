package ca

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
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"testing"
)

func TestParseOID(t *testing.T) {
	good := map[string]asn1.ObjectIdentifier{
		"1.3.6.1.5.2.3.5":        {1, 3, 6, 1, 5, 2, 3, 5},
		"1.3.6.1.4.1.311.20.2.2": {1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
		"2.5.29.37.0":            {2, 5, 29, 37, 0},
		"2.999.1":                {2, 999, 1},
		"0.39":                   {0, 39},
	}
	for in, want := range good {
		got, err := ParseOID(in)
		if err != nil {
			t.Errorf("ParseOID(%q): %v", in, err)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("ParseOID(%q) = %v, want %v", in, got, want)
		}
	}
	for _, in := range []string{
		"", "1", "1.", ".1.2", "1..2", "1.2.", "1.3.6.01", "01.3", "3.1", "1.40", "0.40",
		"1.3.a", "1.3.-6", "1.3.+6", " 1.3.6", "1.3.6 ", "1.3.6.2147483648", "1.3.6.99999999999999999999",
	} {
		if _, err := ParseOID(in); err == nil {
			t.Errorf("ParseOID(%q): expected an error", in)
		}
	}
}

func TestParseExtKeyUsageAcceptsOIDs(t *testing.T) {
	eku, unknown, err := ParseExtKeyUsage([]string{
		"server_auth",
		"1.3.6.1.5.5.7.3.2",      // clientAuth, builtin
		"1.3.6.1.4.1.311.20.2.2", // Smart Card Logon
		"1.3.6.1.5.2.3.5",        // KDC Authentication
	})
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}
	if !slices.Equal(eku, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("builtin = %v, want [ServerAuth ClientAuth]", eku)
	}
	want := []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}, {1, 3, 6, 1, 5, 2, 3, 5}}
	if len(unknown) != len(want) || !unknown[0].Equal(want[0]) || !unknown[1].Equal(want[1]) {
		t.Fatalf("unknown = %v, want %v", unknown, want)
	}
}

func TestParseExtKeyUsageRejects(t *testing.T) {
	for _, in := range [][]string{
		{"bogus"},
		{"Server_Auth"},
		{"1.3.6.01.5"},
		{"server_auth", "1.3.6.1.5.5.7.3.1"},   // the same usage twice
		{"1.3.6.1.5.2.3.5", "1.3.6.1.5.2.3.5"}, // duplicate OID
		{""},
	} {
		if _, _, err := ParseExtKeyUsage(in); err == nil {
			t.Errorf("ParseExtKeyUsage(%q): expected an error", in)
		}
	}
}

// A dotted OID Go does not know lands in UnknownExtKeyUsage and is encoded in
// the certificate after the builtin usages.
func TestSignStampsUnknownExtKeyUsage(t *testing.T) {
	issuerCert, issuerSigner := selfSignedIssuer(t)
	leafKey := p384Key(t)
	eku, unknown, err := ParseExtKeyUsage([]string{"client_auth", "1.3.6.1.5.2.3.5"})
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}
	p := leafProfile()
	p.ExtKeyUsage = eku
	p.UnknownExtKeyUsage = unknown
	der, _, err := Sign(p, &leafKey.PublicKey, issuerCert, issuerSigner)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("ExtKeyUsage = %v", cert.ExtKeyUsage)
	}
	if len(cert.UnknownExtKeyUsage) != 1 || !cert.UnknownExtKeyUsage[0].Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}) {
		t.Fatalf("UnknownExtKeyUsage = %v", cert.UnknownExtKeyUsage)
	}
}
