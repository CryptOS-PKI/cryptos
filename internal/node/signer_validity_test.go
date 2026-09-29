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
	"time"

	"google.golang.org/grpc/codes"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// validityConfig is caProfileConfig with every profile set to policy.
func validityConfig(policy config.ValidityPolicy) *config.Config {
	cfg := caProfileConfig(config.RoleIntermediate)
	for i := range cfg.PKI.Profiles {
		cfg.PKI.Profiles[i].ValidityPolicy = policy
	}
	return cfg
}

func TestSignSubordinateCapsValidityAtIssuer(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(validityConfig(""), &closed)
	s := NewCASigner(load, issuer, get)

	chainDER, _, vcap, err := s.SignSubordinate(context.Background(), makeCSR(t, "Example Subordinate CA G1"), "sub-ca")
	if err != nil {
		t.Fatalf("SignSubordinate: %v", err)
	}
	child, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		t.Fatalf("parse child: %v", err)
	}
	if !child.NotAfter.Equal(f.issuerCert.NotAfter) {
		t.Fatalf("child NotAfter = %s, want issuer NotAfter %s", child.NotAfter, f.issuerCert.NotAfter)
	}
	if vcap == nil {
		t.Fatal("no validity cap reported")
	}
	if !vcap.Effective.Equal(f.issuerCert.NotAfter) {
		t.Errorf("cap Effective = %s, want %s", vcap.Effective, f.issuerCert.NotAfter)
	}
	if wantMin := time.Now().Add(3649 * 24 * time.Hour); vcap.Requested.Before(wantMin) {
		t.Errorf("cap Requested = %s, want the profile's 3650 days out", vcap.Requested)
	}
}

func TestIssueLeafWithRequestSANsCapsValidityAtIssuer(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(validityConfig(config.ValidityPolicyCap), &closed)
	s := NewCASigner(load, issuer, get)

	certDER, vcap, err := s.IssueLeafWithRequestSANs(context.Background(), makeCSR(t, "leaf.example.org"), "leaf-server", nil)
	if err != nil {
		t.Fatalf("IssueLeafWithRequestSANs: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if !leaf.NotAfter.Equal(f.issuerCert.NotAfter) {
		t.Fatalf("leaf NotAfter = %s, want issuer NotAfter %s", leaf.NotAfter, f.issuerCert.NotAfter)
	}
	if vcap == nil || !vcap.Effective.Equal(f.issuerCert.NotAfter) {
		t.Fatalf("cap = %+v, want Effective %s", vcap, f.issuerCert.NotAfter)
	}
}

func TestIssuanceInsideIssuerLifetimeReportsNoCap(t *testing.T) {
	f := newSignerFixtureValidFor(t, 20*365*24*time.Hour)
	var closed bool
	load, issuer, get := f.loaders(validityConfig(config.ValidityPolicyReject), &closed)
	s := NewCASigner(load, issuer, get)

	certDER, vcap, err := s.IssueLeafWithRequestSANs(context.Background(), makeCSR(t, "leaf.example.org"), "leaf-server", nil)
	if err != nil {
		t.Fatalf("IssueLeafWithRequestSANs: %v", err)
	}
	if vcap != nil {
		t.Fatalf("cap = %+v, want none", vcap)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got < 89*24*time.Hour {
		t.Fatalf("leaf lifetime = %s, want the profile's 90 days", got)
	}
	if _, _, vcap, err := s.SignSubordinate(context.Background(), makeCSR(t, "Example Subordinate CA G1"), "sub-ca"); err != nil || vcap != nil {
		t.Fatalf("SignSubordinate = cap %+v, err %v; want no cap, no error", vcap, err)
	}
}

// Under reject, issuance past the issuer's notAfter fails before the CA key is
// loaded and nothing is recorded, on every issuance path.
func TestValidityPolicyRejectRefusesIssuance(t *testing.T) {
	f := newSignerFixture(t)
	wantDate := f.issuerCert.NotAfter.UTC().Format(time.DateOnly)
	requested := time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.DateOnly)

	calls := map[string]func(s *CASigner) error{
		"IssueLeafWithRequestSANs": func(s *CASigner) error {
			_, _, err := s.IssueLeafWithRequestSANs(context.Background(), makeCSR(t, "leaf.example.org"), "leaf-server", nil)
			return err
		},
		"IssueLeafForNames": func(s *CASigner) error {
			_, _, err := s.IssueLeafForNames(context.Background(), makeCSR(t, "leaf.example.org"), "leaf-server", []string{"leaf.example.org"})
			return err
		},
		"SignSubordinate": func(s *CASigner) error {
			_, _, _, err := s.SignSubordinate(context.Background(), makeCSR(t, "Example Subordinate CA G1"), "sub-ca")
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			var closed, recorded bool
			load, issuer, get := f.loaders(validityConfig(config.ValidityPolicyReject), &closed)
			s := NewCASigner(load, issuer, get).WithRecorder(func(context.Context, []byte, string) error {
				recorded = true
				return nil
			})
			err := call(s)
			wantCode(t, err, codes.FailedPrecondition)
			if !strings.Contains(err.Error(), wantDate) {
				t.Errorf("error %q does not name the issuer notAfter %s", err, wantDate)
			}
			if name == "IssueLeafWithRequestSANs" && !strings.Contains(err.Error(), requested) {
				t.Errorf("error %q does not name the requested notAfter %s", err, requested)
			}
			if closed || recorded {
				t.Errorf("key loaded = %t, recorded = %t; want neither", closed, recorded)
			}
		})
	}
}
