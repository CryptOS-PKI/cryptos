package config

/*
Apache License 2.0

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
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestValidityPolicyYAMLAndProtoRoundTrip(t *testing.T) {
	var p CertificateProfile
	dec := yaml.NewDecoder(strings.NewReader("name: vmca\nvalidity_policy: reject\n"))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.ValidityPolicy != ValidityPolicyReject {
		t.Fatalf("validity_policy decoded as %q, want %q", p.ValidityPolicy, ValidityPolicyReject)
	}

	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	leaf := kdcProfile()
	leaf.ValidityPolicy = ValidityPolicyReject
	cfg.PKI.Profiles = []CertificateProfile{leaf}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	pb := cfg.ToProto()
	if got := pb.GetPki().GetProfiles()[0].GetValidityPolicy(); got != "reject" {
		t.Fatalf("ToProto validity_policy = %q, want reject", got)
	}
	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if back.PKI.Profiles[0].ValidityPolicy != ValidityPolicyReject {
		t.Fatal("FromProto dropped validity_policy")
	}
}

func TestValidityPolicyValidation(t *testing.T) {
	tests := []struct {
		policy  ValidityPolicy
		wantErr bool
	}{
		{policy: "", wantErr: false},
		{policy: ValidityPolicyCap, wantErr: false},
		{policy: ValidityPolicyReject, wantErr: false},
		{policy: "truncate", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(string(tc.policy), func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			prof := kdcProfile()
			prof.ValidityPolicy = tc.policy
			cfg.PKI.Profiles = []CertificateProfile{prof}
			err = cfg.Validate()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "validity_policy") {
					t.Fatalf("Validate = %v, want a validity_policy error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestProfileValidityWarnings(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	issuer := &x509.Certificate{NotAfter: time.Date(2041, 9, 21, 0, 0, 0, 0, time.UTC)}

	short := kdcProfile()
	short.Name = "fits"
	short.ValidityDays = 365
	long := kdcProfile()
	long.Name = "vmca-sub"
	long.ValidityDays = 7300
	strict := long
	strict.Name = "vmca-strict"
	strict.ValidityPolicy = ValidityPolicyReject

	cfg := &Config{}
	cfg.PKI.Profiles = []CertificateProfile{short, long, strict}
	got := cfg.ProfileValidityWarnings(issuer, now)
	if len(got) != 2 {
		t.Fatalf("got %d warnings, want 2: %q", len(got), got)
	}
	for i, name := range []string{"vmca-sub", "vmca-strict"} {
		for _, want := range []string{name, "7300", "2041-09-21"} {
			if !strings.Contains(got[i], want) {
				t.Errorf("warning %q does not mention %q", got[i], want)
			}
		}
	}
	if !strings.Contains(got[0], "capped") || !strings.Contains(got[1], "refused") {
		t.Errorf("warnings do not name the policy outcome: %q", got)
	}

	if w := cfg.ProfileValidityWarnings(nil, now); w != nil {
		t.Errorf("no issuer yet: got %q, want none", w)
	}
}
