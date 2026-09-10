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
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func testPasswordDigest() string {
	sum := sha256.Sum256([]byte("est-test-password-obviously-not-a-secret"))
	return hex.EncodeToString(sum[:])
}

// validEST is a block that must pass, so each rejection below differs from a
// passing config in exactly one way.
func validEST() *EST {
	return &EST{
		Hostnames:                 []string{"est.example.org"},
		Profile:                   "leaf-server",
		AllowedIdentifierSuffixes: []string{"example.org"},
		EnrollCredentials: []ESTEnrollCredential{
			{Username: "switch-fleet", PasswordSHA256: testPasswordDigest()},
		},
	}
}

func TestValidateESTAccepts(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = acmeTestProfiles()
	cfg.PKI.EST = validEST()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid EST block was rejected: %v", err)
	}
}

func TestValidateESTAbsentIsFine(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.PKI.EST != nil {
		t.Fatal("EST must default to disabled")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateESTRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*EST)
		expect string
	}{
		{"no hostnames", func(e *EST) { e.Hostnames = nil }, "hostnames"},
		{"blank hostname", func(e *EST) { e.Hostnames = []string{" "} }, "hostnames[0]"},
		{"label with a slash", func(e *EST) { e.Label = "a/b" }, "label"},
		{"no profile", func(e *EST) { e.Profile = "" }, "profile"},
		{"unknown profile", func(e *EST) { e.Profile = "nope" }, "no profile named"},
		{"ca profile", func(e *EST) { e.Profile = "sub-ca" }, "CA profile"},
		{
			// The security-relevant default: credentials without an
			// allowlist and without the explicit override must not validate.
			name:   "credentials with no allowlist and no override",
			mutate: func(e *EST) { e.AllowedIdentifierSuffixes = nil },
			expect: "allowed_identifier_suffixes",
		},
		{
			name:   "credential with no username",
			mutate: func(e *EST) { e.EnrollCredentials[0].Username = "" },
			expect: "username",
		},
		{
			name: "duplicate username",
			mutate: func(e *EST) {
				e.EnrollCredentials = append(e.EnrollCredentials,
					ESTEnrollCredential{Username: "switch-fleet", PasswordSHA256: testPasswordDigest()})
			},
			expect: "duplicated",
		},
		{
			name:   "digest is not hex",
			mutate: func(e *EST) { e.EnrollCredentials[0].PasswordSHA256 = "not hex" },
			expect: "password_sha256",
		},
		{
			// A digest of the wrong length is a different hash, not a
			// SHA-256, and would never match.
			name:   "digest is the wrong length",
			mutate: func(e *EST) { e.EnrollCredentials[0].PasswordSHA256 = "abcd" },
			expect: "password_sha256",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg.PKI.Profiles = acmeTestProfiles()
			e := validEST()
			tc.mutate(e)
			cfg.PKI.EST = e

			err = cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("error %q does not mention %q", err, tc.expect)
			}
		})
	}
}

// The explicit override is the only way to run simpleenroll unrestricted.
func TestValidateESTAllowAnyIdentifier(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = acmeTestProfiles()
	e := validEST()
	e.AllowedIdentifierSuffixes = nil
	e.AllowAnyIdentifier = true
	cfg.PKI.EST = e
	if err := cfg.Validate(); err != nil {
		t.Fatalf("allow_any_identifier should permit an empty allowlist: %v", err)
	}
}

// A reenroll-only deployment, with no simpleenroll credentials at all, is a
// valid configuration and needs no allowlist.
func TestValidateESTReenrollOnly(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = acmeTestProfiles()
	e := validEST()
	e.EnrollCredentials = nil
	e.AllowedIdentifierSuffixes = nil
	cfg.PKI.EST = e
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a re-enrolment-only EST block was rejected: %v", err)
	}
}

func TestParseESTFromYAML(t *testing.T) {
	yaml := string(validYAML(t)) + `  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth, client_auth]
  est:
    hostnames: [est.example.org, 10.0.0.10]
    http_port: 8443
    profile: leaf-server
    label: issuing
    realm: acme corp est
    allowed_identifier_suffixes: [example.org]
    enroll_credentials:
      - username: switch-fleet
        password_sha256: ` + testPasswordDigest() + `
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.PKI.EST == nil {
		t.Fatal("est block did not parse")
	}
	if len(cfg.PKI.EST.Hostnames) != 2 || cfg.PKI.EST.HTTPPort != 8443 {
		t.Fatalf("est = %+v", cfg.PKI.EST)
	}
	if cfg.PKI.EST.Label != "issuing" || cfg.PKI.EST.Realm != "acme corp est" {
		t.Fatalf("est = %+v", cfg.PKI.EST)
	}
	if cfg.PKI.EST.AllowAnyIdentifier {
		t.Fatal("allow_any_identifier must default to false")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
