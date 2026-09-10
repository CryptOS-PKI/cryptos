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
	"encoding/base64"
	"strings"
	"testing"
)

// acmeTestProfiles is the minimum profile set an ACME block can name.
func acmeTestProfiles() []CertificateProfile {
	return []CertificateProfile{
		{Name: "leaf-server", KeyAlg: RootKeyECDSAP384, ValidityDays: 90, KeyUsage: []string{"digital_signature"}, ExtKeyUsage: []string{"server_auth"}},
		{Name: "sub-ca", KeyAlg: RootKeyECDSAP384, ValidityDays: 3650, KeyUsage: []string{"cert_sign", "crl_sign"},
			BasicConstraints: BasicConstraints{IsCA: true}},
	}
}

func validEABKey() string {
	return base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

// validACME is a block that must pass, so each rejection case below differs
// from a passing config in exactly one way.
func validACME() *ACME {
	return &ACME{
		BaseURL:             "https://ca.example.org/acme",
		Profile:             "leaf-server",
		ExternalAccountKeys: []ExternalAccountKey{{KeyID: "ops", HMACKeyBase64: validEABKey()}},
	}
}

func TestValidateACMEAccepts(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = acmeTestProfiles()
	cfg.PKI.ACME = validACME()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid ACME block was rejected: %v", err)
	}
}

// A nil block is the default and must not require anything.
func TestValidateACMEAbsentIsFine(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.PKI.ACME != nil {
		t.Fatal("ACME must default to disabled")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateACMERejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ACME)
		expect string
	}{
		{"no base url", func(a *ACME) { a.BaseURL = "" }, "base_url"},
		{"relative base url", func(a *ACME) { a.BaseURL = "/acme" }, "base_url"},
		{"non-http base url", func(a *ACME) { a.BaseURL = "ftp://ca.example.org/acme" }, "base_url"},
		{"no profile", func(a *ACME) { a.Profile = "" }, "profile"},
		{"unknown profile", func(a *ACME) { a.Profile = "nope" }, "no profile named"},
		{"ca profile", func(a *ACME) { a.Profile = "sub-ca" }, "CA profile"},
		{
			// The security-relevant default: without the explicit opt-out,
			// an ACME block with no binding keys must not validate.
			name:   "no binding keys and no opt-out",
			mutate: func(a *ACME) { a.ExternalAccountKeys = nil },
			expect: "external_account_keys",
		},
		{
			name:   "binding key id missing",
			mutate: func(a *ACME) { a.ExternalAccountKeys[0].KeyID = "" },
			expect: "key_id",
		},
		{
			name: "duplicate binding key id",
			mutate: func(a *ACME) {
				a.ExternalAccountKeys = append(a.ExternalAccountKeys,
					ExternalAccountKey{KeyID: "ops", HMACKeyBase64: validEABKey()})
			},
			expect: "duplicated",
		},
		{
			name:   "binding key not base64url",
			mutate: func(a *ACME) { a.ExternalAccountKeys[0].HMACKeyBase64 = "not base64!" },
			expect: "base64url",
		},
		{
			name: "binding key too short",
			mutate: func(a *ACME) {
				a.ExternalAccountKeys[0].HMACKeyBase64 = base64.RawURLEncoding.EncodeToString([]byte("short"))
			},
			expect: "at least 32 bytes",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg.PKI.Profiles = acmeTestProfiles()
			a := validACME()
			tc.mutate(a)
			cfg.PKI.ACME = a

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

// Setting the explicit opt-out is the only way to run without binding keys.
func TestValidateACMEAnonymousOptOut(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.PKI.Profiles = acmeTestProfiles()
	a := validACME()
	a.ExternalAccountKeys = nil
	a.AllowAnonymousAccounts = true
	cfg.PKI.ACME = a
	if err := cfg.Validate(); err != nil {
		t.Fatalf("allow_anonymous_accounts should permit an empty key list: %v", err)
	}
}

// The block must survive a YAML round-trip, since that is how an operator
// actually supplies it.
func TestParseACMEFromYAML(t *testing.T) {
	yaml := string(validYAML(t)) + `  profiles:
    - name: leaf-server
      key_alg: ECDSA-P384
      validity_days: 90
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
  acme:
    base_url: https://ca.example.org/acme
    http_port: 8555
    profile: leaf-server
    allowed_identifier_suffixes: [example.org]
    external_account_keys:
      - key_id: ops
        hmac_key_base64: ` + validEABKey() + `
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.PKI.ACME == nil {
		t.Fatal("acme block did not parse")
	}
	if cfg.PKI.ACME.HTTPPort != 8555 || cfg.PKI.ACME.Profile != "leaf-server" {
		t.Fatalf("acme = %+v", cfg.PKI.ACME)
	}
	if len(cfg.PKI.ACME.AllowedIdentifierSuffixes) != 1 {
		t.Fatalf("allowed_identifier_suffixes = %v", cfg.PKI.ACME.AllowedIdentifierSuffixes)
	}
	if cfg.PKI.ACME.AllowAnonymousAccounts {
		t.Fatal("allow_anonymous_accounts must default to false")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
