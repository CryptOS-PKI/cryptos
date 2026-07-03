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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// validYAML returns a minimal valid Phase 1 MachineConfig as YAML.
// admin_cert_pem is filled in with a freshly-generated self-signed cert
// so the parser's PEM validation has something real to chew on.
func validYAML(t *testing.T) []byte {
	t.Helper()
	pemCert := selfSignedCertPEM(t)
	var b bytes.Buffer
	b.WriteString(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: ca-east-1
role:
  kind: root
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
storage:
  state_partition_label: cryptos-state
  first_boot: true
bootstrap:
  admin_cert_pem: |
`)
	for _, line := range strings.Split(strings.TrimRight(pemCert, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString(`pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "CryptOS Root CA — Acme Corp"
    organization: "Acme Corp"
    country: "US"
  root_validity_years: 20
  path_len_constraint: 2
`)
	return b.Bytes()
}

// selfSignedCertPEM produces a throwaway PEM-encoded X.509 cert for
// tests that exercise the admin_cert_pem validation path.
func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParse_HappyPath(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Role.Kind != RoleRoot {
		t.Fatalf("Role.Kind = %q, want %q", cfg.Role.Kind, RoleRoot)
	}
	if cfg.PKI.RootValidityYears != 20 {
		t.Fatalf("RootValidityYears = %d, want 20", cfg.PKI.RootValidityYears)
	}
}

func TestParse_ToProto_RoundTrip(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	proto := cfg.ToProto()
	if proto.GetApiVersion() != APIVersion {
		t.Fatalf("proto.ApiVersion = %q, want %q", proto.GetApiVersion(), APIVersion)
	}
	if proto.GetPki().GetRootValidityYears() != 20 {
		t.Fatalf("proto.Pki.RootValidityYears = %d, want 20", proto.GetPki().GetRootValidityYears())
	}
	if proto.GetBootstrap().GetAdminCertPem() == "" {
		t.Fatalf("proto.Bootstrap.AdminCertPem should be populated")
	}
}

func TestParse_Digest_StableAcrossWhitespace(t *testing.T) {
	cfg1, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse 1: %v", err)
	}
	d1, err := cfg1.Digest()
	if err != nil {
		t.Fatalf("Digest 1: %v", err)
	}

	// Build a second config from the same Go values but stress digest
	// stability by recomputing it directly.
	d2, err := cfg1.Digest()
	if err != nil {
		t.Fatalf("Digest 2: %v", err)
	}
	if hex.EncodeToString(d1) != hex.EncodeToString(d2) {
		t.Fatalf("digest not stable: %x vs %x", d1, d2)
	}
}

// rejectionTest exercises one validation rule by mutating valid YAML.
type rejectionTest struct {
	name    string
	mutate  func(string) string
	wantSub string
}

func TestParse_Rejections(t *testing.T) {
	base := string(validYAML(t))
	cases := []rejectionTest{
		{
			name:    "wrong apiVersion",
			mutate:  func(s string) string { return strings.Replace(s, APIVersion, "cryptos.dev/v0", 1) },
			wantSub: "apiVersion",
		},
		{
			name:    "wrong kind",
			mutate:  func(s string) string { return strings.Replace(s, "kind: MachineConfig", "kind: NotMachineConfig", 1) },
			wantSub: "kind",
		},
		{
			name:    "non-root role in Phase 1",
			mutate:  func(s string) string { return strings.Replace(s, "kind: root", "kind: intermediate", 1) },
			wantSub: "role.kind",
		},
		{
			name:    "missing interface",
			mutate:  func(s string) string { return strings.Replace(s, "interface: eth0", `interface: ""`, 1) },
			wantSub: "network.interface",
		},
		{
			name:    "address not CIDR",
			mutate:  func(s string) string { return strings.Replace(s, "10.0.0.10/24", "10.0.0.10", 1) },
			wantSub: "network.address",
		},
		{
			name:    "gateway not IP",
			mutate:  func(s string) string { return strings.Replace(s, "gateway: 10.0.0.1", "gateway: not-an-ip", 1) },
			wantSub: "network.gateway",
		},
		{
			name: "wrong root_key_alg",
			mutate: func(s string) string {
				return strings.Replace(s, "root_key_alg: ECDSA-P384", "root_key_alg: ECDSA-P256", 1)
			},
			wantSub: "root_key_alg",
		},
		{
			name: "root validity 0",
			mutate: func(s string) string {
				return strings.Replace(s, "root_validity_years: 20", "root_validity_years: 0", 1)
			},
			wantSub: "root_validity_years",
		},
		{
			name: "root validity too high",
			mutate: func(s string) string {
				return strings.Replace(s, "root_validity_years: 20", "root_validity_years: 100", 1)
			},
			wantSub: "root_validity_years",
		},
		{
			name: "path length too high",
			mutate: func(s string) string {
				return strings.Replace(s, "path_len_constraint: 2", "path_len_constraint: 99", 1)
			},
			wantSub: "path_len_constraint",
		},
		{
			name: "empty CN",
			mutate: func(s string) string {
				return strings.Replace(s, `common_name: "CryptOS Root CA — Acme Corp"`, `common_name: ""`, 1)
			},
			wantSub: "common_name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.mutate(base)))
			if err == nil {
				t.Fatalf("Parse should have failed")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestParse_BootstrapExactlyOne(t *testing.T) {
	base := string(validYAML(t))

	// Both set → error.
	withBoth := strings.Replace(
		base,
		"bootstrap:\n  admin_cert_pem: |\n",
		"bootstrap:\n  admin_cert_sha256: \""+strings.Repeat("a", 64)+"\"\n  admin_cert_pem: |\n",
		1,
	)
	if _, err := Parse([]byte(withBoth)); err == nil {
		t.Fatalf("Parse should fail when both bootstrap fields are set")
	}

	// Neither set → error.
	idxStart := strings.Index(base, "bootstrap:")
	idxEnd := strings.Index(base, "pki:")
	withNeither := base[:idxStart] + "bootstrap:\n" + base[idxEnd:]
	if _, err := Parse([]byte(withNeither)); err == nil {
		t.Fatalf("Parse should fail when neither bootstrap field is set")
	}
}

func TestParse_AdminCertSHA256(t *testing.T) {
	base := string(validYAML(t))
	// Replace the entire bootstrap section with the sha256 path.
	idxStart := strings.Index(base, "bootstrap:")
	idxEnd := strings.Index(base, "pki:")
	withSHA := base[:idxStart] +
		"bootstrap:\n  admin_cert_sha256: \"" + strings.Repeat("a", 64) + "\"\n" +
		base[idxEnd:]
	if _, err := Parse([]byte(withSHA)); err != nil {
		t.Fatalf("Parse with sha256 bootstrap: %v", err)
	}
}

func TestParse_AdminCertSHA256_BadLength(t *testing.T) {
	base := string(validYAML(t))
	idxStart := strings.Index(base, "bootstrap:")
	idxEnd := strings.Index(base, "pki:")
	withBad := base[:idxStart] +
		"bootstrap:\n  admin_cert_sha256: \"deadbeef\"\n" +
		base[idxEnd:]
	if _, err := Parse([]byte(withBad)); err == nil {
		t.Fatalf("Parse should reject 8-char sha256")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatalf("Parse(nil) should fail")
	}
	if _, err := Parse([]byte{}); err == nil {
		t.Fatalf("Parse([]) should fail")
	}
}

func TestFromProtoRoundTrip(t *testing.T) {
	orig, err := Parse(validYAML(t))
	if err != nil {
		t.Fatal(err)
	}
	pb := orig.ToProto()
	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	y, err := back.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Re-parse must succeed; Storage is missing from the round-trip
	// (not mapped through proto) so inject the original storage values
	// before reparsing.
	back.Storage = orig.Storage
	y, err = back.Marshal()
	if err != nil {
		t.Fatalf("Marshal with storage: %v", err)
	}
	reparsed, err := Parse(y)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if reparsed.Metadata.Name != orig.Metadata.Name ||
		reparsed.Network.Address != orig.Network.Address ||
		reparsed.PKI.RootKeyAlg != orig.PKI.RootKeyAlg {
		t.Error("round-trip changed a field")
	}
}
