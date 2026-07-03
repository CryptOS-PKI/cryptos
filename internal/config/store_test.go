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
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	if _, _, ok, err := s.Read(); err != nil || ok {
		t.Fatalf("empty Read: ok=%v err=%v, want ok=false nil", ok, err)
	}
	raw := validConfigYAML(t) // helper below
	gen, err := s.Write(raw)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if gen != 1 {
		t.Errorf("first generation = %d, want 1", gen)
	}
	got, gen2, ok, err := s.Read()
	if err != nil || !ok {
		t.Fatalf("Read after Write: ok=%v err=%v", ok, err)
	}
	if gen2 != 1 {
		t.Errorf("read generation = %d, want 1", gen2)
	}
	if _, err := Parse(got); err != nil {
		t.Errorf("stored bytes do not parse: %v", err)
	}
	gen3, err := s.Write(raw)
	if err != nil || gen3 != 2 {
		t.Errorf("second Write gen = %d err = %v, want 2 nil", gen3, err)
	}
}

func TestFileStoreRejectsInvalid(t *testing.T) {
	s := NewFileStore(t.TempDir())
	if _, err := s.Write([]byte("not: a: valid: config")); err == nil {
		t.Error("Write should reject config that fails Parse")
	}
	if _, _, ok, _ := s.Read(); ok {
		t.Error("nothing should be persisted after a rejected Write")
	}
}

func TestFileStoreWriteErrorWithBlockedPath(t *testing.T) {
	dir := t.TempDir()
	// Create a file at the config directory level so MkdirAll will fail
	blockerPath := filepath.Join(dir, "afile")
	if err := os.WriteFile(blockerPath, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("setup: write blocker file: %v", err)
	}
	// Try to use a path under the file (not a directory)
	configDir := filepath.Join(blockerPath, "config")
	s := NewFileStore(configDir)

	// Write should fail due to MkdirAll failing
	raw := validConfigYAML(t)
	_, err := s.Write(raw)
	if err == nil {
		t.Error("Write should fail when directory cannot be created")
	}

	// Read should report ok=false (no config written)
	_, _, ok, _ := s.Read()
	if ok {
		t.Errorf("Read after failed Write: ok=%v, want ok=false", ok)
	}
}

func validConfigYAML(t *testing.T) []byte {
	raw := []byte(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: integration-root}
role: {kind: root}
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
bootstrap:
  admin_cert_pem: |
    -----BEGIN CERTIFICATE-----
    MIIBajCCAQ+gAwIBAgIIGL6osNJqeWowCgYIKoZIzj0EAwIwJjEkMCIGA1UEAxMb
    aW50ZWdyYXRpb24gYm9vdHN0cmFwIGFkbWluMB4XDTI2MDcwMzAyMDYxOVoXDTI2
    MDcwNDAzMDYxOVowJjEkMCIGA1UEAxMbaW50ZWdyYXRpb24gYm9vdHN0cmFwIGFk
    bWluMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYei4K4KPkW1SSxuvKELevYEX
    7386oeG0EFj98MtNaIfefCYAEqtB+3kkc3lbUoRRjiXDSrKY4VcmJlKqlhDQr6Mn
    MCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAoGCCqGSM49
    BAMCA0kAMEYCIQCImibqyRK1O4k4MLl7+rqYj0R/5V9oqWEyragr+JADFAIhANUb
    SSBlS58I71LtY5fYBkmBWs3+b1KaoJz5PA55EAlb
    -----END CERTIFICATE-----
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: "CryptOS Integration Root", organization: "Integration", country: "US"}
  root_validity_years: 20
  path_len_constraint: 2
`)
	// Verify the YAML parses before using it in tests
	if _, err := Parse(raw); err != nil {
		t.Fatalf("validConfigYAML itself fails to parse: %v", err)
	}
	return raw
}
