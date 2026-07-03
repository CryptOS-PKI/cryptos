package main

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
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// applyConfigRequest mirrors exactly what newConfigApplyCmd sends over the
// wire: config.Parse the raw YAML, then call ToProto.  This test confirms
// that install.disk survives the client-side YAML→proto conversion so the
// maintenance node receives a non-empty Install.Disk in the ApplyConfig RPC.
func TestApplyConfig_InstallDiskSentOnWire(t *testing.T) {
	raw := buildMachineYAMLWithInstall(t, "/dev/vdb")

	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}

	// Reproduce the exact request the command builds.
	req := &cryptosv1.ApplyConfigRequest{Config: cfg.ToProto()}

	if req.Config.GetInstall().GetDisk() != "/dev/vdb" {
		t.Fatalf("ApplyConfigRequest.Config.Install.Disk = %q, want %q",
			req.Config.GetInstall().GetDisk(), "/dev/vdb")
	}
}

// selfSignedAdminCertPEM mints a throwaway PEM-encoded X.509 cert suitable
// for the bootstrap.admin_cert_pem field in a MachineConfig YAML under test.
func selfSignedAdminCertPEM(t *testing.T) string {
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
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// buildMachineYAMLWithInstall produces a minimal valid Phase 1 MachineConfig
// YAML that includes an install section specifying disk.  The bootstrap field
// uses a freshly-generated self-signed certificate so validation passes.
func buildMachineYAMLWithInstall(t *testing.T, disk string) []byte {
	t.Helper()
	pemCert := selfSignedAdminCertPEM(t)
	var b bytes.Buffer
	fmt.Fprintf(&b, `apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: maint-node-1
role:
  kind: root
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_pem: |
`)
	for _, line := range strings.Split(strings.TrimRight(pemCert, "\n"), "\n") {
		fmt.Fprintf(&b, "    %s\n", line)
	}
	fmt.Fprintf(&b, `pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "CryptOS Root CA"
    organization: "Test Org"
    country: "US"
  root_validity_years: 20
install:
  disk: %s
`, disk)
	return b.Bytes()
}
