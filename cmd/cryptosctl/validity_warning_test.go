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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

var testValidityCap = &ca.ValidityCap{
	Requested: time.Date(2046, 9, 22, 0, 0, 0, 0, time.UTC),
	Effective: time.Date(2041, 9, 21, 0, 0, 0, 0, time.UTC),
}

const wantCapWarning = "WARNING: requested validity ends 2046-09-22; capped to issuer notAfter 2041-09-21"

type cappingSubordinateSigner struct{ chainDER [][]byte }

func (c *cappingSubordinateSigner) SignSubordinate(context.Context, []byte, string) ([][]byte, string, *ca.ValidityCap, error) {
	return c.chainDER, "", testValidityCap, nil
}

func TestIssueLeaf_PrintsValidityCapWarning(t *testing.T) {
	ls := &recordingLeafSigner{certDER: selfSignedCA(t), vcap: testValidityCap}
	ts := startIssueLeafServer(t, ls)
	csr := filepath.Join(t.TempDir(), "leaf.req")
	writeFile(t, csr, testCSR(t))

	out, err := ts.run(t, "ca", "issue-leaf", "--csr", csr, "--profile", "leaf-server")
	if err != nil {
		t.Fatalf("issue-leaf: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, wantCapWarning) {
		t.Fatalf("output does not carry the cap warning:\n%s", out)
	}
	if !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Fatalf("output lost the certificate:\n%s", out)
	}
}

func TestSignSubordinate_PrintsValidityCapWarning(t *testing.T) {
	ts := startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.SubordinateSigner = &cappingSubordinateSigner{chainDER: [][]byte{selfSignedCA(t)}}
		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
	csr := filepath.Join(t.TempDir(), "sub.req")
	writeFile(t, csr, testCSR(t))

	out, err := ts.run(t, "ca", "sign-subordinate", "--csr", csr, "--profile", "sub-ca")
	if err != nil {
		t.Fatalf("sign-subordinate: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, wantCapWarning) {
		t.Fatalf("output does not carry the cap warning:\n%s", out)
	}
}

func TestConfigApply_PrintsNodeWarnings(t *testing.T) {
	caNotAfter := time.Now().Add(30 * 24 * time.Hour)
	ts := startTestServerWith(t, func(cfg *cgrpc.ServerConfig, _ *x509.Certificate) {
		cfg.ConfigStore = node.NewConfigStore(config.NewFileStore(t.TempDir())).WithIssuer(
			func(context.Context) (*x509.Certificate, error) {
				return &x509.Certificate{NotAfter: caNotAfter}, nil
			})
	})
	raw := strings.Replace(minimalConfig, "    organization: Example Organization\n", `    organization: Example Organization
  profiles:
    - name: vmca-sub
      key_alg: ECDSA-P384
      validity_days: 7300
      basic_constraints: {is_ca: true}
      key_usage: [cert_sign, crl_sign]
`, 1)
	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := ts.run(t, "config", "apply", "-f", path)
	if err != nil {
		t.Fatalf("config apply: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, `WARNING: profile "vmca-sub": validity_days 7300`) {
		t.Fatalf("output does not carry the node's warning:\n%s", out)
	}
	if !strings.Contains(out, "applied: generation=") {
		t.Fatalf("apply did not report success:\n%s", out)
	}
}
