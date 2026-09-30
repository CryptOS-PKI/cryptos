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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
)

// issuedLookup stands in for the node's revoker on get-issued.
type issuedLookup struct {
	gotSerial string
	resp      *cryptosv1.GetIssuedCertificateResponse
}

func (l *issuedLookup) Revoke(context.Context, string, int) (*cryptosv1.Revocation, error) {
	return nil, nil
}

func (l *issuedLookup) ListIssued(context.Context) ([]*cryptosv1.IssuedCert, error) {
	return nil, nil
}

func (l *issuedLookup) ListRevocations(context.Context) ([]*cryptosv1.Revocation, error) {
	return nil, nil
}

func (l *issuedLookup) GetIssuedCertificate(_ context.Context, serialHex string) (*cryptosv1.GetIssuedCertificateResponse, error) {
	l.gotSerial = serialHex
	return l.resp, nil
}

func startGetIssuedServer(t *testing.T, l *issuedLookup) *testServer {
	t.Helper()
	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.Revoker = l
		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

func revokedLookup(t *testing.T) *issuedLookup {
	t.Helper()
	return &issuedLookup{resp: &cryptosv1.GetIssuedCertificateResponse{
		CertificateDer: selfSignedCA(t),
		ChainDer:       [][]byte{selfSignedCA(t), selfSignedCA(t)},
		Status:         "revoked",
		RevokedAt:      "2026-03-04T05:06:07Z",
	}}
}

// pemCertificates returns the DER of every CERTIFICATE block in out, in order.
func pemCertificates(out string) [][]byte {
	var ders [][]byte
	rest := []byte(out)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return ders
		}
		if b.Type == "CERTIFICATE" {
			ders = append(ders, b.Bytes)
		}
	}
}

func TestGetIssued_PrintsTheCertificateThenTheChain(t *testing.T) {
	l := revokedLookup(t)
	ts := startGetIssuedServer(t, l)

	out, err := ts.run(t, "ca", "get-issued", "--serial", "0A1B")
	if err != nil {
		t.Fatalf("get-issued: %v (out=%s)", err, out)
	}
	if l.gotSerial != "a1b" {
		t.Errorf("node got serial %q, want the normalised a1b", l.gotSerial)
	}
	got := pemCertificates(out)
	want := append([][]byte{l.resp.GetCertificateDer()}, l.resp.GetChainDer()...)
	if len(got) != len(want) {
		t.Fatalf("printed %d certificates, want %d (out=%s)", len(got), len(want), out)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("certificate %d is not the one the node returned", i)
		}
	}
	if !strings.Contains(out, "status: revoked (revoked at 2026-03-04T05:06:07Z)") {
		t.Errorf("output does not report the status: %s", out)
	}
}

func TestGetIssued_MachineFormats(t *testing.T) {
	ts := startGetIssuedServer(t, revokedLookup(t))

	out, err := ts.run(t, "-o", "json", "ca", "get-issued", "--serial", "0a")
	if err != nil {
		t.Fatalf("get-issued -o json: %v (out=%s)", err, out)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("-o json is not JSON: %v (out=%s)", err, out)
	}
	if doc["status"] != "revoked" || doc["revoked_at"] != "2026-03-04T05:06:07Z" || doc["certificate_der"] == nil || doc["chain_der"] == nil {
		t.Errorf("-o json = %v, want certificate_der, chain_der, status and revoked_at", doc)
	}

	out, err = ts.run(t, "-o", "yaml", "ca", "get-issued", "--serial", "0a")
	if err != nil {
		t.Fatalf("get-issued -o yaml: %v (out=%s)", err, out)
	}
	for _, w := range []string{"certificate_der:", "chain_der:", "status: revoked", `revoked_at: "2026-03-04T05:06:07Z"`} {
		if !strings.Contains(out, w) {
			t.Errorf("-o yaml output lacks %q: %s", w, out)
		}
	}
	if strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Error("-o yaml printed PEM")
	}
}

func TestGetIssued_RequiresASerial(t *testing.T) {
	l := revokedLookup(t)
	ts := startGetIssuedServer(t, l)

	if _, err := ts.run(t, "ca", "get-issued"); err == nil || !strings.Contains(err.Error(), "--serial is required") {
		t.Fatalf("get-issued without --serial = %v, want a usage error", err)
	}
	if l.gotSerial != "" {
		t.Fatal("the node was called without a serial")
	}
}
