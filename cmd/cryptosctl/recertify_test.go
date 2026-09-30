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
	"encoding/pem"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
)

// recordingRenewer stands in for the node's renewer.
type recordingRenewer struct {
	csr      []byte
	gotChain [][]byte
}

func (r *recordingRenewer) RenewalCSR(context.Context) ([]byte, error) { return r.csr, nil }

func (r *recordingRenewer) AcceptRenewal(_ context.Context, chainDER [][]byte) (*cryptosv1.Identity, error) {
	r.gotChain = chainDER
	return &cryptosv1.Identity{ChainDer: chainDER, LeafSha256: []byte{1}}, nil
}

// startRenewServer wires rn behind real mTLS. admin selects whether the pinned
// bootstrap admin is the CLI's own client certificate or some other one.
func startRenewServer(t *testing.T, rn cgrpc.Renewer, admin bool) *testServer {
	t.Helper()
	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.Renewer = rn
		pinned := clientCert.Raw
		if !admin {
			pinned = selfSignedCA(t)
		}
		fp := sha256.Sum256(pinned)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

func TestRecertifyVerbsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, sub := range newCACmd(&globalOpts{}).Commands() {
		names[sub.Name()] = true
	}
	for _, want := range []string{"get-renewal-csr", "submit-renewed-cert"} {
		if !names[want] {
			t.Errorf("%s not registered under ca", want)
		}
	}
}

func TestSubmitRenewedCertRequiresChain(t *testing.T) {
	if _, err := runCmd(t, "ca", "submit-renewed-cert"); err == nil {
		t.Error("submit-renewed-cert without --chain = nil, want error")
	}
}

func TestRecertifyRoundTrip(t *testing.T) {
	rn := &recordingRenewer{csr: []byte("renewal-csr-der")}
	ts := startRenewServer(t, rn, true)

	out, err := ts.run(t, "ca", "get-renewal-csr")
	if err != nil {
		t.Fatalf("get-renewal-csr: %v (out=%s)", err, out)
	}
	block, _ := pem.Decode([]byte(out))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || string(block.Bytes) != "renewal-csr-der" {
		t.Fatalf("get-renewal-csr output = %q, want the CSR as a CERTIFICATE REQUEST PEM block", out)
	}

	leaf, parent := selfSignedCA(t), selfSignedCA(t)
	chainPath := filepath.Join(t.TempDir(), "renewed-chain.pem")
	var chain bytes.Buffer
	for _, der := range [][]byte{leaf, parent} {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	writeFile(t, chainPath, chain.Bytes())
	if out, err := ts.run(t, "ca", "submit-renewed-cert", "--chain", chainPath); err != nil {
		t.Fatalf("submit-renewed-cert: %v (out=%s)", err, out)
	}
	if len(rn.gotChain) != 2 || !bytes.Equal(rn.gotChain[0], leaf) || !bytes.Equal(rn.gotChain[1], parent) {
		t.Fatalf("node got chain of %d certs, want [leaf, parent] in order", len(rn.gotChain))
	}
}

func TestRecertifyNonAdminDenied(t *testing.T) {
	rn := &recordingRenewer{csr: []byte("renewal-csr-der")}
	ts := startRenewServer(t, rn, false)

	if _, err := ts.run(t, "ca", "get-renewal-csr"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("get-renewal-csr as non-admin: err = %v, want PermissionDenied", err)
	}
	chainPath := filepath.Join(t.TempDir(), "chain.pem")
	writeFile(t, chainPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedCA(t)}))
	if _, err := ts.run(t, "ca", "submit-renewed-cert", "--chain", chainPath); status.Code(err) != codes.PermissionDenied {
		t.Errorf("submit-renewed-cert as non-admin: err = %v, want PermissionDenied", err)
	}
	if rn.gotChain != nil {
		t.Fatal("renewer was consulted for a non-admin caller")
	}
}
