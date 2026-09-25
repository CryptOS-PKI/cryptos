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
	"path/filepath"
	"slices"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
)

// recordingLeafSigner stands in for the node's CA signer on issue-leaf.
type recordingLeafSigner struct {
	certDER  []byte
	profile  string
	dnsNames []string
}

func (r *recordingLeafSigner) IssueLeafWithRequestSANs(_ context.Context, _ []byte, profileName string, dnsNames []string) ([]byte, error) {
	r.profile = profileName
	r.dnsNames = dnsNames
	return r.certDER, nil
}

func startIssueLeafServer(t *testing.T, ls cgrpc.LeafSigner) *testServer {
	t.Helper()
	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.LeafSigner = ls
		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

func TestIssueLeaf_SendsRepeatedDNSFlags(t *testing.T) {
	ls := &recordingLeafSigner{certDER: selfSignedCA(t)}
	ts := startIssueLeafServer(t, ls)
	csr := filepath.Join(t.TempDir(), "dc02.req")
	writeFile(t, csr, ls.certDER) // the fake signer never parses it

	if out, err := ts.run(t, "ca", "issue-leaf", "--csr", csr, "--profile", "ldaps-dc",
		"--dns", "dc02.ad.example.org", "--dns", "ad.example.org"); err != nil {
		t.Fatalf("issue-leaf: %v (out=%s)", err, out)
	}
	if ls.profile != "ldaps-dc" || !slices.Equal(ls.dnsNames, []string{"dc02.ad.example.org", "ad.example.org"}) {
		t.Fatalf("node got profile=%q names=%v", ls.profile, ls.dnsNames)
	}

	// Without --dns nothing is sent, and the profile's SANs apply.
	if out, err := ts.run(t, "ca", "issue-leaf", "--csr", csr, "--profile", "ldaps-dc"); err != nil {
		t.Fatalf("issue-leaf: %v (out=%s)", err, out)
	}
	if len(ls.dnsNames) != 0 {
		t.Fatalf("node got names %v without --dns", ls.dnsNames)
	}
}
