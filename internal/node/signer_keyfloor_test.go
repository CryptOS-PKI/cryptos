package node

/*
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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

func makeRSACSR(t *testing.T, cn string, bits int) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("GenerateKey RSA %d: %v", bits, err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

// The SCEP device profiles are the only issuance path that may certify an
// RSA 2048 key, and only when the caller names that floor.
func TestIssueLeafForNamesMinRSA(t *testing.T) {
	f := newSignerFixture(t)
	var closed bool
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), &closed)
	s := NewCASigner(load, issuer, get)
	ctx := context.Background()
	names := []string{"switch01.example.org"}

	csr2048 := makeRSACSR(t, "switch01.example.org", 2048)
	if _, _, err := s.IssueLeafForNames(ctx, csr2048, "leaf-server", names); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("IssueLeafForNames with an RSA 2048 key = %v, want InvalidArgument", err)
	}
	if _, _, err := s.IssueLeafForNamesMinRSA(ctx, csr2048, "leaf-server", names, 3072); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("IssueLeafForNamesMinRSA(3072) with an RSA 2048 key = %v, want InvalidArgument", err)
	}
	chain, _, err := s.IssueLeafForNamesMinRSA(ctx, csr2048, "leaf-server", names, 2048)
	if err != nil {
		t.Fatalf("IssueLeafForNamesMinRSA(2048): %v", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := leaf.PublicKey.(*rsa.PublicKey).N.BitLen(); got != 2048 {
		t.Fatalf("certified key is %d bits, want 2048", got)
	}
	if _, _, err := s.IssueLeafForNamesMinRSA(ctx, csr2048, "leaf-server", names, 1024); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("IssueLeafForNamesMinRSA(1024) = %v, want InvalidArgument", err)
	}
}
