package grpc

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
)

// authzTestCert builds a throwaway self-signed certificate for authz tests.
func authzTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "authz-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// trustForCert loads a fingerprint-only Trust pinned to cert's DER SHA-256.
func trustForCert(t *testing.T, cert *x509.Certificate) *bootstrap.Trust {
	t.Helper()
	fp := sha256.Sum256(cert.Raw)
	tr, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	return tr
}

func authzMTLSContext(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}},
	})
}

func TestAuthorizeAdmin_LocalNoPeer(t *testing.T) {
	trust := trustForCert(t, authzTestCert(t))
	if err := AuthorizeAdmin(context.Background(), trust); err != nil {
		t.Fatalf("AuthorizeAdmin (local, no peer): want nil, got %v", err)
	}
}

func TestAuthorizeAdmin_MatchingCert(t *testing.T) {
	admin := authzTestCert(t)
	trust := trustForCert(t, admin)
	if err := AuthorizeAdmin(authzMTLSContext(admin), trust); err != nil {
		t.Fatalf("AuthorizeAdmin (matching cert): want nil, got %v", err)
	}
}

func TestAuthorizeAdmin_MismatchIsPermissionDenied(t *testing.T) {
	trust := trustForCert(t, authzTestCert(t))
	other := authzTestCert(t)
	err := AuthorizeAdmin(authzMTLSContext(other), trust)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AuthorizeAdmin (mismatch): want PermissionDenied, got %v", err)
	}
}

func TestAuthorizeAdmin_NoCertIsUnauthenticated(t *testing.T) {
	trust := trustForCert(t, authzTestCert(t))
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}},
	})
	err := AuthorizeAdmin(ctx, trust)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("AuthorizeAdmin (no cert): want Unauthenticated, got %v", err)
	}
}
