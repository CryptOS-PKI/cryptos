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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/audit"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

type stubCeremony struct{}

func (stubCeremony) Start(_ context.Context, _ *cryptosv1.StartCeremonyRequest, _ func(*cryptosv1.StartCeremonyResponse) error) error {
	return nil
}

// testServer wires a real mTLS gRPC server backed by embedded etcd with a
// committed identity, and writes client identity/trust files to dir.
type testServer struct {
	endpoint string
	dir      string
	rootDER  []byte
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	dir := t.TempDir()

	// Client bootstrap identity.
	cred, err := generateBootstrapCredential("roundtrip-admin", time.Hour)
	if err != nil {
		t.Fatalf("bootstrap cred: %v", err)
	}
	writeFile(t, filepath.Join(dir, "identity.crt"), cred.CertPEM)
	writeFile(t, filepath.Join(dir, "identity.key"), cred.KeyPEM)
	clientCertDER, _ := decodePEM(t, cred.CertPEM, "CERTIFICATE")
	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	// Server leaf cert for localhost; the client trusts it via trust.crt.
	serverCert, serverPEM := serverTLSCert(t)
	writeFile(t, filepath.Join(dir, "trust.crt"), serverPEM)

	// Embedded etcd + store with a committed identity.
	srv, err := etcd.Open(t.TempDir())
	if err != nil {
		t.Fatalf("etcd.Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("etcd.Client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	store, err := node.New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	rootDER := selfSignedCA(t)
	admin, err := bootstrap.AdminFromCertDER(clientCert.Raw)
	if err != nil {
		t.Fatalf("admin record: %v", err)
	}
	ctx := context.Background()
	if err := store.CommitFirstCeremony(ctx, node.FirstCeremonyCommit{
		RootCertDER:   rootDER,
		RootKeyBlob:   []byte("blob"),
		RootKeyPublic: []byte("pub"),
		ManifestID:    "m1",
		ManifestBytes: []byte("manifest"),
		Admin:         admin,
	}); err != nil {
		t.Fatalf("commit identity: %v", err)
	}

	// Audit logger.
	seed := make([]byte, audit.SeedLength)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	logger, err := audit.Open(filepath.Join(dir, "audit"), seed)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	statusProv, err := node.NewStatusProvider(node.StatusConfig{
		Store:           store,
		Role:            cryptosv1.NodeRole_NODE_ROLE_ROOT,
		SoftwareVersion: "test",
	})
	if err != nil {
		t.Fatalf("status provider: %v", err)
	}

	// Server TLS: present serverCert, require + verify the client cert
	// against a pool containing the bootstrap admin.
	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCert)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	server, err := cgrpc.New(cgrpc.ServerConfig{
		TLSConfig:   tlsCfg,
		Auditor:     logger,
		Identity:    node.NewIdentityProvider(store),
		Status:      statusProv,
		Ceremony:    stubCeremony{},
		ConfigStore: node.NewConfigStore(config.NewFileStore(filepath.Join(dir, "config"))),
	})
	if err != nil {
		t.Fatalf("grpc.New: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	return &testServer{endpoint: lis.Addr().String(), dir: dir, rootDER: rootDER}
}

func (ts *testServer) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	full := append([]string{
		"--endpoint", ts.endpoint,
		"--identity", filepath.Join(ts.dir, "identity.crt"),
		"--identity-key", filepath.Join(ts.dir, "identity.key"),
		"--trust", filepath.Join(ts.dir, "trust.crt"),
		"--server-name", "localhost",
	}, args...)
	root.SetArgs(full)
	err := root.Execute()
	return buf.String(), err
}

func TestRoundTrip_Status(t *testing.T) {
	ts := startTestServer(t)
	out, err := ts.run(t, "status")
	if err != nil {
		t.Fatalf("status: %v (out=%s)", err, out)
	}
	for _, want := range []string{"ROOT", "ESTABLISHED"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestRoundTrip_IdentityShowAndValidate(t *testing.T) {
	ts := startTestServer(t)

	pemOut, err := ts.run(t, "identity", "show", "-o", "pem")
	if err != nil {
		t.Fatalf("identity show: %v (out=%s)", err, pemOut)
	}
	if !strings.Contains(pemOut, "BEGIN CERTIFICATE") {
		t.Errorf("identity show -o pem produced no cert:\n%s", pemOut)
	}

	valOut, err := ts.run(t, "identity", "validate")
	if err != nil {
		t.Fatalf("identity validate: %v (out=%s)", err, valOut)
	}
	if !strings.Contains(valOut, "OK") {
		t.Errorf("identity validate output = %q, want OK", valOut)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// serverTLSCert mints a localhost server leaf certificate and returns
// both the tls.Certificate (with key) and the cert PEM for the client's
// trust store.
func serverTLSCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	return tlsCert, certPEM
}
