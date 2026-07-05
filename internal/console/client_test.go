package console_test

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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"testing"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/console"
	"google.golang.org/grpc"
)

// leafPEM2 builds a self-signed leaf certificate with the given CommonName and
// returns it as PEM. It mirrors leafPEM in status_test.go but takes no testing
// handle so the client test stays self-contained and can run out of order.
func leafPEM2(cn string) string {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fakeNode struct {
	cryptosv1.UnimplementedNodeServiceServer
	cn string
}

func (f *fakeNode) GetStatus(context.Context, *cryptosv1.GetStatusRequest) (*cryptosv1.GetStatusResponse, error) {
	return &cryptosv1.GetStatusResponse{Status: &cryptosv1.NodeStatus{
		Role: cryptosv1.NodeRole_NODE_ROLE_ROOT, IdentityState: cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
		TpmState: cryptosv1.TpmState_TPM_STATE_OK, SoftwareVersion: "phase-1-dev",
	}}, nil
}

func (f *fakeNode) GetIdentity(context.Context, *cryptosv1.GetIdentityRequest) (*cryptosv1.GetIdentityResponse, error) {
	return &cryptosv1.GetIdentityResponse{Identity: &cryptosv1.Identity{ChainPem: leafPEM2(f.cn)}}, nil
}

func TestClientSnapshot(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	cryptosv1.RegisterNodeServiceServer(srv, &fakeNode{cn: "ACME Root CA G1"})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	c, err := console.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	v, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.RootCN != "ACME Root CA G1" || v.NodeStatus != "ESTABLISHED" {
		t.Fatalf("snapshot view wrong: %+v", v)
	}
}
