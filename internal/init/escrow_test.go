package init

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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// newEscrowStore spins up an embedded etcd and returns a node.Store + context.
func newEscrowStore(t *testing.T) (*node.Store, context.Context) {
	t.Helper()
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
	s, err := node.New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return s, ctx
}

// makeSoftCA generates a software CA key via the software Root backend and
// self-signs a Root certificate carrying that key, returning the key blobs
// (as node.RootKeyBlobs encodes them) and the leaf-first single-cert chain.
func makeSoftCA(t *testing.T, cn string) (keyBlob, keyPublic []byte, chain [][]byte) {
	t.Helper()
	var b softRootBackend
	created, err := b.CreateKey(tpm.AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	signer, err := b.LoadKey(created.Private, created.Public)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return created.Private, created.Public, [][]byte{der}
}

// commitCA seeds a store with a committed CA identity via CommitRestoredIdentity
// (the no-identity-guarded restore path), so the exporter has something to read.
func commitCA(t *testing.T, s *node.Store, ctx context.Context, keyBlob, keyPublic []byte, chain [][]byte) {
	t.Helper()
	if err := s.CommitRestoredIdentity(ctx, keyBlob, keyPublic, chain); err != nil {
		t.Fatalf("seed CommitRestoredIdentity: %v", err)
	}
}

func TestEscrowRoundTrip(t *testing.T) {
	// Source node: a software CA with a committed identity.
	src, ctx := newEscrowStore(t)
	keyBlob, keyPub, chain := makeSoftCA(t, "Root CA Escrow Test")
	commitCA(t, src, ctx, keyBlob, keyPub, chain)

	exp := newCAEscrow(src, true)
	pass := []byte("operator-passphrase")
	envelope, err := exp.ExportCAKey(ctx, pass)
	if err != nil {
		t.Fatalf("ExportCAKey: %v", err)
	}
	if len(envelope) == 0 {
		t.Fatal("ExportCAKey returned an empty envelope")
	}

	// Destination node: fresh, no identity. Import reproduces the same CA cert.
	dst, dctx := newEscrowStore(t)
	imp := newCAEscrow(dst, true)
	id, err := imp.ImportCAKey(dctx, envelope, pass)
	if err != nil {
		t.Fatalf("ImportCAKey: %v", err)
	}
	if len(id.GetChainDer()) != 1 {
		t.Fatalf("restored chain length = %d, want 1", len(id.GetChainDer()))
	}
	if string(id.GetChainDer()[0]) != string(chain[0]) {
		t.Fatal("restored CA certificate does not match the exported one")
	}

	// The restored key blobs match too, so the signer can load.
	gotPriv, gotPub, ok, err := dst.RootKeyBlobs(dctx)
	if err != nil || !ok {
		t.Fatalf("RootKeyBlobs ok=%v err=%v", ok, err)
	}
	if string(gotPriv) != string(keyBlob) || string(gotPub) != string(keyPub) {
		t.Fatal("restored key blobs do not match the exported ones")
	}
}

func TestExportRefusedWhenNotExportable(t *testing.T) {
	s, ctx := newEscrowStore(t)
	keyBlob, keyPub, chain := makeSoftCA(t, "TPM Root")
	commitCA(t, s, ctx, keyBlob, keyPub, chain)

	exp := newCAEscrow(s, false) // tpm-mode: non-exportable
	if _, err := exp.ExportCAKey(ctx, []byte("pw")); !errors.Is(err, cgrpc.ErrNotExportable) {
		t.Fatalf("ExportCAKey on a non-exportable node = %v, want ErrNotExportable", err)
	}
}

func TestExportRefusedWhenNoIdentity(t *testing.T) {
	s, ctx := newEscrowStore(t)
	exp := newCAEscrow(s, true)
	if _, err := exp.ExportCAKey(ctx, []byte("pw")); err == nil {
		t.Fatal("ExportCAKey with no identity = nil, want error")
	}
}

func TestImportRefusedWhenIdentityExists(t *testing.T) {
	// Export from a source node.
	src, ctx := newEscrowStore(t)
	keyBlob, keyPub, chain := makeSoftCA(t, "Root")
	commitCA(t, src, ctx, keyBlob, keyPub, chain)
	envelope, err := newCAEscrow(src, true).ExportCAKey(ctx, []byte("pw"))
	if err != nil {
		t.Fatalf("ExportCAKey: %v", err)
	}

	// Destination already has an identity: import is refused.
	dst, dctx := newEscrowStore(t)
	obk, opub, ochain := makeSoftCA(t, "Existing Root")
	commitCA(t, dst, dctx, obk, opub, ochain)
	if _, err := newCAEscrow(dst, true).ImportCAKey(dctx, envelope, []byte("pw")); !errors.Is(err, cgrpc.ErrIdentityExists) {
		t.Fatalf("ImportCAKey onto an established node = %v, want ErrIdentityExists", err)
	}
}

func TestImportBadPassphrase(t *testing.T) {
	src, ctx := newEscrowStore(t)
	keyBlob, keyPub, chain := makeSoftCA(t, "Root")
	commitCA(t, src, ctx, keyBlob, keyPub, chain)
	envelope, err := newCAEscrow(src, true).ExportCAKey(ctx, []byte("right"))
	if err != nil {
		t.Fatalf("ExportCAKey: %v", err)
	}

	dst, dctx := newEscrowStore(t)
	_, err = newCAEscrow(dst, true).ImportCAKey(dctx, envelope, []byte("wrong"))
	if err == nil {
		t.Fatal("ImportCAKey with a wrong passphrase should error")
	}
}
