package e2e_test

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

// This file drives same-key re-certification of an intermediate end to end
// over real gRPC servers (the local-socket transport cryptosctl uses on-box):
// the root signs the intermediate with no revocation pointers, the root is then
// configured with a revocation base URL, and the intermediate's renewal CSR is
// signed by the root and submitted back. The intermediate keeps its key, subject
// and SKI, now carries CDP/OCSP/caIssuers pointers, and certificates it issued
// before the swap still verify through the renewed certificate.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	stdgrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	cinit "github.com/CryptOS-PKI/cryptos/internal/init"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

type nopAuditor struct{}

func (nopAuditor) Append(*cryptosv1.AuditEvent) error { return nil }

// serveLocal starts cfg on a UNIX socket (the on-box transport) and returns a
// client for it.
func serveLocal(t *testing.T, cfg cgrpc.ServerConfig) cryptosv1.NodeServiceClient {
	t.Helper()
	dir, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg.Auditor = nopAuditor{}
	srv, err := cgrpc.NewLocal(cfg)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := stdgrpc.NewClient("unix://"+sock, stdgrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return cryptosv1.NewNodeServiceClient(conn)
}

// storeKeyLoader reloads the CA key from the store's canonical key location on
// every call, exactly as production's keyLoader in internal/init/run.go does.
func storeKeyLoader(store *node.Store) node.KeyLoader {
	backend := cinit.NewSoftRootBackend()
	return func(ctx context.Context) (crypto.Signer, func(), error) {
		priv, pub, ok, err := store.RootKeyBlobs(ctx)
		if err != nil || !ok {
			return nil, nil, err
		}
		signer, err := backend.LoadKey(priv, pub)
		if err != nil {
			return nil, nil, err
		}
		return signer, func() { _ = signer.Close() }, nil
	}
}

// storeIssuer reads the node's CA certificate from the store on every call, as
// production's issuerFunc does. This is what lets a renewal take effect live.
func storeIssuer(store *node.Store) node.IssuerFunc {
	return func(ctx context.Context) (*x509.Certificate, error) {
		id, err := store.Identity(ctx)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(id.ChainDer[0])
	}
}

func TestRecertifyIntermediateE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	// Root: real ceremony; its live config is a pointer the test edits later.
	rootStore := newStore(t)
	establishRoot(t, ctx, rootStore)
	rootCfg := rootProfilesConfig()
	rootSigner := node.NewCASigner(storeKeyLoader(rootStore), storeIssuer(rootStore),
		func(context.Context) (*config.Config, error) { return rootCfg, nil }).
		WithPreflight(func(context.Context) bool { return true })
	root := serveLocal(t, cgrpc.ServerConfig{SubordinateSigner: rootSigner, LeafSigner: rootSigner})
	rootID, err := rootStore.Identity(ctx)
	if err != nil {
		t.Fatalf("root Identity: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootID.ChainDer[0])
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw}))

	// Intermediate: staged with a software key, wired like production.
	subStore := newStore(t)
	subKey := newP384Key(t)
	subCSR := buildCSR(t, subKey, pkix.Name{CommonName: "ACME Issuing G1"})
	if err := subStore.StageSubordinate(ctx, subCSR, marshalECKey(t, subKey), marshalECPub(t, subKey)); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	subCfg := subordinateConfig(t, rootPEM)
	parentTrust, err := subCfg.ParentTrust()
	if err != nil {
		t.Fatalf("ParentTrust: %v", err)
	}
	enr, err := node.NewSubordinateEnroller(subStore, parentTrust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	subLoad := storeKeyLoader(subStore)
	renewer, err := cinit.NewRenewer(subStore, subLoad, enr)
	if err != nil {
		t.Fatalf("NewRenewer: %v", err)
	}
	subSigner := node.NewCASigner(subLoad, storeIssuer(subStore),
		func(context.Context) (*config.Config, error) { return subCfg, nil })
	sub := serveLocal(t, cgrpc.ServerConfig{
		SubordinateEnroller: enr,
		Renewer:             renewer,
		LeafSigner:          subSigner,
	})

	// First enrolment: root has no revocation_base_url, so no pointers.
	csrResp, err := sub.GetSubordinateCSR(ctx, &cryptosv1.GetSubordinateCSRRequest{})
	if err != nil {
		t.Fatalf("GetSubordinateCSR: %v", err)
	}
	signed, err := root.SignSubordinateCSR(ctx, &cryptosv1.SignSubordinateCSRRequest{CsrDer: csrResp.GetCsrDer(), ProfileName: "sub-ca"})
	if err != nil {
		t.Fatalf("SignSubordinateCSR: %v", err)
	}
	if _, err := sub.SubmitSubordinateCertificate(ctx, &cryptosv1.SubmitSubordinateCertificateRequest{ChainDer: signed.GetChainDer()}); err != nil {
		t.Fatalf("SubmitSubordinateCertificate: %v", err)
	}
	oldCert, _ := x509.ParseCertificate(signed.GetChainDer()[0])
	if len(oldCert.CRLDistributionPoints) != 0 || len(oldCert.IssuingCertificateURL) != 0 {
		t.Fatal("first-enrolment certificate unexpectedly carries revocation pointers")
	}

	// The intermediate issues a leaf under the original certificate.
	leafKey := newP384Key(t)
	before, err := sub.IssueLeaf(ctx, &cryptosv1.IssueLeafRequest{
		CsrDer: buildCSR(t, leafKey, pkix.Name{CommonName: "before.acme.example"}), ProfileName: "leaf",
	})
	if err != nil {
		t.Fatalf("IssueLeaf (before): %v", err)
	}
	beforeLeaf, _ := x509.ParseCertificate(before.GetCertDer())

	// The root is now configured with a revocation base URL.
	const base = "http://pki.acme.example"
	rootCfg.PKI.RevocationBaseURL = base

	// Re-certify: renewal CSR -> root sign-subordinate -> submit.
	renewCSR, err := sub.GetRenewalCSR(ctx, &cryptosv1.GetRenewalCSRRequest{})
	if err != nil {
		t.Fatalf("GetRenewalCSR: %v", err)
	}
	resigned, err := root.SignSubordinateCSR(ctx, &cryptosv1.SignSubordinateCSRRequest{CsrDer: renewCSR.GetCsrDer(), ProfileName: "sub-ca"})
	if err != nil {
		t.Fatalf("SignSubordinateCSR (renewal): %v", err)
	}
	submitted, err := sub.SubmitRenewedCertificate(ctx, &cryptosv1.SubmitRenewedCertificateRequest{ChainDer: resigned.GetChainDer()})
	if err != nil {
		t.Fatalf("SubmitRenewedCertificate: %v", err)
	}
	newCert, _ := x509.ParseCertificate(resigned.GetChainDer()[0])

	// Same key, subject and SKI; a new certificate with the pointers.
	oldPub, _ := x509.MarshalPKIXPublicKey(oldCert.PublicKey)
	newPub, _ := x509.MarshalPKIXPublicKey(newCert.PublicKey)
	switch {
	case !bytes.Equal(oldPub, newPub):
		t.Error("renewed certificate carries a different key")
	case !bytes.Equal(oldCert.RawSubject, newCert.RawSubject):
		t.Error("renewed certificate subject changed")
	case !bytes.Equal(oldCert.SubjectKeyId, newCert.SubjectKeyId) || len(newCert.SubjectKeyId) == 0:
		t.Error("renewed certificate SKI changed")
	case newCert.SerialNumber.Cmp(oldCert.SerialNumber) == 0:
		t.Error("renewed certificate reuses the old serial")
	}
	if got := newCert.CRLDistributionPoints; len(got) != 1 || got[0] != base+"/crl" {
		t.Errorf("renewed CDP = %v, want [%s/crl]", got, base)
	}
	if got := newCert.OCSPServer; len(got) != 1 || got[0] != base+"/ocsp" {
		t.Errorf("renewed AIA OCSP = %v, want [%s/ocsp]", got, base)
	}
	if got := newCert.IssuingCertificateURL; len(got) != 1 || got[0] != base+"/ca.cer" {
		t.Errorf("renewed AIA caIssuers = %v, want [%s/ca.cer]", got, base)
	}

	// The node serves the renewed chain and kept the old certificate.
	if !bytes.Equal(submitted.GetIdentity().GetChainDer()[0], newCert.Raw) {
		t.Error("SubmitRenewedCertificate did not return the renewed identity")
	}
	idResp, err := subStore.Identity(ctx)
	if err != nil || !bytes.Equal(idResp.GetChainDer()[0], newCert.Raw) {
		t.Fatalf("served identity is not the renewed certificate (err=%v)", err)
	}
	hist, err := subStore.CertificateHistory(ctx)
	if err != nil || len(hist) != 1 || !bytes.Equal(hist[0], oldCert.Raw) {
		t.Fatalf("certificate history = %d entries (err=%v), want the replaced certificate", len(hist), err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	viaNew := x509.NewCertPool()
	viaNew.AddCert(newCert)
	opts := x509.VerifyOptions{Roots: roots, Intermediates: viaNew, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}

	// A leaf issued BEFORE the swap verifies through the renewed certificate.
	if _, err := beforeLeaf.Verify(opts); err != nil {
		t.Errorf("pre-renewal leaf does not verify through the renewed certificate: %v", err)
	}
	if !bytes.Equal(beforeLeaf.AuthorityKeyId, newCert.SubjectKeyId) {
		t.Error("pre-renewal leaf AKI does not match the renewed SKI")
	}

	// Without a reboot, the next issuance is signed under the renewed certificate.
	after, err := sub.IssueLeaf(ctx, &cryptosv1.IssueLeafRequest{
		CsrDer: buildCSR(t, leafKey, pkix.Name{CommonName: "after.acme.example"}), ProfileName: "leaf",
	})
	if err != nil {
		t.Fatalf("IssueLeaf (after): %v", err)
	}
	afterLeaf, _ := x509.ParseCertificate(after.GetCertDer())
	if _, err := afterLeaf.Verify(opts); err != nil {
		t.Errorf("post-renewal leaf does not verify through the renewed certificate: %v", err)
	}

	// Negative: a chain for a different key, signed by the same root under the
	// same profile, is refused and leaves the served certificate unchanged.
	other := newP384Key(t)
	foreign, err := root.SignSubordinateCSR(ctx, &cryptosv1.SignSubordinateCSRRequest{
		CsrDer: buildCSR(t, other, pkix.Name{CommonName: "ACME Issuing G1"}), ProfileName: "sub-ca",
	})
	if err != nil {
		t.Fatalf("SignSubordinateCSR (other key): %v", err)
	}
	if _, err := sub.SubmitRenewedCertificate(ctx, &cryptosv1.SubmitRenewedCertificateRequest{ChainDer: foreign.GetChainDer()}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("SubmitRenewedCertificate(other key) code = %v, want FailedPrecondition", status.Code(err))
	}
	if id, _ := subStore.Identity(ctx); !bytes.Equal(id.GetChainDer()[0], newCert.Raw) {
		t.Error("a refused renewal changed the served certificate")
	}

	// The root has no parent: the renewal RPCs are not wired there.
	if _, err := root.GetRenewalCSR(ctx, &cryptosv1.GetRenewalCSRRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("root GetRenewalCSR code = %v, want Unimplemented", status.Code(err))
	}
}
