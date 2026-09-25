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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/revocation"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// signIntermediate signs a pathLen-1 intermediate for pub under the parent, with
// or without revocation pointers.
func (p *rekeyParent) signIntermediate(t *testing.T, pub crypto.PublicKey, base string) []byte {
	t.Helper()
	now := time.Now()
	pathLen := 1
	prof := ca.Profile{
		Subject:   pkix.Name{CommonName: "Child Issuing CA"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(12 * time.Hour),
		IsCA:      true,
		PathLen:   &pathLen,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if base != "" {
		prof.CRLDistributionPoints = []string{base + "/crl"}
		prof.OCSPServer = []string{base + "/ocsp"}
		prof.IssuingCertificateURL = []string{base + "/ca.cer"}
	}
	der, _, err := ca.Sign(prof, pub, p.cert, p.key)
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	return der
}

// TestRecertifiedIssuerIsLiveEverywhere wires the issuer consumers exactly as
// run.go does (a store-backed key loader and issuer getter shared by the
// signer, the revoker's /crl, /ocsp and /ca.cer closures, the delegated OCSP
// responder and EST /cacerts) and proves that after a same-key renewal each of
// them serves or chains to the NEW CA certificate with no restart.
func TestRecertifiedIssuerIsLiveEverywhere(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
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
	revStore := revocation.NewStore(cli)

	// Establish the intermediate with a software key and no pointers.
	parent := newRekeyParent(t)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	blob, _ := x509.MarshalECPrivateKey(key)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Child Issuing CA"}}, key)
	if err := store.StageSubordinate(ctx, csr, blob, pub); err != nil {
		t.Fatalf("StageSubordinate: %v", err)
	}
	if err := store.CommitSubordinateCert(ctx, [][]byte{parent.signIntermediate(t, &key.PublicKey, ""), parent.der}); err != nil {
		t.Fatalf("CommitSubordinateCert: %v", err)
	}

	// Production wiring (internal/init/run.go).
	backend := NewSoftRootBackend()
	load := func(ctx context.Context) (crypto.Signer, func(), error) {
		priv, pub, _, err := store.RootKeyBlobs(ctx)
		if err != nil {
			return nil, nil, err
		}
		s, err := backend.LoadKey(priv, pub)
		if err != nil {
			return nil, nil, err
		}
		return s, func() { _ = s.Close() }, nil
	}
	issuer := func(ctx context.Context) (*x509.Certificate, error) {
		id, err := store.Identity(ctx)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(id.ChainDer[0])
	}
	pathLen := uint32(0)
	cfg := &config.Config{PKI: config.PKI{Profiles: []config.CertificateProfile{
		{Name: "leaf", ValidityDays: 30, KeyUsage: []string{"digital_signature"}, ExtKeyUsage: []string{"server_auth"}},
		{Name: "sub", ValidityDays: 30, KeyUsage: []string{"cert_sign", "crl_sign"},
			BasicConstraints: config.BasicConstraints{IsCA: true, PathLen: &pathLen}},
	}}}
	signer := node.NewCASigner(load, issuer, func(context.Context) (*config.Config, error) { return cfg, nil }).
		WithRecorder(issuedRecorder(revStore))
	revoker := &nodeRevoker{store: revStore, crlBuilder: revocation.NewCRLBuilder(revStore, time.Hour), load: load, issuer: issuer}
	responder := newOCSPResponder(store, load, issuer, 0)
	ocspFn := revoker.ocspFn(revocation.NewOCSPResponder(revStore), responder)

	// Before the swap: a leaf, and the delegated OCSP responder minted.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leafCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc.example"}}, leafKey)
	leafChain, _, err := signer.IssueLeafForNames(ctx, leafCSR, "leaf", nil)
	if err != nil {
		t.Fatalf("IssueLeafForNames (before): %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafChain[0])
	respBefore, _, err := responder.ensure(ctx)
	if err != nil {
		t.Fatalf("OCSP responder ensure: %v", err)
	}

	// Re-certify through the real renewer and enroller.
	trust, err := bootstrap.LoadTrust(certPEM(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	enr, err := node.NewSubordinateEnroller(store, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	renewer, err := NewRenewer(store, load, enr)
	if err != nil {
		t.Fatalf("NewRenewer: %v", err)
	}
	renewalCSR, err := renewer.RenewalCSR(ctx)
	if err != nil {
		t.Fatalf("RenewalCSR: %v", err)
	}
	parsedCSR, _ := x509.ParseCertificateRequest(renewalCSR)
	newDER := parent.signIntermediate(t, parsedCSR.PublicKey, "http://pki.example.test")
	if _, err := renewer.AcceptRenewal(ctx, [][]byte{newDER, parent.der}); err != nil {
		t.Fatalf("AcceptRenewal: %v", err)
	}
	newCert, _ := x509.ParseCertificate(newDER)

	// /ca.cer serves the new certificate.
	caCer, err := revoker.caCertFn()(ctx)
	if err != nil || !bytes.Equal(caCer, newDER) {
		t.Errorf("/ca.cer does not serve the renewed certificate (err=%v)", err)
	}
	// EST /cacerts serves the new certificate.
	if got, err := estCAChain(issuer)(ctx); err != nil || len(got) != 1 || !bytes.Equal(got[0], newDER) {
		t.Errorf("EST /cacerts does not serve the renewed certificate (err=%v)", err)
	}

	// IssueLeaf and SignSubordinate return chains that carry the new certificate.
	afterChain, _, err := signer.IssueLeafForNames(ctx, leafCSR, "leaf", nil)
	if err != nil || len(afterChain) != 2 || !bytes.Equal(afterChain[1], newDER) {
		t.Errorf("IssueLeaf chain does not carry the renewed certificate (err=%v)", err)
	}
	childKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	childCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Grandchild CA"}}, childKey)
	subChain, _, err := signer.SignSubordinate(ctx, childCSR, "sub")
	if err != nil || len(subChain) != 2 || !bytes.Equal(subChain[1], newDER) {
		t.Errorf("SignSubordinate chain does not carry the renewed certificate (err=%v)", err)
	}

	// The CRL names the new certificate's subject and SKI and verifies under it.
	crlDER, err := revoker.crlFn()(ctx)
	if err != nil {
		t.Fatalf("crlFn: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(newCert); err != nil {
		t.Errorf("CRL does not verify under the renewed certificate: %v", err)
	}
	if !bytes.Equal(crl.RawIssuer, newCert.RawSubject) || !bytes.Equal(crl.AuthorityKeyId, newCert.SubjectKeyId) {
		t.Error("CRL issuer name or AKI does not match the renewed certificate")
	}

	// OCSP: the delegated responder is NOT re-minted (same CA name and key), and
	// both it and the response validate against the new certificate.
	respAfter, _, err := responder.ensure(ctx)
	if err != nil {
		t.Fatalf("OCSP responder ensure (after): %v", err)
	}
	if respAfter.SerialNumber.Cmp(respBefore.SerialNumber) != 0 {
		t.Error("the delegated OCSP responder was re-minted; it should stay valid across a same-key renewal")
	}
	if err := respAfter.CheckSignatureFrom(newCert); err != nil {
		t.Errorf("delegated responder cert does not verify under the renewed certificate: %v", err)
	}
	if !bytes.Equal(respAfter.RawIssuer, newCert.RawSubject) || !bytes.Equal(respAfter.AuthorityKeyId, newCert.SubjectKeyId) {
		t.Error("delegated responder issuer name or AKI does not match the renewed certificate")
	}
	reqDER, err := ocsp.CreateRequest(leaf, newCert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	ocspDER, err := ocspFn(ctx, reqDER)
	if err != nil {
		t.Fatalf("ocspFn: %v", err)
	}
	parsed, err := ocsp.ParseResponseForCert(ocspDER, leaf, newCert)
	if err != nil {
		t.Fatalf("OCSP response does not validate against the renewed certificate: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("OCSP status for the pre-renewal leaf = %d, want Good", parsed.Status)
	}
}
