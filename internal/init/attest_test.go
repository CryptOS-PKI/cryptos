package init

/*
Apache License 2.0

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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// newSoftKeyLoader returns a node.KeyLoader over a freshly generated software
// ECDSA-P384 key (the same backend production selects in nodeID/dev mode), for
// tests that need a real crypto.Signer without standing up an embedded etcd
// store or a TPM.
func newSoftKeyLoader(t *testing.T) node.KeyLoader {
	t.Helper()
	var b softRootBackend
	created, err := b.CreateKey(tpm.AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return func(_ context.Context) (crypto.Signer, func(), error) {
		signer, err := b.LoadKey(created.Private, created.Public)
		if err != nil {
			return nil, nil, err
		}
		return signer, func() { _ = signer.Close() }, nil
	}
}

// TestNewAttester_NilLoaderRejected verifies newAttester fails closed on a nil
// key loader.
func TestNewAttester_NilLoaderRejected(t *testing.T) {
	if _, err := newAttester(nil); err == nil {
		t.Fatal("newAttester(nil): want error, got nil")
	}
}

// TestAttester_SignNonceVerifies signs a nonce with the production attester
// over a software identity key and verifies the returned ASN.1 DER signature
// against the returned PKIX/DER public key with ecdsa.VerifyASN1, over the
// SHA-384 digest the attester is specified to sign.
func TestAttester_SignNonceVerifies(t *testing.T) {
	att, err := newAttester(newSoftKeyLoader(t))
	if err != nil {
		t.Fatalf("newAttester: %v", err)
	}

	nonce := []byte("fleet-manager-challenge-nonce")
	sig, pubDER, err := att.SignNonce(context.Background(), nonce)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}
	if len(sig) == 0 || len(pubDER) == 0 {
		t.Fatal("SignNonce returned empty signature or public key")
	}

	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", pubAny)
	}
	digest := sha512.Sum384(cgrpc.AttestationMessage(nonce))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("VerifyASN1: signature does not verify against the returned public key")
	}
	raw := sha512.Sum384(nonce)
	if ecdsa.VerifyASN1(pub, raw[:], sig) {
		t.Fatal("VerifyASN1: signature verifies over SHA-384 of the bare nonce; want it bound to the attestation context")
	}
}

// attestTestCA builds an attester over a software CA key and a self-signed CA
// certificate for that same key, for the forgery tests below.
func attestTestCA(t *testing.T) (*nodeAttester, *x509.Certificate, crypto.Signer) {
	t.Helper()
	load := newSoftKeyLoader(t)
	signer, closeFn, err := load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(closeFn)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "attest test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("CreateCertificate(CA): %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}
	att, err := newAttester(load)
	if err != nil {
		t.Fatalf("newAttester: %v", err)
	}
	return att, caCert, signer
}

// spliceSignature re-wraps tbs with sig under ecdsa-with-SHA384, the same
// outer shape (tbs, algorithm, BIT STRING) Certificate and CertificateList use.
func spliceSignature(t *testing.T, tbs, sig []byte) []byte {
	t.Helper()
	out, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		TBS:       asn1.RawValue{FullBytes: tbs},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}},
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatalf("marshal spliced structure: %v", err)
	}
	return out
}

// TestAttest_SignatureCannotForgeCertificate hands Attest the TBSCertificate
// of an attacker-chosen certificate as the nonce and checks the returned
// signature does not make a certificate that verifies under the CA.
func TestAttest_SignatureCannotForgeCertificate(t *testing.T) {
	att, caCert, signer := attestTestCA(t)
	leafKey, err := ecdsa.GenerateKey(caCert.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x7a7a),
		Subject:               pkix.Name{CommonName: "forged intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	legit, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf): %v", err)
	}
	legitCert, err := x509.ParseCertificate(legit)
	if err != nil {
		t.Fatalf("ParseCertificate(leaf): %v", err)
	}
	tbs := legitCert.RawTBSCertificate

	sig, _, err := att.SignNonce(context.Background(), tbs)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}
	if err := caCert.CheckSignature(x509.ECDSAWithSHA384, tbs, sig); err == nil {
		t.Fatal("Attest signature verifies as a CA signature over the TBSCertificate")
	}
	forged, err := x509.ParseCertificate(spliceSignature(t, tbs, sig))
	if err != nil {
		t.Fatalf("ParseCertificate(forged): %v", err)
	}
	if err := forged.CheckSignatureFrom(caCert); err == nil {
		t.Fatal("certificate built from an Attest signature verifies under the CA")
	}
}

// TestAttest_SignatureCannotForgeCRL does the same for a TBSCertList.
func TestAttest_SignatureCannotForgeCRL(t *testing.T) {
	att, caCert, signer := attestTestCA(t)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:             big.NewInt(9),
		ThisUpdate:         time.Now(),
		NextUpdate:         time.Now().Add(time.Hour),
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}, caCert, signer)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	tbs := crl.RawTBSRevocationList

	sig, _, err := att.SignNonce(context.Background(), tbs)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}
	forged, err := x509.ParseRevocationList(spliceSignature(t, tbs, sig))
	if err != nil {
		t.Fatalf("ParseRevocationList(forged): %v", err)
	}
	if err := forged.CheckSignatureFrom(caCert); err == nil {
		t.Fatal("CRL built from an Attest signature verifies under the CA")
	}
}

// TestAttest_SignatureCannotForgeOCSP does the same for an OCSP ResponseData,
// checked the way an OCSP client checks a CA-signed response.
func TestAttest_SignatureCannotForgeOCSP(t *testing.T) {
	att, caCert, signer := attestTestCA(t)
	respDER, err := ocsp.CreateResponse(caCert, caCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(0x7a7a),
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
	}, signer)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	resp, err := ocsp.ParseResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	tbs := resp.TBSResponseData

	sig, _, err := att.SignNonce(context.Background(), tbs)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}
	if err := caCert.CheckSignature(x509.ECDSAWithSHA384, tbs, sig); err == nil {
		t.Fatal("OCSP ResponseData verifies under the CA with an Attest signature")
	}
}

// TestAttester_LoadErrorPropagates verifies a key-loader failure surfaces as
// an error rather than a nil signer being dereferenced.
func TestAttester_LoadErrorPropagates(t *testing.T) {
	wantErr := errors.New("boom")
	att, err := newAttester(func(_ context.Context) (crypto.Signer, func(), error) {
		return nil, nil, wantErr
	})
	if err != nil {
		t.Fatalf("newAttester: %v", err)
	}
	if _, _, err := att.SignNonce(context.Background(), []byte("nonce")); err == nil {
		t.Fatal("SignNonce: want error, got nil")
	}
}
