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
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"testing"

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
	digest := sha512.Sum384(nonce)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("VerifyASN1: signature does not verify against the returned public key")
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
