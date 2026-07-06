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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

// defaultOCSPResponderValidity is the lifetime of a minted delegated OCSP
// responder certificate (one week). The responder is re-minted at the halfway
// point (remaining life < validity/2), so a fresh responder is always at least
// half its life away from expiry.
const defaultOCSPResponderValidity = 168 * time.Hour

// oidOCSPNoCheck is id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1). A responder
// certificate carrying it tells relying parties not to check the responder's
// own revocation status, which is the standard treatment for a short-lived
// delegated responder cert.
var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// asn1NULL is the DER encoding of ASN.1 NULL, the value of the ocsp-nocheck
// extension.
var asn1NULL = []byte{0x05, 0x00}

// responderProfile builds the ca.Profile for a delegated OCSP responder
// certificate: an end-entity cert with digitalSignature key usage, the
// OCSPSigning extended key usage, a subject derived from the issuer CN, and the
// non-critical id-pkix-ocsp-nocheck extension.
func responderProfile(issuer *x509.Certificate, notBefore, notAfter time.Time) ca.Profile {
	return ca.Profile{
		Subject:     pkix.Name{CommonName: issuer.Subject.CommonName + " OCSP Responder"},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		IsCA:        false,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{{
			Id:       oidOCSPNoCheck,
			Critical: false,
			Value:    asn1NULL,
		}},
	}
}

// ocspResponder mints and renews this node's delegated OCSP responder
// certificate, backed by a dedicated software-backend key persisted in the
// node store. It holds the same CA key loader and issuer getter the CRL/OCSP
// closures use (reload-per-use, released via the loader's close fn), so the CA
// key is loaded only to mint/renew the responder cert, never per OCSP request.
type ocspResponder struct {
	store    *node.Store
	load     node.KeyLoader
	issuer   node.IssuerFunc
	validity time.Duration
}

// newOCSPResponder returns an ocspResponder using the given store, CA key
// loader, issuer getter, and responder-cert validity window. A zero validity
// falls back to defaultOCSPResponderValidity.
func newOCSPResponder(store *node.Store, load node.KeyLoader, issuer node.IssuerFunc, validity time.Duration) *ocspResponder {
	if validity <= 0 {
		validity = defaultOCSPResponderValidity
	}
	return &ocspResponder{store: store, load: load, issuer: issuer, validity: validity}
}

// ensure returns the current delegated OCSP responder certificate and its
// signing key, minting a fresh one when none is stored, the stored one fails to
// parse, or the stored one is inside the renewal window (remaining life less
// than half the validity). A freshly minted responder is persisted before it is
// returned, so a later ensure (or a restart) reuses it until renewal.
func (r *ocspResponder) ensure(ctx context.Context) (*x509.Certificate, crypto.Signer, error) {
	if cert, key, ok := r.loadStored(ctx); ok {
		return cert, key, nil
	}
	return r.mint(ctx)
}

// loadStored returns the persisted responder cert+key when one exists, parses,
// and is still outside the renewal window. Any failure (absent, unparsable,
// expiring) reports ok=false so the caller re-mints.
func (r *ocspResponder) loadStored(ctx context.Context) (*x509.Certificate, crypto.Signer, bool) {
	certDER, keyBlob, _, ok, err := r.store.OCSPResponder(ctx)
	if err != nil || !ok {
		return nil, nil, false
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, false
	}
	remaining := time.Until(cert.NotAfter)
	if remaining < r.validity/2 {
		return nil, nil, false
	}
	key, err := x509.ParseECPrivateKey(keyBlob)
	if err != nil {
		return nil, nil, false
	}
	return cert, key, true
}

// mint generates a fresh P-384 responder key, signs a responder certificate
// with the CA key + issuer (loaded per use and released immediately), persists
// both, and returns them.
func (r *ocspResponder) mint(ctx context.Context) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("init: generate OCSP responder key: %w", err)
	}

	signer, closeFn, err := r.load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("init: load CA key for OCSP responder: %w", err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	issuerCert, err := r.issuer(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("init: load issuer for OCSP responder: %w", err)
	}

	now := time.Now().UTC()
	prof := responderProfile(issuerCert, now, now.Add(r.validity))
	der, _, err := ca.Sign(prof, key.Public(), issuerCert, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("init: sign OCSP responder cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("init: parse OCSP responder cert: %w", err)
	}

	keyBlob, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("init: marshal OCSP responder key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("init: marshal OCSP responder public key: %w", err)
	}
	if err := r.store.PutOCSPResponder(ctx, der, keyBlob, keyPublic); err != nil {
		return nil, nil, fmt.Errorf("init: persist OCSP responder: %w", err)
	}
	return cert, key, nil
}
