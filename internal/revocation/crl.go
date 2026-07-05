package revocation

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
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// CRLBuilder assembles an RFC 5280 certificate revocation list from the
// revoked set in a Store and signs it with the CA key. It holds no key
// material of its own: the signer and issuer are supplied per Build call, the
// same loader pattern the node uses for issuance.
type CRLBuilder struct {
	store      *Store
	nextUpdate time.Duration
}

// NewCRLBuilder returns a CRLBuilder that reads revoked records from store and
// sets each CRL's nextUpdate to now+nextUpdate.
func NewCRLBuilder(store *Store, nextUpdate time.Duration) *CRLBuilder {
	return &CRLBuilder{store: store, nextUpdate: nextUpdate}
}

// Build reads the revoked set, prunes any entry whose issued certificate has
// already expired at now (an expired certificate no longer needs to appear on
// the CRL, RFC 5280 §3.3), and returns the signed DER CRL. The CRL is signed
// by issuer using signer; crypto/x509 derives the signatureAlgorithm from the
// signer key, so a P-384 CA key yields ECDSA-SHA384.
func (b *CRLBuilder) Build(ctx context.Context, issuer *x509.Certificate, signer crypto.Signer, now time.Time) ([]byte, error) {
	revoked, err := b.store.ListRevoked(ctx)
	if err != nil {
		return nil, fmt.Errorf("revocation: Build: list revoked: %w", err)
	}

	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, rec := range revoked {
		issued, ok, err := b.store.GetIssued(ctx, rec.SerialHex)
		if err != nil {
			return nil, fmt.Errorf("revocation: Build: get issued %q: %w", rec.SerialHex, err)
		}
		// Prune entries whose certificate has already expired: such a
		// certificate is invalid on its own and need not stay on the CRL.
		if ok && !issued.NotAfter.IsZero() && issued.NotAfter.Before(now) {
			continue
		}
		serial, ok := new(big.Int).SetString(rec.SerialHex, 16)
		if !ok {
			return nil, fmt.Errorf("revocation: Build: bad serial hex %q", rec.SerialHex)
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: rec.RevokedAt,
			ReasonCode:     rec.ReasonCode,
		})
	}

	num, err := b.store.NextCRLNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("revocation: Build: crl number: %w", err)
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    new(big.Int).SetUint64(num),
		ThisUpdate:                now,
		NextUpdate:                now.Add(b.nextUpdate),
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, signer)
	if err != nil {
		return nil, fmt.Errorf("revocation: Build: create revocation list: %w", err)
	}
	return der, nil
}
