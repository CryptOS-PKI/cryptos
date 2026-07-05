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
	"crypto/x509"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ocspNextUpdate is how far ahead an OCSP response advertises its validity. It
// mirrors the CRL refresh cadence closely enough that clients re-query within a
// day of a revocation taking effect.
const ocspNextUpdate = 24 * time.Hour

// OCSPResponder answers RFC 6960 OCSP requests from the revocation Store. Like
// the CRL builder it holds no key material: the issuer certificate and signer
// are supplied per Respond call, the same loader pattern the node uses for
// issuance.
type OCSPResponder struct {
	store *Store
}

// NewOCSPResponder returns an OCSPResponder backed by store.
func NewOCSPResponder(store *Store) *OCSPResponder {
	return &OCSPResponder{store: store}
}

// Respond parses the DER-encoded OCSP request in reqDER, looks the requested
// serial up in the store, and returns a signed DER OCSP response. The status is
// Revoked when the serial has a revoked record, Good when it is issued but not
// revoked, and Unknown when the store has no issued record for it. The response
// is signed directly by the issuer (issuer == responder), which matches the
// CryptOS single-key CA model. A malformed request returns an error so the HTTP
// layer can emit the RFC 6960 malformedRequest bytes.
func (r *OCSPResponder) Respond(ctx context.Context, reqDER []byte, issuer *x509.Certificate, signer crypto.Signer, now time.Time) ([]byte, error) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("revocation: Respond: parse request: %w", err)
	}

	serialHex := req.SerialNumber.Text(16)

	tmpl := ocsp.Response{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(ocspNextUpdate),
	}

	if revoked, ok, err := r.store.GetRevoked(ctx, serialHex); err != nil {
		return nil, fmt.Errorf("revocation: Respond: get revoked %q: %w", serialHex, err)
	} else if ok {
		tmpl.Status = ocsp.Revoked
		tmpl.RevokedAt = revoked.RevokedAt
		tmpl.RevocationReason = revoked.ReasonCode
	} else if _, issued, err := r.store.GetIssued(ctx, serialHex); err != nil {
		return nil, fmt.Errorf("revocation: Respond: get issued %q: %w", serialHex, err)
	} else if issued {
		tmpl.Status = ocsp.Good
	} else {
		tmpl.Status = ocsp.Unknown
	}

	respDER, err := ocsp.CreateResponse(issuer, issuer, tmpl, signer)
	if err != nil {
		return nil, fmt.Errorf("revocation: Respond: create response: %w", err)
	}
	return respDER, nil
}
