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
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/revocation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// defaultCRLNextUpdateHours is the CRL validity window used when the config
// leaves crl_next_update_hours at zero (one week).
const defaultCRLNextUpdateHours = 168

// defaultRevocationHTTPPort is the anonymous CRL/OCSP listener port used when
// the config leaves revocation_http_port at zero.
const defaultRevocationHTTPPort = 80

// nonzero returns v when it is non-zero, otherwise the fallback. It lets the
// wiring apply documented defaults for optional config fields.
func nonzero(v, fallback uint32) uint32 {
	if v == 0 {
		return fallback
	}
	return v
}

// issuedRecorder returns a CASigner recorder that parses a freshly minted
// certificate and persists it into the revocation issued set. The recorder is
// called after a successful Sign but before the certificate is returned to the
// caller, so the issued set never drifts from what a caller received.
func issuedRecorder(store *revocation.Store) func(ctx context.Context, der []byte, profileName string) error {
	return func(ctx context.Context, der []byte, profileName string) error {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("init: parse issued certificate: %w", err)
		}
		return store.RecordIssued(ctx, issuedRecordFromCert(cert, profileName))
	}
}

// issuedRecordFromCert maps a parsed certificate to a revocation.IssuedRecord.
// The serial hex is the single join key shared with the CRL and OCSP paths.
func issuedRecordFromCert(cert *x509.Certificate, profileName string) revocation.IssuedRecord {
	return revocation.IssuedRecord{
		SerialHex:   cert.SerialNumber.Text(16),
		SubjectDN:   cert.Subject.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		SKIHex:      hex.EncodeToString(cert.SubjectKeyId),
		ProfileName: profileName,
		IssuedAt:    time.Now().UTC(),
	}
}

// nodeRevoker adapts a revocation.Store plus a CRL rebuild to the
// grpc.Revoker interface. Revoke records the revocation and then rebuilds the
// published CRL so the anonymous /crl endpoint reflects the new state on its
// next fetch. It is wired only on the management listeners.
type nodeRevoker struct {
	store      *revocation.Store
	crlBuilder *revocation.CRLBuilder
	load       node.KeyLoader
	issuer     node.IssuerFunc
}

// Revoke marks serialHex revoked with the given reason, then rebuilds the CRL
// cache. The store reports revocation.ErrNotIssued for a serial this node never
// issued; the handler maps that to NotFound. A CRL rebuild failure is surfaced
// so the caller learns the published CRL did not refresh, even though the store
// write already committed.
func (r *nodeRevoker) Revoke(ctx context.Context, serialHex string, reason int) (*cryptosv1.Revocation, error) {
	rec, err := r.store.Revoke(ctx, serialHex, reason, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if _, err := r.buildCRL(ctx); err != nil {
		return nil, fmt.Errorf("init: rebuild CRL after revoke: %w", err)
	}
	return revocationToProto(rec), nil
}

// ListIssued returns this node's issued-certificate inventory.
func (r *nodeRevoker) ListIssued(ctx context.Context) ([]*cryptosv1.IssuedCert, error) {
	recs, err := r.store.ListIssued(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*cryptosv1.IssuedCert, 0, len(recs))
	for _, rec := range recs {
		out = append(out, issuedToProto(rec))
	}
	return out, nil
}

// ListRevocations returns this node's revoked-certificate inventory.
func (r *nodeRevoker) ListRevocations(ctx context.Context) ([]*cryptosv1.Revocation, error) {
	recs, err := r.store.ListRevoked(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*cryptosv1.Revocation, 0, len(recs))
	for _, rec := range recs {
		out = append(out, revocationToProto(rec))
	}
	return out, nil
}

// buildCRL loads the CA key and issuer via the same loader/issuer used for
// signing (reload-per-use, released via the loader's close fn) and builds the
// signed DER CRL. It is used both by the anonymous /crl endpoint and to refresh
// the CRL after a revoke.
func (r *nodeRevoker) buildCRL(ctx context.Context) ([]byte, error) {
	signer, closeFn, err := r.load(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: load CA key for CRL: %w", err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	issuer, err := r.issuer(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: load issuer for CRL: %w", err)
	}
	return r.crlBuilder.Build(ctx, issuer, signer, time.Now().UTC())
}

// crlFn returns the /crl provider closure for the anonymous HTTP listener: it
// loads the CA key + issuer per use and builds a fresh signed CRL.
func (r *nodeRevoker) crlFn() func(ctx context.Context) ([]byte, error) {
	return r.buildCRL
}

// ocspFn returns the /ocsp responder closure for the anonymous HTTP listener:
// it loads the CA key + issuer per use and answers a parsed OCSP request from
// the store via resp.
func (r *nodeRevoker) ocspFn(resp *revocation.OCSPResponder) func(ctx context.Context, reqDER []byte) ([]byte, error) {
	return func(ctx context.Context, reqDER []byte) ([]byte, error) {
		signer, closeFn, err := r.load(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load CA key for OCSP: %w", err)
		}
		if closeFn != nil {
			defer closeFn()
		}
		issuer, err := r.issuer(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load issuer for OCSP: %w", err)
		}
		return resp.Respond(ctx, reqDER, issuer, signer, time.Now().UTC())
	}
}

// issuedToProto maps a stored IssuedRecord to its wire form.
func issuedToProto(r revocation.IssuedRecord) *cryptosv1.IssuedCert {
	return &cryptosv1.IssuedCert{
		SerialHex:   r.SerialHex,
		SubjectDn:   r.SubjectDN,
		NotBefore:   timestamppb.New(r.NotBefore),
		NotAfter:    timestamppb.New(r.NotAfter),
		SkiHex:      r.SKIHex,
		ProfileName: r.ProfileName,
		IssuedAt:    timestamppb.New(r.IssuedAt),
	}
}

// revocationToProto maps a stored RevokedRecord to its wire form.
func revocationToProto(r revocation.RevokedRecord) *cryptosv1.Revocation {
	return &cryptosv1.Revocation{
		SerialHex:  r.SerialHex,
		RevokedAt:  timestamppb.New(r.RevokedAt),
		ReasonCode: int32(r.ReasonCode),
	}
}
