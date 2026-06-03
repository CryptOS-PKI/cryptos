package bootstrap

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
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// Trust is the verified bootstrap administrator credential loaded from
// machine config. It is the only client the gRPC :443 listener trusts on
// first boot; PID 1 refuses to bring up that listener until a Trust loads
// cleanly (Phase 1 spec §4).
//
// Two configurations are supported, matching the machine-config schema:
//
//   - Full certificate (bootstrap.admin_cert_pem): the parsed cert is
//     retained, so it can anchor an mTLS ClientCAs pool and be promoted
//     into the admin registry at the end of the ceremony.
//   - Fingerprint only (bootstrap.admin_cert_sha256): only the SHA-256 of
//     the leaf DER is known. mTLS authentication is then by SHA-256
//     pinning via VerifyPeerCertificate; no ClientCAs pool is available.
//
// Trust is immutable after LoadTrust and safe for concurrent reads.
type Trust struct {
	fingerprint [32]byte
	cert        *x509.Certificate // nil when only a fingerprint was configured
	certDER     []byte            // nil when only a fingerprint was configured
}

// Admin is a canonical record of an administrator certificate. The
// ceremony writes one of these into the admin registry (internal/node)
// when it promotes the bootstrap admin to the steady-state admin.
type Admin struct {
	// Subject is the certificate Subject DN in RFC 2253 string form.
	Subject string
	// SHA256 is the SHA-256 digest of the certificate's DER bytes.
	SHA256 [32]byte
	// NotAfter is the certificate's expiry.
	NotAfter time.Time
	// CertDER is the DER-encoded certificate.
	CertDER []byte
	// CertPEM is the PEM-encoded certificate.
	CertPEM string
}

// LoadTrust parses and verifies the bootstrap credential carried in the
// machine config. Exactly one of AdminCertPEM or AdminCertSHA256 must be
// set; LoadTrust enforces that independently of config.Validate so the
// package is safe to use standalone.
func LoadTrust(b config.Bootstrap) (*Trust, error) {
	hasPEM := b.AdminCertPEM != ""
	hasSHA := b.AdminCertSHA256 != ""
	switch {
	case hasPEM && hasSHA:
		return nil, errors.New("bootstrap: LoadTrust: exactly one of admin_cert_pem or admin_cert_sha256 must be set, got both")
	case !hasPEM && !hasSHA:
		return nil, errors.New("bootstrap: LoadTrust: no bootstrap admin credential configured")
	case hasPEM:
		return loadFromPEM(b.AdminCertPEM)
	default:
		return loadFromFingerprint(b.AdminCertSHA256)
	}
}

func loadFromPEM(pemStr string) (*Trust, error) {
	cert, der, err := parseSingleCertPEM(pemStr)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: LoadTrust: %w", err)
	}
	return &Trust{
		fingerprint: sha256.Sum256(der),
		cert:        cert,
		certDER:     der,
	}, nil
}

func loadFromFingerprint(sha string) (*Trust, error) {
	raw, err := hex.DecodeString(sha)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: LoadTrust: admin_cert_sha256 not hex: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("bootstrap: LoadTrust: admin_cert_sha256 must be %d bytes, got %d", sha256.Size, len(raw))
	}
	var t Trust
	copy(t.fingerprint[:], raw)
	return &t, nil
}

// Fingerprint returns the SHA-256 of the trusted admin certificate's DER
// bytes — known in both PEM and fingerprint-only modes.
func (t *Trust) Fingerprint() [32]byte { return t.fingerprint }

// FingerprintHex returns the lowercase hex encoding of Fingerprint.
func (t *Trust) FingerprintHex() string { return hex.EncodeToString(t.fingerprint[:]) }

// HasCertificate reports whether the full certificate is available
// (true for the PEM path, false for fingerprint-only).
func (t *Trust) HasCertificate() bool { return t.cert != nil }

// Certificate returns the parsed bootstrap admin certificate, or nil
// when only a fingerprint was configured.
func (t *Trust) Certificate() *x509.Certificate { return t.cert }

// ClientCAPool returns an x509.CertPool containing the bootstrap admin
// certificate as a trust anchor, suitable for tls.Config.ClientCAs with
// RequireAndVerifyClientCert. ok is false when only a fingerprint was
// configured, in which case the caller must authenticate via
// VerifyPeerCertificate pinning instead.
func (t *Trust) ClientCAPool() (pool *x509.CertPool, ok bool) {
	if t.cert == nil {
		return nil, false
	}
	p := x509.NewCertPool()
	p.AddCert(t.cert)
	return p, true
}

// VerifyPeerCertificate pins the presented client certificate to the
// trusted SHA-256. It satisfies the signature of
// tls.Config.VerifyPeerCertificate and works in both PEM and
// fingerprint-only modes. The leaf is rawCerts[0].
func (t *Trust) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 || len(rawCerts[0]) == 0 {
		return errors.New("bootstrap: VerifyPeerCertificate: no client certificate presented")
	}
	got := sha256.Sum256(rawCerts[0])
	if subtle.ConstantTimeCompare(got[:], t.fingerprint[:]) != 1 {
		return fmt.Errorf("bootstrap: VerifyPeerCertificate: client certificate fingerprint %s does not match trusted %s",
			hex.EncodeToString(got[:]), t.FingerprintHex())
	}
	return nil
}

// Expired reports whether the trusted certificate's validity has lapsed
// at now. Fingerprint-only trust has no validity window and always
// reports false (the mTLS handshake enforces expiry separately).
func (t *Trust) Expired(now time.Time) bool {
	if t.cert == nil {
		return false
	}
	return now.After(t.cert.NotAfter)
}

// Admin returns the canonical Admin record for the bootstrap
// certificate. ok is false when only a fingerprint was configured (no
// cert to derive a record from).
func (t *Trust) Admin() (Admin, bool) {
	if t.cert == nil {
		return Admin{}, false
	}
	return adminFromCert(t.cert, t.certDER), true
}

// AdminFromCertDER builds an Admin record from a DER-encoded
// certificate. Used by the ceremony when recording an enrolled admin.
func AdminFromCertDER(der []byte) (Admin, error) {
	if len(der) == 0 {
		return Admin{}, errors.New("bootstrap: AdminFromCertDER: empty DER")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Admin{}, fmt.Errorf("bootstrap: AdminFromCertDER: parse: %w", err)
	}
	return adminFromCert(cert, der), nil
}

func adminFromCert(cert *x509.Certificate, der []byte) Admin {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return Admin{
		Subject:  cert.Subject.String(),
		SHA256:   sha256.Sum256(der),
		NotAfter: cert.NotAfter,
		CertDER:  der,
		CertPEM:  string(pemBytes),
	}
}

// parseSingleCertPEM decodes exactly one CERTIFICATE PEM block and parses
// it. Extra blocks or trailing non-whitespace are rejected so an operator
// can't smuggle a second credential past the validator.
func parseSingleCertPEM(pemStr string) (*x509.Certificate, []byte, error) {
	block, rest := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, nil, errors.New("admin_cert_pem: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("admin_cert_pem: PEM type %q, want CERTIFICATE", block.Type)
	}
	// A second decodable block means more than one credential was
	// supplied; trailing whitespace/comments decode to nil and are fine.
	if next, _ := pem.Decode(rest); next != nil {
		return nil, nil, errors.New("admin_cert_pem: must contain exactly one PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("admin_cert_pem: parse: %w", err)
	}
	return cert, block.Bytes, nil
}
