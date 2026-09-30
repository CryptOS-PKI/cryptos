package scep

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
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// RAKeyBits is the RA key size. Key transport needs an RSA recipient, and the
// node's own keys stay at RSA 3072 or stronger.
const RAKeyBits = 3072

// raCert is one RA certificate with its key.
type raCert struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// MintRAFunc signs an RA certificate over pub with the node's CA key, valid
// from notBefore to notAfter, with key usage digitalSignature and
// keyEncipherment, and returns its DER. The CA key signs the certificate and
// nothing else: the RA key decrypts requests and signs replies.
type MintRAFunc func(ctx context.Context, pub *rsa.PublicKey, notBefore, notAfter time.Time) ([]byte, error)

// IssuerCertFunc returns the node's current CA certificate.
type IssuerCertFunc func(ctx context.Context) (*x509.Certificate, error)

// RAManager keeps the node's RA certificates: it mints the first one, mints a
// successor when the newest enters its rotation overlap, and drops expired
// ones. During the overlap both RAs decrypt, so a device that cached the old
// RA certificate from GetCACert still enrols; GetCACert offers the newest.
//
// Keys are generated in software and stored as PKCS#8 in the node's etcd, on
// the encrypted state partition, the same way the delegated OCSP responder
// key is. They are never written in the clear.
type RAManager struct {
	store    *Store
	mint     MintRAFunc
	issuer   IssuerCertFunc
	validity time.Duration
	overlap  time.Duration
	now      func() time.Time
	logf     func(string, ...any)
	keygen   func() (*rsa.PrivateKey, error)

	mu  sync.RWMutex
	ras []raCert
}

// RAOptions configures an RAManager.
type RAOptions struct {
	Validity time.Duration
	Overlap  time.Duration
	// Now and Logf default to time.Now and discarding.
	Now  func() time.Time
	Logf func(string, ...any)
}

// NewRAManager returns an RAManager. Call Ensure before serving.
func NewRAManager(store *Store, mint MintRAFunc, issuer IssuerCertFunc, opts RAOptions) (*RAManager, error) {
	if store == nil || mint == nil || issuer == nil {
		return nil, errors.New("scep: NewRAManager: store, mint and issuer are required")
	}
	if opts.Validity <= 0 || opts.Overlap <= 0 || opts.Overlap >= opts.Validity {
		return nil, fmt.Errorf("scep: NewRAManager: the overlap (%s) must be positive and shorter than the validity (%s)", opts.Overlap, opts.Validity)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &RAManager{
		store: store, mint: mint, issuer: issuer,
		validity: opts.Validity, overlap: opts.Overlap, now: opts.Now, logf: opts.Logf,
		keygen: func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, RAKeyBits) },
	}, nil
}

// Ensure loads the stored RAs, drops expired ones and mints a successor when
// there is none, the newest is inside its overlap, or the newest no longer
// chains to the CA certificate (after a CA key rotation). It runs at boot and
// then periodically.
func (m *RAManager) Ensure(ctx context.Context) error {
	now := m.now()
	stored, err := m.store.listRAs(ctx)
	if err != nil {
		return err
	}
	var ras []raCert
	for _, s := range stored {
		ra, perr := parseStoredRA(s)
		if perr != nil {
			m.logf("scep: RA: a stored RA does not load, ignoring it: %v", perr)
			continue
		}
		serial := ra.Cert.SerialNumber.Text(16)
		if !now.Before(ra.Cert.NotAfter) {
			m.logf("scep: RA: %s expired %s, removing it", serial, ra.Cert.NotAfter.UTC().Format(time.RFC3339))
			if derr := m.store.deleteRA(ctx, serial); derr != nil {
				m.logf("scep: RA: removing expired %s failed: %v", serial, derr)
			}
			continue
		}
		ras = append(ras, ra)
	}
	sort.Slice(ras, func(i, j int) bool { return ras[i].Cert.NotAfter.After(ras[j].Cert.NotAfter) })

	issuer, err := m.issuer(ctx)
	if err != nil {
		return fmt.Errorf("scep: RA: load the CA certificate: %w", err)
	}
	if issuer == nil {
		return errors.New("scep: RA: this node has no CA certificate yet")
	}

	reason := ""
	switch {
	case len(ras) == 0:
		reason = "no RA yet"
	case ras[0].Cert.NotAfter.Sub(now) <= m.overlap:
		reason = fmt.Sprintf("the newest RA expires %s, inside the %s overlap", ras[0].Cert.NotAfter.UTC().Format(time.RFC3339), m.overlap)
	case ras[0].Cert.CheckSignatureFrom(issuer) != nil:
		reason = "the newest RA does not chain to the current CA certificate"
	}
	if reason != "" {
		m.logf("scep: RA: minting a new RA (%s)", reason)
		next, merr := m.mintRA(ctx, now)
		if merr != nil {
			if len(ras) == 0 {
				return merr
			}
			m.logf("scep: RA: minting the successor failed, keeping the current RA: %v", merr)
		} else if len(ras) > 0 && !next.Cert.NotAfter.After(ras[0].Cert.NotAfter) && ras[0].Cert.CheckSignatureFrom(issuer) == nil {
			// The CA certificate caps the RA's notAfter, so near the CA's own
			// expiry a successor cannot outlive the current RA; storing it
			// would only mint again on every pass.
			m.logf("scep: RA: the successor would not outlive the current RA (the CA expires %s); not storing it",
				issuer.NotAfter.UTC().Format(time.RFC3339))
		} else {
			if perr := m.store.putRA(ctx, next.Cert.SerialNumber.Text(16), storedRAFor(next)); perr != nil {
				if len(ras) == 0 {
					return perr
				}
				m.logf("scep: RA: storing the successor failed, keeping the current RA: %v", perr)
			} else {
				m.logf("scep: RA: %s minted, valid until %s", next.Cert.SerialNumber.Text(16), next.Cert.NotAfter.UTC().Format(time.RFC3339))
				ras = append([]raCert{next}, ras...)
			}
		}
	}

	m.mu.Lock()
	m.ras = ras
	m.mu.Unlock()
	serials := make([]string, len(ras))
	for i, r := range ras {
		serials[i] = r.Cert.SerialNumber.Text(16)
	}
	m.logf("scep: RA: %d usable RA certificate(s), newest first: %v", len(ras), serials)
	return nil
}

func (m *RAManager) mintRA(ctx context.Context, now time.Time) (raCert, error) {
	key, err := m.keygen()
	if err != nil {
		return raCert{}, fmt.Errorf("scep: RA: generate the key: %w", err)
	}
	der, err := m.mint(ctx, &key.PublicKey, now, now.Add(m.validity))
	if err != nil {
		return raCert{}, fmt.Errorf("scep: RA: sign the certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return raCert{}, fmt.Errorf("scep: RA: parse the certificate: %w", err)
	}
	return raCert{Cert: cert, Key: key}, nil
}

// Current returns the newest RA, the one GetCACert offers.
func (m *RAManager) Current() (raCert, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.ras) == 0 {
		return raCert{}, false
	}
	return m.ras[0], true
}

// All returns every usable RA, newest first: the candidates for decrypting a
// request.
func (m *RAManager) All() []raCert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]raCert(nil), m.ras...)
}

func storedRAFor(r raCert) storedRA {
	// MarshalPKCS8PrivateKey cannot fail for an *rsa.PrivateKey.
	key, _ := x509.MarshalPKCS8PrivateKey(r.Key)
	return storedRA{CertDER: r.Cert.Raw, KeyPKCS8: key}
}

func parseStoredRA(s storedRA) (raCert, error) {
	cert, err := x509.ParseCertificate(s.CertDER)
	if err != nil {
		return raCert{}, fmt.Errorf("certificate: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(s.KeyPKCS8)
	if err != nil {
		return raCert{}, fmt.Errorf("key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return raCert{}, fmt.Errorf("key: want RSA, got %T", parsed)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return raCert{}, errors.New("the key does not match the certificate")
	}
	return raCert{Cert: cert, Key: key}, nil
}
