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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/est"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/revocation"
)

// defaultESTHTTPPort is the port the EST listener binds when the config
// leaves it at zero. EST terminates TLS itself, so unlike ACME it is not
// behind a front end; 8443 keeps it clear of the CRL/OCSP listener on 80 and
// of anything an operator may already run on 443.
const defaultESTHTTPPort = 8443

// estServerCertValidity is the lifetime of the EST listener's server
// certificate. It is re-minted at the halfway point, so a serving node always
// presents a certificate at least half its life from expiry.
const estServerCertValidity = 90 * 24 * time.Hour

// estServerCert mints and renews the TLS server certificate the EST listener
// presents, signing it with this node's own CA.
//
// A self-signed throwaway like GenerateServerCert would not do here. That one
// works for the management listener because operators pin it out of band, but
// an EST client validates the server against a trust anchor, and the anchor it
// has is this CA -- fetched from /cacerts on first contact or shipped with the
// device. Signing the listener certificate with the CA is what closes that
// loop.
//
// The certificate is held in memory only. Unlike the delegated OCSP responder
// there is nothing to persist: a relying party never caches a TLS server
// certificate across our restarts, so re-minting on boot costs nothing.
type estServerCert struct {
	load     node.KeyLoader
	issuer   node.IssuerFunc
	hosts    []string
	validity time.Duration

	mu   sync.Mutex
	cur  *tls.Certificate
	logf func(string, ...any)
}

func newESTServerCert(load node.KeyLoader, issuer node.IssuerFunc, hosts []string) *estServerCert {
	return &estServerCert{
		load:     load,
		issuer:   issuer,
		hosts:    hosts,
		validity: estServerCertValidity,
		logf:     log.Printf,
	}
}

// get is the tls.Config.GetCertificate callback. It hands back the current
// certificate, minting a fresh one on the first call and whenever the
// existing one is inside its renewal window.
func (m *estServerCert) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cur != nil && m.cur.Leaf != nil && time.Until(m.cur.Leaf.NotAfter) >= m.validity/2 {
		return m.cur, nil
	}
	ctx := context.Background()
	if hello != nil && hello.Context() != nil {
		ctx = hello.Context()
	}
	cert, err := m.mint(ctx)
	if err != nil {
		// A handshake with no certificate to present is fatal for that
		// connection, but the node keeps serving everything else.
		m.logf("est: minting the listener certificate failed: %v", err)
		return nil, err
	}
	m.cur = cert
	return cert, nil
}

// mint generates a fresh P-384 key and signs a server certificate for the
// configured hosts with the CA key, loaded per use and released immediately.
func (m *estServerCert) mint(ctx context.Context) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("init: generate EST server key: %w", err)
	}

	signer, closeFn, err := m.load(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: load CA key for the EST server certificate: %w", err)
	}
	if closeFn != nil {
		defer closeFn()
	}
	issuerCert, err := m.issuer(ctx)
	if err != nil {
		return nil, fmt.Errorf("init: load issuer for the EST server certificate: %w", err)
	}
	if issuerCert == nil {
		return nil, errors.New("init: no issuer certificate available for the EST server certificate")
	}

	now := time.Now().UTC()
	der, _, err := ca.Sign(estServerProfile(m.hosts, now, now.Add(m.validity)), key.Public(), issuerCert, signer)
	if err != nil {
		return nil, fmt.Errorf("init: sign the EST server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("init: parse the EST server certificate: %w", err)
	}
	// The issuer travels with it so a client that already trusts the CA can
	// build the chain without a separate fetch.
	return &tls.Certificate{
		Certificate: [][]byte{der, issuerCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// estServerProfile is the ca.Profile for the EST listener certificate: an
// end-entity server certificate for the configured hosts and nothing more.
func estServerProfile(hosts []string, notBefore, notAfter time.Time) ca.Profile {
	p := ca.Profile{
		Subject:     pkix.Name{CommonName: hosts[0]},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		IsCA:        false,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if addr, err := netip.ParseAddr(h); err == nil {
			p.IPAddresses = append(p.IPAddresses, addr.AsSlice())
		} else {
			p.DNSNames = append(p.DNSNames, h)
		}
	}
	return p
}

// estTLSConfig is the listener config: it presents the CA-issued server
// certificate and asks for, but does not require, a client certificate.
//
// RequestClientCert rather than RequireAndVerifyClientCert is deliberate.
// /cacerts exists for a client that holds nothing yet, so demanding a
// certificate at the handshake would lock out exactly the callers that
// endpoint is for. simplereenroll does the verifying itself, against the live
// CA chain and the revocation set, which the TLS stack cannot consult.
//
// TLS 1.2 is the floor rather than 1.3: RFC 7030 predates 1.3 and the
// embedded clients EST exists to serve commonly top out at 1.2.
func estTLSConfig(cert *estServerCert) *tls.Config {
	return &tls.Config{
		GetCertificate: cert.get,
		ClientAuth:     tls.RequestClientCert,
		MinVersion:     tls.VersionTLS12,
	}
}

// estCAChain returns the closure backing /cacerts and the re-enrolment trust
// anchor set.
func estCAChain(issuer node.IssuerFunc) est.CAChainFunc {
	return func(ctx context.Context) ([][]byte, error) {
		cert, err := issuer(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load the issuer certificate: %w", err)
		}
		if cert == nil {
			return nil, errors.New("init: this node has no CA certificate")
		}
		return [][]byte{cert.Raw}, nil
	}
}

// estIssuer returns the closure backing enrolment. It routes through
// IssueLeafForNames so the SANs are the names the handler authorized while
// the profile still decides every other extension, and so the certificate is
// recorded in the revocation issued set before it is handed back.
func estIssuer(signer *node.CASigner, profileName string) est.IssueFunc {
	return func(ctx context.Context, csrDER []byte, dnsNames []string) ([][]byte, error) {
		chainDER, _, err := signer.IssueLeafForNames(ctx, csrDER, profileName, dnsNames)
		return chainDER, err
	}
}

// estRevoked returns the closure that stops a revoked certificate renewing
// itself through simplereenroll.
func estRevoked(store *revocation.Store) est.RevokedFunc {
	return func(ctx context.Context, serialHex string) (bool, error) {
		_, revoked, err := store.GetRevoked(ctx, serialHex)
		return revoked, err
	}
}

// estOptions maps the validated node config onto est.Options. The config
// layer has already checked the profile, the hostnames and the credential
// digests, so a failure here is a decode of something validateEST accepted.
func estOptions(c *config.EST) (est.Options, error) {
	opts := est.Options{
		Label:              c.Label,
		AllowedSuffixes:    c.AllowedIdentifierSuffixes,
		AllowAnyIdentifier: c.AllowAnyIdentifier,
		Realm:              c.Realm,
		Logf:               log.Printf,
	}
	if len(c.EnrollCredentials) == 0 {
		// No credentials means simpleenroll stays closed and only
		// certificate-authenticated renewal is offered.
		return opts, nil
	}
	digests := make(map[string][]byte, len(c.EnrollCredentials))
	for _, cred := range c.EnrollCredentials {
		sum, err := hex.DecodeString(cred.PasswordSHA256)
		if err != nil {
			return est.Options{}, fmt.Errorf("init: decode the EST credential digest for %q: %w", cred.Username, err)
		}
		digests[cred.Username] = sum
	}
	opts.EnrollAuth = est.StaticEnrollCredentials(digests)
	return opts, nil
}
