package init

/*
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
	"bytes"
	"context"
	"crypto/tls"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

// managementCertRefresh is how often the management certificate is checked
// outside handshakes, so the console shows the CA-signed certificate soon
// after the ceremony and renewal does not wait for a client to connect.
const managementCertRefresh = 30 * time.Second

// managementCertOptions wires a managementCert to the node.
type managementCertOptions struct {
	// SelfSigned is the certificate presented until the node has a CA.
	SelfSigned tls.Certificate
	// Load and Issuer reach the node's CA key and certificate, as for EST.
	Load   node.KeyLoader
	Issuer node.IssuerFunc
	// Chain returns the node's CA chain, leaf-first, presented after the
	// management leaf.
	Chain func(context.Context) ([][]byte, error)
	// Hosts are the SANs of the CA-signed certificate (ManagementSANs).
	Hosts []string
	// Alg is the configured CA key algorithm, used to pre-generate the key.
	Alg config.RootKeyAlg
	// HasCA reports whether the node has committed a CA identity.
	HasCA func(context.Context) bool
	// Publish receives each new certificate the listener presents, for the
	// console.
	Publish func(tls.Certificate) error
}

// managementCert chooses the certificate the management listener presents.
// Before the node has a CA it is the self-signed boot certificate, which
// clients pin by fingerprint. Once the CA exists it is a certificate signed by
// that CA, minted and renewed like the EST listener's, so a client that trusts
// the CA chain keeps verifying the node across reboots although the key is new
// each boot. The switch happens on the boot that commits the CA, without a
// restart, and never goes back within a boot.
//
// Signing goes through ca.Sign directly, not the node's CA signer, so the SNTP
// clock gate does not apply: gating it would lock operators out of the one
// listener they need to fix the clock.
type managementCert struct {
	selfSigned tls.Certificate
	signed     *caServerCert
	hasCA      func(context.Context) bool
	publish    func(tls.Certificate) error
	logf       func(string, ...any)

	caSigned atomic.Bool

	mu        sync.Mutex
	published []byte
}

func newManagementCert(o managementCertOptions) *managementCert {
	m := &managementCert{
		selfSigned: o.SelfSigned,
		hasCA:      o.HasCA,
		publish:    o.Publish,
		logf:       log.Printf,
	}
	m.signed = &caServerCert{
		label:    "management",
		load:     o.Load,
		issuer:   o.Issuer,
		chain:    o.Chain,
		hosts:    o.Hosts,
		validity: estServerCertValidity,
		warmer:   warmNodeKey(o.Alg),
		logf:     func(format string, args ...any) { m.logf(format, args...) },
	}
	return m
}

// get is the tls.Config.GetCertificate callback.
func (m *managementCert) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ctx := context.Background()
	if hello != nil && hello.Context() != nil {
		ctx = hello.Context()
	}
	return m.current(ctx, hello)
}

// refresh brings the certificate up to date outside a handshake.
func (m *managementCert) refresh(ctx context.Context) error {
	_, err := m.current(ctx, nil)
	return err
}

// run refreshes the certificate every interval until ctx is done.
func (m *managementCert) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := m.refresh(ctx); err != nil {
			m.logf("management cert: refresh failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *managementCert) current(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !m.caSigned.Load() {
		if !m.hasCA(ctx) {
			m.publishIfNew(&m.selfSigned)
			return &m.selfSigned, nil
		}
		m.caSigned.Store(true)
	}
	cert, err := m.signed.get(hello)
	if err != nil {
		return nil, err
	}
	m.publishIfNew(cert)
	return cert, nil
}

// publishIfNew hands cert to Publish when it differs from the last one
// published. A failed publish only logs; the console then omits or keeps the
// old fingerprint, and the listener is unaffected.
func (m *managementCert) publishIfNew(cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cert.Leaf == nil || bytes.Equal(m.published, cert.Leaf.Raw) {
		return
	}
	if err := m.publish(*cert); err != nil {
		m.logf("management cert: not published for the console: %v", err)
		return
	}
	m.published = cert.Leaf.Raw
}

// managementTLSConfig is ServerTLSConfig for a managementCert: the same
// strict mTLS, with the certificate chosen per handshake.
func managementTLSConfig(m *managementCert, trust *bootstrap.Trust) (*tls.Config, error) {
	cfg, err := ServerTLSConfig(m.selfSigned, trust)
	if err != nil {
		return nil, err
	}
	cfg.Certificates = nil
	cfg.GetCertificate = m.get
	return cfg, nil
}
