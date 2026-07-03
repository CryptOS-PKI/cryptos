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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
)

// serverCertValidity is how long the ephemeral boot server certificate is
// valid. It is regenerated every boot, so this only needs to comfortably
// exceed a node's uptime between reboots.
const serverCertValidity = 825 * 24 * time.Hour

// GenerateServerCert mints an ephemeral self-signed ECDSA P-256 server
// certificate for the management TLS listener, valid for the given hosts
// (IP literals become IP SANs, everything else a DNS SAN). The node has
// no CA identity before the first-boot ceremony, so the listener
// presents this throwaway cert; clients pin it via their trust store.
func GenerateServerCert(hosts []string) (tls.Certificate, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, errors.New("init: GenerateServerCert: at least one host is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("init: GenerateServerCert: key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("init: GenerateServerCert: serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(serverCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip, err := netip.ParseAddr(h); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip.AsSlice())
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("init: GenerateServerCert: create: %w", err)
	}
	// Parse the signed DER so Leaf carries Raw (needed when callers add it
	// to a trust pool); the template's Raw is empty.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("init: GenerateServerCert: parse: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// ServerTLSConfig assembles the mTLS config for the management listener:
// it presents serverCert and requires + verifies a client certificate
// against the bootstrap admin trust. It is suitable for grpc.New, which
// mandates RequireAndVerifyClientCert.
//
// This requires the full bootstrap admin certificate (the PEM form). A
// fingerprint-only trust can't anchor a ClientCAs pool, so it is rejected
// here rather than silently weakening client verification.
func ServerTLSConfig(serverCert tls.Certificate, trust *bootstrap.Trust) (*tls.Config, error) {
	if trust == nil {
		return nil, errors.New("init: ServerTLSConfig: trust is required")
	}
	pool, ok := trust.ClientCAPool()
	if !ok {
		return nil, errors.New("init: ServerTLSConfig: the mTLS listener needs the full bootstrap admin certificate (PEM), not just a fingerprint")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// MaintenanceServerTLSConfig is the mTLS-less server config for maintenance
// mode: it presents serverCert but does NOT request or verify a client cert,
// because no bootstrap trust exists yet (Talos --insecure). Do not use outside
// maintenance — the normal listener uses ServerTLSConfig with client verification.
func MaintenanceServerTLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}
