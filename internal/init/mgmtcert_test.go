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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// mgmtTestConfig is a node with one management address and EST names, which
// are the DNS names the management certificate must cover.
func mgmtTestConfig() *config.Config {
	c := &config.Config{}
	c.Network.Address = "192.0.2.10/24"
	c.PKI.EST = &config.EST{Hostnames: []string{"ca.example.org", "192.0.2.20", "192.0.2.10"}}
	return c
}

// mgmtHarness wires a managementCert to a test CA whose identity can be
// switched on, and records every certificate it publishes.
type mgmtHarness struct {
	ca        *estTestCA
	hasCA     atomic.Bool
	published []tls.Certificate
}

func newMgmtHarness(t *testing.T, ca *estTestCA, hosts []string) (*mgmtHarness, *managementCert) {
	t.Helper()
	self, err := GenerateServerCert([]string{"192.0.2.10", "localhost"}, config.RootKeyECDSAP384)
	if err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}
	h := &mgmtHarness{ca: ca}
	m := newManagementCert(managementCertOptions{
		SelfSigned: self,
		Load:       ca.loader(),
		Issuer:     ca.issuerFunc(),
		Chain:      func(context.Context) ([][]byte, error) { return [][]byte{ca.cert.Raw}, nil },
		Hosts:      hosts,
		Alg:        config.RootKeyECDSAP384,
		HasCA:      func(context.Context) bool { return h.hasCA.Load() },
		Publish: func(c tls.Certificate) error {
			h.published = append(h.published, c)
			return nil
		},
	})
	m.logf = t.Logf
	return h, m
}

func mustSANs(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	sans, err := ManagementSANs(cfg)
	if err != nil {
		t.Fatalf("ManagementSANs: %v", err)
	}
	return sans
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// The CA-signed certificate names the management IP and every name from the
// config, once each, and nothing that only resolves on the node itself.
func TestManagementSANs(t *testing.T) {
	if got, want := mustSANs(t, mgmtTestConfig()), []string{"192.0.2.10", "ca.example.org", "192.0.2.20"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ManagementSANs = %v, want %v", got, want)
	}
	noEST := &config.Config{}
	noEST.Network.Address = "192.0.2.10/24"
	if got, want := mustSANs(t, noEST), []string{"192.0.2.10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ManagementSANs without EST = %v, want %v", got, want)
	}
	bad := &config.Config{}
	bad.Network.Address = "not-a-cidr"
	if _, err := ManagementSANs(bad); err == nil {
		t.Fatal("ManagementSANs accepted a bad network.address")
	}
}

func TestManagementCertIsSelfSignedBeforeTheCA(t *testing.T) {
	h, m := newMgmtHarness(t, newESTTestCA(t), mustSANs(t, mgmtTestConfig()))

	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !isSelfSigned(cert.Leaf) {
		t.Fatalf("pre-CA certificate is issued by %q, want self-signed", cert.Leaf.Issuer)
	}
	if h.ca.closed != 0 {
		t.Fatalf("the CA key was loaded %d times before the node had a CA", h.ca.closed)
	}
	if len(h.published) != 1 || !bytes.Equal(h.published[0].Leaf.Raw, cert.Leaf.Raw) {
		t.Fatalf("published %d certificates, want the self-signed one", len(h.published))
	}
}

// Once the CA exists, the listener certificate chains to it and passes the
// host check for every address a client may dial.
func TestManagementCertChainsToTheNodeCA(t *testing.T) {
	sans := mustSANs(t, mgmtTestConfig())
	h, m := newMgmtHarness(t, newESTTestCA(t), sans)
	h.hasCA.Store(true)

	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.cert)
	for _, host := range sans {
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{
			Roots:     pool,
			DNSName:   host,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Errorf("Verify for %s: %v", host, err)
		}
	}
	if err := cert.Leaf.VerifyHostname("localhost"); err == nil {
		t.Error("the CA-signed certificate names localhost")
	}
	if len(cert.Certificate) != 2 || !bytes.Equal(cert.Certificate[1], h.ca.cert.Raw) {
		t.Fatalf("presented chain has %d certificates, want the leaf and the CA chain", len(cert.Certificate))
	}
	if left := time.Until(cert.Leaf.NotAfter); left > estServerCertValidity || left < estServerCertValidity-time.Hour {
		t.Fatalf("validity left %v, want the EST server certificate's %v", left, estServerCertValidity)
	}
}

func TestManagementCertIsNotACA(t *testing.T) {
	h, m := newMgmtHarness(t, newESTTestCA(t), mustSANs(t, mgmtTestConfig()))
	h.hasCA.Store(true)

	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	leaf := cert.Leaf
	if leaf.IsCA {
		t.Fatal("the management certificate is a CA")
	}
	if leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		t.Fatalf("key usage %v allows signing certificates or CRLs", leaf.KeyUsage)
	}
	if !reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatalf("EKU = %v, want serverAuth only", leaf.ExtKeyUsage)
	}
}

// The boot that runs the ceremony switches to the CA-signed certificate
// without a reboot, and publishes it for the console.
func TestManagementCertSwitchesWhenTheCAArrives(t *testing.T) {
	h, m := newMgmtHarness(t, newESTTestCA(t), mustSANs(t, mgmtTestConfig()))
	ctx := context.Background()

	if err := m.refresh(ctx); err != nil {
		t.Fatalf("refresh before the CA: %v", err)
	}
	h.hasCA.Store(true)
	if err := m.refresh(ctx); err != nil {
		t.Fatalf("refresh after the CA: %v", err)
	}
	if len(h.published) != 2 {
		t.Fatalf("published %d certificates, want the self-signed then the CA-signed one", len(h.published))
	}
	if !isSelfSigned(h.published[0].Leaf) || isSelfSigned(h.published[1].Leaf) {
		t.Fatal("the published certificates are not self-signed then CA-signed")
	}

	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(cert.Leaf.Raw, h.published[1].Leaf.Raw) {
		t.Fatal("the handshake presents a different certificate than the one published")
	}
	if len(h.published) != 2 {
		t.Fatalf("an unchanged certificate was published again (%d publishes)", len(h.published))
	}
}

// Each boot mints a new key, but a client that trusts the CA keeps verifying
// the node across the reboot.
func TestManagementCertVerifiesAcrossAReboot(t *testing.T) {
	ca := newESTTestCA(t)
	sans := mustSANs(t, mgmtTestConfig())
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	var leaves []*x509.Certificate
	for boot := range 2 {
		h, m := newMgmtHarness(t, ca, sans)
		h.hasCA.Store(true)
		cert, err := m.get(nil)
		if err != nil {
			t.Fatalf("boot %d: get: %v", boot, err)
		}
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "192.0.2.10"}); err != nil {
			t.Fatalf("boot %d: Verify: %v", boot, err)
		}
		leaves = append(leaves, cert.Leaf)
	}
	if bytes.Equal(leaves[0].RawSubjectPublicKeyInfo, leaves[1].RawSubjectPublicKeyInfo) {
		t.Fatal("the reboot kept the same management key")
	}
}

// A client that anchors on the CA completes the mutual handshake against the
// management listener config, dialling by name.
func TestManagementTLSConfigHandshakesAgainstTheCA(t *testing.T) {
	adminPEM, adminKeyPair := clientCert(t, "bootstrap-admin")
	trust, err := bootstrap.LoadTrust(adminPEM, "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	h, m := newMgmtHarness(t, newESTTestCA(t), mustSANs(t, mgmtTestConfig()))
	h.hasCA.Store(true)
	srvCfg, err := managementTLSConfig(m, trust)
	if err != nil {
		t.Fatalf("managementTLSConfig: %v", err)
	}
	if srvCfg.ClientAuth != tls.RequireAndVerifyClientCert || srvCfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("management config is not strict mTLS TLS 1.3")
	}

	lis, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	errCh := make(chan error, 1)
	go func() {
		conn, aerr := lis.Accept()
		if aerr != nil {
			errCh <- aerr
			return
		}
		defer func() { _ = conn.Close() }()
		errCh <- conn.(*tls.Conn).Handshake()
	}()

	roots := x509.NewCertPool()
	roots.AddCert(h.ca.cert)
	conn, err := tls.Dial("tcp", lis.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{adminKeyPair},
		RootCAs:      roots,
		ServerName:   "ca.example.org",
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = conn.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// PublishManagementCert publishes the leaf only; the console reads it to tell
// a CA-signed certificate from a self-signed one.
func TestPublishManagementCertWritesTheCASignedLeaf(t *testing.T) {
	h, m := newMgmtHarness(t, newESTTestCA(t), mustSANs(t, mgmtTestConfig()))
	h.hasCA.Store(true)
	cert, err := m.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	path := filepath.Join(t.TempDir(), "mgmt.crt")
	if err := PublishManagementCert(path, *cert); err != nil {
		t.Fatalf("PublishManagementCert: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || !bytes.Equal(block.Bytes, cert.Leaf.Raw) || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("published file is not exactly the leaf:\n%s", data)
	}
}

// Maintenance mode has no CA and no trust: its listener keeps presenting a
// self-signed certificate.
func TestMaintenanceKeepsASelfSignedCert(t *testing.T) {
	self, err := GenerateServerCert([]string{"localhost"}, "")
	if err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}
	cfg := MaintenanceServerTLSConfig(self)
	if cfg.GetCertificate != nil || len(cfg.Certificates) != 1 || !isSelfSigned(cfg.Certificates[0].Leaf) {
		t.Fatal("the maintenance listener does not present a fixed self-signed certificate")
	}
}
