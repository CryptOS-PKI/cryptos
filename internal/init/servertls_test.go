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
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// clientCert mints a self-signed clientAuth cert and returns the PEM (for
// the trust) plus a tls.Certificate (to present as a client).
func clientCert(t *testing.T, cn string) (string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return certPEM, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestGenerateServerCert(t *testing.T) {
	cert, err := GenerateServerCert([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("Leaf not populated")
	}
	if len(cert.Leaf.IPAddresses) != 1 || cert.Leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IP SANs = %v, want [127.0.0.1]", cert.Leaf.IPAddresses)
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "localhost" {
		t.Errorf("DNS SANs = %v, want [localhost]", cert.Leaf.DNSNames)
	}
	if _, err := GenerateServerCert(nil); err == nil {
		t.Error("GenerateServerCert(nil) should error")
	}
}

func TestServerTLSConfig_FingerprintRejected(t *testing.T) {
	// Fingerprint-only trust can't anchor ClientCAs -> rejected.
	tr, err := bootstrap.LoadTrust(config.Bootstrap{AdminCertSHA256: "ab" + repeat("0", 62)})
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	sc, _ := GenerateServerCert([]string{"localhost"})
	if _, err := ServerTLSConfig(sc, tr); err == nil {
		t.Error("ServerTLSConfig with fingerprint-only trust should error")
	}
	if _, err := ServerTLSConfig(sc, nil); err == nil {
		t.Error("ServerTLSConfig(nil trust) should error")
	}
}

func TestServerTLSConfig_MutualHandshake(t *testing.T) {
	adminPEM, adminKeyPair := clientCert(t, "bootstrap-admin")
	trust, err := bootstrap.LoadTrust(config.Bootstrap{AdminCertPEM: adminPEM})
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	serverCert, err := GenerateServerCert([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}
	srvCfg, err := ServerTLSConfig(serverCert, trust)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	if srvCfg.ClientAuth != tls.RequireAndVerifyClientCert || srvCfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("server config is not strict mTLS TLS 1.3")
	}

	// Client trusts the server's ephemeral cert.
	roots := x509.NewCertPool()
	roots.AddCert(serverCert.Leaf)

	handshake := func(clientKeyPair tls.Certificate) error {
		lis, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
		if err != nil {
			return err
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

		cConn, err := tls.Dial("tcp", lis.Addr().String(), &tls.Config{
			Certificates: []tls.Certificate{clientKeyPair},
			RootCAs:      roots,
			ServerName:   "localhost",
			MinVersion:   tls.VersionTLS13,
		})
		if err != nil {
			return err
		}
		_ = cConn.Close()
		return <-errCh
	}

	// Authorized: the bootstrap admin cert is accepted.
	if err := handshake(adminKeyPair); err != nil {
		t.Errorf("authorized mTLS handshake failed: %v", err)
	}

	// Unauthorized: a different self-signed client cert is rejected.
	_, intruder := clientCert(t, "intruder")
	if err := handshake(intruder); err == nil {
		t.Error("unauthorized client cert was accepted, want rejection")
	}
}

// repeat returns s repeated n times (small helper to build a 64-hex string).
func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
