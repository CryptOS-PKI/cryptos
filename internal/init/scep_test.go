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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

func scepBootConfig() *config.Config {
	return &config.Config{PKI: config.PKI{SCEP: &config.SCEP{
		Profiles:                  []config.SCEPProfile{{Profile: "cisco-device", MinRSAKeyBits: 2048}, {Profile: "mdm"}},
		AllowedIdentifierSuffixes: []string{"example.com"},
	}}}
}

func TestSCEPListenerPlacement(t *testing.T) {
	c := scepBootConfig()
	if got := scepListenPort(c); got != 80 {
		t.Fatalf("default SCEP port = %d, want 80, the CRL/OCSP port", got)
	}
	if scepSharesRevocationListener(c) {
		t.Fatal("with no revocation listener running SCEP must get its own")
	}
	c.PKI.RevocationBaseURL = "http://ca.example.com"
	if !scepSharesRevocationListener(c) {
		t.Fatal("on the same port as the CRL/OCSP listener SCEP must share it")
	}
	c.PKI.SCEP.HTTPPort = 8080
	if scepSharesRevocationListener(c) || scepListenPort(c) != 8080 {
		t.Fatal("a separate SCEP port must get its own listener")
	}
	c.PKI.SCEP.HTTPPort = 0
	c.PKI.RevocationHTTPPort = 8081
	if !scepSharesRevocationListener(c) || scepListenPort(c) != 8081 {
		t.Fatal("SCEP follows a moved CRL/OCSP port by default")
	}
}

func TestSCEPOptionsCarryTheFloors(t *testing.T) {
	opts := scepOptions(scepBootConfig().PKI.SCEP)
	if len(opts.Profiles) != 2 || opts.Profiles[0].MinRSABits != 2048 || opts.Profiles[1].MinRSABits != 3072 {
		t.Fatalf("profiles = %+v, want the 2048 floor and the 3072 default", opts.Profiles)
	}
	if len(opts.AllowedSuffixes) != 1 {
		t.Fatalf("allowlist = %v", opts.AllowedSuffixes)
	}
}

func TestSCEPMintRA(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now().UTC()
	der, _, err := ca.Sign(ca.Profile{Subject: pkix.Name{CommonName: "Node CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(3, 0, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, &caKey.PublicKey, nil, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	closed := false
	load := func(context.Context) (crypto.Signer, func(), error) { return caKey, func() { closed = true }, nil }
	issuer := func(context.Context) (*x509.Certificate, error) { return caCert, nil }

	raKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	raDER, err := scepMintRA(load, issuer)(context.Background(), &raKey.PublicKey, now, now.AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !closed {
		t.Fatal("the CA key was not released after signing the RA")
	}
	ra, _ := x509.ParseCertificate(raDER)
	if ra.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment || ra.IsCA || len(ra.ExtKeyUsage) != 0 {
		t.Fatalf("RA usage = %v %v IsCA=%t", ra.KeyUsage, ra.ExtKeyUsage, ra.IsCA)
	}
	if !strings.HasSuffix(ra.Subject.CommonName, "SCEP RA") || ra.CheckSignatureFrom(caCert) != nil {
		t.Fatalf("RA subject %q or signature wrong", ra.Subject.CommonName)
	}
}

// SCEP issuance goes through the same clock-gated CA signer as ACME and EST,
// so an unsynced clock refuses it. The RA certificate is minted with the CA
// key directly, like the OCSP responder and EST server certificates, and is
// not gated: SCEP must be able to offer an RA from the first boot.
func TestSCEPIssuanceHonoursTheClockGate(t *testing.T) {
	g := newGateFixture(t, unsyncedEngine(t))
	_, err := scepIssuer(g.signer)(g.ctx, testCSR(t), "leaf", []string{"router.example.com"}, 0)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("SCEP issuance on an unsynced clock = %v, want FailedPrecondition", err)
	}

	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now().UTC()
	der, _, err := ca.Sign(ca.Profile{Subject: pkix.Name{CommonName: "Node CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(3, 0, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, &caKey.PublicKey, nil, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	load := func(context.Context) (crypto.Signer, func(), error) { return caKey, func() {}, nil }
	issuer := func(context.Context) (*x509.Certificate, error) { return caCert, nil }
	raKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	if _, err := scepMintRA(load, issuer)(g.ctx, &raKey.PublicKey, now, now.AddDate(1, 0, 0)); err != nil {
		t.Fatalf("RA mint on an unsynced clock: %v", err)
	}
}
