package main

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

func TestRunRendersSnapshot(t *testing.T) {
	var buf bytes.Buffer
	tick := make(chan time.Time, 1)
	tick <- time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	snap := func(context.Context) (console.View, error) {
		cancel() // one render then stop
		return console.View{RootCN: "ACME Root CA G1", Role: "ROOT", NodeStatus: "ESTABLISHED", TPM: "SEALED"}, nil
	}
	run(ctx, snap, &buf, tick, 64, 24)
	if !bytes.Contains(buf.Bytes(), []byte("ACME Root CA G1")) {
		t.Fatalf("run did not render the dashboard:\n%s", buf.String())
	}
}

func TestRunRendersDegradedOnError(t *testing.T) {
	var buf bytes.Buffer
	tick := make(chan time.Time, 1)
	tick <- time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	snap := func(context.Context) (console.View, error) {
		cancel()
		return console.View{Degraded: true}, errors.New("dial failed")
	}
	run(ctx, snap, &buf, tick, 64, 24)
	if !bytes.Contains(buf.Bytes(), []byte("degraded")) {
		t.Fatalf("run did not render degraded:\n%s", buf.String())
	}
}

func TestWithMgmtFingerprintAddsThePublishedCert(t *testing.T) {
	cert := testCertPEM(t)
	path := filepath.Join(t.TempDir(), "mgmt.crt")
	if err := os.WriteFile(path, cert, 0o644); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cert)
	base := func(context.Context) (console.View, error) {
		return console.View{RootCN: "ACME Root CA G1"}, nil
	}

	v, err := withMgmtFingerprint(base, path)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := console.Fingerprint(block.Bytes); v.MgmtFingerprint != want || v.RootCN != "ACME Root CA G1" {
		t.Fatalf("view = %+v, want fingerprint %q on the base view", v, want)
	}
}

func TestWithMgmtFingerprintLeavesAFailedSnapshotAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mgmt.crt")
	if err := os.WriteFile(path, testCertPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	base := func(context.Context) (console.View, error) {
		return console.View{Degraded: true}, errors.New("dial failed")
	}

	v, err := withMgmtFingerprint(base, path)(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dial failed") || v.MgmtFingerprint != "" {
		t.Fatalf("got view %+v, err %v; want the base error and no fingerprint", v, err)
	}
}

func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "192.0.2.10"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestWithMgmtFingerprintMarksACASignedCert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mgmt.crt")
	if err := os.WriteFile(path, testCertPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	base := func(context.Context) (console.View, error) { return console.View{}, nil }
	v, err := withMgmtFingerprint(base, path)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.MgmtCASigned {
		t.Fatal("a self-signed management certificate is marked CA-signed")
	}

	if err := os.WriteFile(path, caSignedCertPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err = withMgmtFingerprint(base, path)(context.Background()); err != nil || !v.MgmtCASigned {
		t.Fatalf("view = %+v, err %v; want a CA-signed management certificate marked", v, err)
	}
}

func caSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Root CA G1"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "192.0.2.10"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestWithMgmtAddrsAddsTheAddresses(t *testing.T) {
	base := func(context.Context) (console.View, error) {
		return console.View{Maintenance: true}, nil
	}
	addrs := func() []string { return []string{"192.0.2.10"} }

	v, err := withMgmtAddrs(base, addrs)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Maintenance || strings.Join(v.MgmtAddrs, ",") != "192.0.2.10" {
		t.Fatalf("view = %+v, want the addresses on the base view", v)
	}
}

func TestWithMgmtAddrsLeavesAFailedSnapshotAlone(t *testing.T) {
	base := func(context.Context) (console.View, error) {
		return console.View{Degraded: true}, errors.New("dial failed")
	}
	addrs := func() []string { return []string{"192.0.2.10"} }

	v, err := withMgmtAddrs(base, addrs)(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dial failed") || v.MgmtAddrs != nil {
		t.Fatalf("got view %+v, err %v; want the base error and no addresses", v, err)
	}
}
