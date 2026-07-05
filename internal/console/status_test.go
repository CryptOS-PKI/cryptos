package console_test

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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/console"
)

func leafPEM(t *testing.T, cn string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestRootCN(t *testing.T) {
	id := &cryptosv1.Identity{ChainPem: leafPEM(t, "ACME Root CA G1")}
	if got := console.RootCN(id); got != "ACME Root CA G1" {
		t.Fatalf("RootCN = %q", got)
	}
	if console.RootCN(nil) != "" {
		t.Fatal("RootCN(nil) should be empty")
	}
}

func TestIssuerCN(t *testing.T) {
	chain := leafPEM(t, "ACME Issuing CA G1") + leafPEM(t, "ACME Root CA G1")
	id := &cryptosv1.Identity{ChainPem: chain}
	if got := console.IssuerCN(id); got != "ACME Root CA G1" {
		t.Fatalf("IssuerCN(2-cert chain) = %q, want the second subject CN", got)
	}
	self := &cryptosv1.Identity{ChainPem: leafPEM(t, "ACME Root CA G1")}
	if got := console.IssuerCN(self); got != "self-signed" {
		t.Fatalf("IssuerCN(1-cert) = %q, want %q", got, "self-signed")
	}
	if console.IssuerCN(nil) != "" {
		t.Fatal("IssuerCN(nil) should be empty")
	}
}

func TestViewFromAPI(t *testing.T) {
	st := &cryptosv1.NodeStatus{
		Role:            cryptosv1.NodeRole_NODE_ROLE_ROOT,
		IdentityState:   cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
		TpmState:        cryptosv1.TpmState_TPM_STATE_OK,
		SoftwareVersion: "phase-1-dev",
	}
	id := &cryptosv1.Identity{ChainPem: leafPEM(t, "ACME Root CA G1")}
	v := console.ViewFromAPI(st, id, 90*time.Minute)
	if v.RootCN != "ACME Root CA G1" || v.Role != "ROOT" || v.NodeStatus != "ESTABLISHED" || v.TPM != "SEALED" {
		t.Fatalf("view mapping wrong: %+v", v)
	}
	if v.Fleet != console.FleetNotEnrolled {
		t.Fatalf("Fleet should default to not-enrolled in M2")
	}
}

func TestViewFromAPIFleet(t *testing.T) {
	cases := map[cryptosv1.FleetManagerState]console.FleetState{
		cryptosv1.FleetManagerState_FLEET_MANAGER_STATE_CONNECTED:    console.FleetConnected,
		cryptosv1.FleetManagerState_FLEET_MANAGER_STATE_DISCONNECTED: console.FleetDisconnected,
		cryptosv1.FleetManagerState_FLEET_MANAGER_STATE_NOT_ENROLLED: console.FleetNotEnrolled,
		cryptosv1.FleetManagerState_FLEET_MANAGER_STATE_UNSPECIFIED:  console.FleetNotEnrolled,
	}
	for api, want := range cases {
		if got := console.ViewFromAPI(&cryptosv1.NodeStatus{FleetManager: api}, nil, 0).Fleet; got != want {
			t.Fatalf("fleet %v -> %v, want %v", api, got, want)
		}
	}
}
