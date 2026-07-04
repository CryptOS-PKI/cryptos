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
	id := &cryptosv1.Identity{ChainPem: leafPEM(t, "Interborough Root CA G1")}
	if got := console.RootCN(id); got != "Interborough Root CA G1" {
		t.Fatalf("RootCN = %q", got)
	}
	if console.RootCN(nil) != "" {
		t.Fatal("RootCN(nil) should be empty")
	}
}

func TestViewFromAPI(t *testing.T) {
	st := &cryptosv1.NodeStatus{
		Role:            cryptosv1.NodeRole_NODE_ROLE_ROOT,
		IdentityState:   cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
		TpmState:        cryptosv1.TpmState_TPM_STATE_OK,
		SoftwareVersion: "phase-1-dev",
	}
	id := &cryptosv1.Identity{ChainPem: leafPEM(t, "Interborough Root CA G1")}
	v := console.ViewFromAPI(st, id, 90*time.Minute)
	if v.RootCN != "Interborough Root CA G1" || v.Role != "ROOT" || v.NodeStatus != "ESTABLISHED" || v.TPM != "SEALED" {
		t.Fatalf("view mapping wrong: %+v", v)
	}
	if v.Fleet != console.FleetNotEnrolled {
		t.Fatalf("Fleet should default to not-enrolled in M2")
	}
}
