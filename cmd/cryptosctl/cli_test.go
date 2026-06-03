package main

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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func TestGenerateBootstrapCredential(t *testing.T) {
	cred, err := generateBootstrapCredential("test-admin", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, _ := decodePEM(t, cred.CertPEM, "CERTIFICATE")
	cert, err := x509.ParseCertificate(block)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "test-admin" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if sha256.Sum256(block) != cred.SHA256 {
		t.Error("SHA256 does not match cert DER")
	}
	foundClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
	}
	if !foundClientAuth {
		t.Error("cert missing clientAuth EKU")
	}
	// Private key parses.
	keyDER, _ := decodePEM(t, cred.KeyPEM, "EC PRIVATE KEY")
	if _, err := x509.ParseECPrivateKey(keyDER); err != nil {
		t.Errorf("parse key: %v", err)
	}
	if _, err := generateBootstrapCredential("x", 0); err == nil {
		t.Error("generate with zero validity = nil error, want error")
	}
}

func decodePEM(t *testing.T, pemBytes []byte, wantType string) ([]byte, []byte) {
	t.Helper()
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			t.Fatalf("no %s PEM block found", wantType)
		}
		if block.Type == wantType {
			return block.Bytes, rest
		}
		pemBytes = rest
	}
}

func TestValidateChain(t *testing.T) {
	caDER := selfSignedCA(t)
	good := &cryptosv1.Identity{ChainDer: [][]byte{caDER}}
	if err := validateChain(good); err != nil {
		t.Errorf("validateChain(self-signed CA) = %v, want nil", err)
	}
	if err := validateChain(&cryptosv1.Identity{}); err == nil {
		t.Error("validateChain(empty) = nil, want error")
	}
	if err := validateChain(&cryptosv1.Identity{ChainDer: [][]byte{[]byte("garbage")}}); err == nil {
		t.Error("validateChain(garbage) = nil, want error")
	}
}

func TestFormatEvent(t *testing.T) {
	tests := []struct {
		ev   *cryptosv1.CeremonyEvent
		want string
	}{
		{&cryptosv1.CeremonyEvent{Detail: &cryptosv1.CeremonyEvent_KeyCreated{KeyCreated: &cryptosv1.KeyCreated{TpmPublic: []byte("abc")}}}, "KEY_CREATED"},
		{&cryptosv1.CeremonyEvent{Detail: &cryptosv1.CeremonyEvent_CertSigned{CertSigned: &cryptosv1.CertSigned{CertSha256: []byte{0xde, 0xad}}}}, "CERT_SIGNED"},
		{&cryptosv1.CeremonyEvent{Detail: &cryptosv1.CeremonyEvent_ManifestWritten{ManifestWritten: &cryptosv1.ManifestWritten{ManifestId: "id-1"}}}, "MANIFEST_WRITTEN"},
		{&cryptosv1.CeremonyEvent{Detail: &cryptosv1.CeremonyEvent_AdminRotated{AdminRotated: &cryptosv1.AdminRotated{AdminCertSha256: []byte{0x01}}}}, "ADMIN_ROTATED"},
		{&cryptosv1.CeremonyEvent{Detail: &cryptosv1.CeremonyEvent_Complete{Complete: &cryptosv1.Complete{}}}, "COMPLETE"},
		{nil, "nil event"},
	}
	for _, tc := range tests {
		if got := formatEvent(tc.ev); !strings.Contains(got, tc.want) {
			t.Errorf("formatEvent = %q, want substring %q", got, tc.want)
		}
	}
}

func TestStreamCeremony(t *testing.T) {
	events := []*cryptosv1.StartCeremonyResponse{
		{Event: &cryptosv1.CeremonyEvent{Detail: &cryptosv1.CeremonyEvent_KeyCreated{KeyCreated: &cryptosv1.KeyCreated{}}}},
		{Event: &cryptosv1.CeremonyEvent{Detail: &cryptosv1.CeremonyEvent_Complete{Complete: &cryptosv1.Complete{}}}},
	}
	i := 0
	recv := func() (*cryptosv1.StartCeremonyResponse, error) {
		if i >= len(events) {
			return nil, io.EOF
		}
		e := events[i]
		i++
		return e, nil
	}
	var buf bytes.Buffer
	if err := streamCeremony(&buf, recv); err != nil {
		t.Fatalf("streamCeremony: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "KEY_CREATED") || !strings.Contains(out, "COMPLETE") {
		t.Errorf("stream output missing events: %q", out)
	}

	// Error propagation.
	errRecv := func() (*cryptosv1.StartCeremonyResponse, error) { return nil, errors.New("boom") }
	if err := streamCeremony(io.Discard, errRecv); err == nil {
		t.Error("streamCeremony with erroring recv = nil, want error")
	}
}

func TestHumanStatus(t *testing.T) {
	s := &cryptosv1.NodeStatus{
		Role:          cryptosv1.NodeRole_NODE_ROLE_ROOT,
		IdentityState: cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
		TpmState:      cryptosv1.TpmState_TPM_STATE_OK,
		EtcdState:     cryptosv1.EtcdState_ETCD_STATE_OK,
		BootCount:     7,
	}
	out := humanStatus(s)
	for _, want := range []string{"ROOT", "ESTABLISHED", "OK", "7"} {
		if !strings.Contains(out, want) {
			t.Errorf("humanStatus missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(humanStatus(nil), "no status") {
		t.Error("humanStatus(nil) should note absence")
	}
}

func TestServerName(t *testing.T) {
	tests := map[string]string{
		"localhost:443": "localhost",
		"10.0.0.10:443": "10.0.0.10",
		"node.example":  "node.example",
	}
	for endpoint, want := range tests {
		if got := serverName(&globalOpts{endpoint: endpoint}); got != want {
			t.Errorf("serverName(%q) = %q, want %q", endpoint, got, want)
		}
	}
	if got := serverName(&globalOpts{endpoint: "x:1", serverName: "override"}); got != "override" {
		t.Errorf("serverName override = %q", got)
	}
}

func TestRenderProto(t *testing.T) {
	s := &cryptosv1.NodeStatus{BootCount: 3, Role: cryptosv1.NodeRole_NODE_ROLE_ROOT}
	var jb bytes.Buffer
	if err := renderProto(&jb, s, formatJSON); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !strings.Contains(jb.String(), "boot_count") {
		t.Errorf("json missing boot_count: %s", jb.String())
	}
	var yb bytes.Buffer
	if err := renderProto(&yb, s, formatYAML); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if !strings.Contains(yb.String(), "boot_count") {
		t.Errorf("yaml missing boot_count: %s", yb.String())
	}
	if err := renderProto(io.Discard, s, "bogus"); err == nil {
		t.Error("renderProto(bogus) = nil, want error")
	}
}

// selfSignedCA mints a self-signed CA certificate DER for chain tests.
func selfSignedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	return der
}
