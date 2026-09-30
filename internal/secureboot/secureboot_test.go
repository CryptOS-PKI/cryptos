package secureboot

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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func mustGenerate(t *testing.T, o Options) *Material {
	t.Helper()
	m, err := Generate(o)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return m
}

func parseCert(t *testing.T, m *Material) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(m.CertDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CertDER): %v", err)
	}
	return cert
}

func parseKey(t *testing.T, m *Material) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(m.KeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("KeyPEM block = %v", block)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T, want *rsa.PrivateKey", keyAny)
	}
	return rsaKey
}

func TestGenerate_KeyAndEncodings(t *testing.T) {
	m := mustGenerate(t, Options{CommonName: "CryptOS Secure Boot (test)"})

	// Key decodes as RSA-2048, PKCS#8 PEM.
	block, _ := pem.Decode(m.KeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("KeyPEM block = %v", block)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T, want *rsa.PrivateKey", keyAny)
	}
	if got := rsaKey.N.BitLen(); got != DefaultKeyBits {
		t.Errorf("key size = %d bits, want %d", got, DefaultKeyBits)
	}

	// CertPEM and CertDER describe the same certificate.
	pemBlock, _ := pem.Decode(m.CertPEM)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		t.Fatalf("CertPEM block = %v", pemBlock)
	}
	if !bytes.Equal(pemBlock.Bytes, m.CertDER) {
		t.Error("CertPEM body does not match CertDER")
	}
}

func TestGenerate_CertProperties(t *testing.T) {
	before := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := mustGenerate(t, Options{
		CommonName: "CryptOS Secure Boot (release)",
		Validity:   90 * 24 * time.Hour,
		NotBefore:  before,
	})
	cert := parseCert(t, m)

	if cert.Subject.CommonName != "CryptOS Secure Boot (release)" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Errorf("IsCA=%v BasicConstraintsValid=%v, want both true", cert.IsCA, cert.BasicConstraintsValid)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("missing digitalSignature key usage")
	}
	wantCodeSign := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			wantCodeSign = true
		}
	}
	if !wantCodeSign {
		t.Error("missing codeSigning EKU")
	}
	if !cert.NotBefore.Equal(before) {
		t.Errorf("NotBefore = %s, want %s", cert.NotBefore, before)
	}
	if want := before.Add(90 * 24 * time.Hour); !cert.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %s, want %s", cert.NotAfter, want)
	}
}

func TestGenerate_SelfSigned(t *testing.T) {
	m := mustGenerate(t, Options{CommonName: "CryptOS Secure Boot (test)"})
	cert := parseCert(t, m)

	// The certificate verifies against its own public key.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("CheckSignatureFrom(self): %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		t.Errorf("Verify against self as root: %v", err)
	}
}

func TestGenerate_DefaultValidity(t *testing.T) {
	before := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := mustGenerate(t, Options{CommonName: "x", NotBefore: before})
	cert := parseCert(t, m)
	if want := before.Add(DefaultValidity); !cert.NotAfter.Equal(want) {
		t.Errorf("default NotAfter = %s, want %s", cert.NotAfter, want)
	}
}

func TestGenerate_UniqueSerials(t *testing.T) {
	a := parseCert(t, mustGenerate(t, Options{CommonName: "x"}))
	b := parseCert(t, mustGenerate(t, Options{CommonName: "x"}))
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Error("two generations produced the same serial")
	}
}

func TestGenerate_Validation(t *testing.T) {
	cases := []struct {
		name string
		o    Options
	}{
		{"no common name", Options{}},
		{"negative validity", Options{CommonName: "x", Validity: -time.Hour}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Generate(tc.o); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestGenerate_KeyBits(t *testing.T) {
	cases := []struct {
		name    string
		keyBits int
		want    int
		wantErr bool
	}{
		{"default (zero) is 2048", 0, 2048, false},
		{"explicit 2048", 2048, 2048, false},
		{"opt-in 4096", 4096, 4096, false},
		{"unsupported 3072", 3072, 0, true},
		{"unsupported 1024", 1024, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Generate(Options{CommonName: "x", KeyBits: tc.keyBits})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if got := parseKey(t, m).N.BitLen(); got != tc.want {
				t.Errorf("key size = %d bits, want %d", got, tc.want)
			}
		})
	}
}
