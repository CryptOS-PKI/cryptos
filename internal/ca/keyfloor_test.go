package ca

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestValidateSubjectKeyMin(t *testing.T) {
	rsa2048 := rsaKey(t, 2048)
	rsa3072 := rsaKey(t, 3072)
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey RSA 1024: %v", err)
	}
	tests := []struct {
		name    string
		key     *rsa.PublicKey
		min     int
		wantErr bool
	}{
		{"2048 on a 2048 floor", &rsa2048.PublicKey, 2048, false},
		{"3072 on a 2048 floor", &rsa3072.PublicKey, 2048, false},
		{"2048 on the default floor", &rsa2048.PublicKey, 0, true},
		{"2048 on a 3072 floor", &rsa2048.PublicKey, 3072, true},
		{"1024 on a 2048 floor", &rsa1024.PublicKey, 2048, true},
		{"a floor below the lowest allowed", &rsa2048.PublicKey, 1024, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSubjectKeyMin(tc.key, tc.min)
			if tc.wantErr != (err != nil) {
				t.Fatalf("ValidateSubjectKeyMin(%d bits, min %d) = %v, wantErr %v", tc.key.N.BitLen(), tc.min, err, tc.wantErr)
			}
		})
	}
	if err := ValidateSubjectKeyMin(&p384Key(t).PublicKey, 2048); err != nil {
		t.Fatalf("P-384 on a 2048 floor: %v", err)
	}
}

func TestSignHonoursProfileRSAFloor(t *testing.T) {
	issuerCert, issuerKey := selfSignedIssuer(t)
	subject := rsaKey(t, 2048)
	now := time.Now().UTC().Truncate(time.Second)
	leaf := Profile{
		Subject:     pkix.Name{CommonName: "switch01.example.com"},
		NotBefore:   now,
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"switch01.example.com"},
	}

	if _, _, err := Sign(leaf, &subject.PublicKey, issuerCert, issuerKey); err == nil {
		t.Fatal("Sign of an RSA 2048 key with the default floor: want an error")
	}

	leaf.MinRSAKeyBits = LowestRSASubjectKeyBits
	der, _, err := Sign(leaf, &subject.PublicKey, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("Sign of an RSA 2048 key on a 2048 floor: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if got := cert.PublicKey.(*rsa.PublicKey).N.BitLen(); got != 2048 {
		t.Fatalf("certified key is %d bits, want 2048", got)
	}

	caProfile := leaf
	caProfile.IsCA = true
	caProfile.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	caProfile.ExtKeyUsage = nil
	if _, _, err := Sign(caProfile, &subject.PublicKey, issuerCert, issuerKey); err == nil {
		t.Fatal("Sign of a CA certificate over an RSA 2048 key: want an error, a CA key never takes the lower floor")
	}
}
