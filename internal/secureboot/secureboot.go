// Package secureboot generates the X.509 signing material that backs a
// UEFI Secure Boot db entry. The build pipeline signs the UKI with sbsign
// using this key/cert; the certificate is then enrolled into platform
// firmware (the db variable) so the firmware will load the signed image.
//
// Only Go stdlib crypto is used (crypto/x509, crypto/rsa, crypto/rand).
// The key is RSA-2048: the UEFI specification mandates RSA-2048 PKCS#1 v1.5
// support for image authentication, whereas ECDSA in db is inconsistently
// implemented across firmware. Secure Boot is the one place CryptOS chooses
// RSA over its ECDSA default, for firmware interoperability.
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// keyBits is fixed at 2048: required by the UEFI spec for db image
// authentication and the widest-compatibility choice across firmware.
const keyBits = 2048

// DefaultValidity is the certificate lifetime when Options.Validity is zero.
// Secure Boot db certs are long-lived: rotating one means re-enrolling it in
// every machine's firmware, so the default is generous.
const DefaultValidity = 10 * 365 * 24 * time.Hour

// Options controls the generated signing material.
type Options struct {
	// CommonName is the certificate subject CN, e.g. "CryptOS Secure Boot
	// (ephemeral CI)" or "CryptOS Secure Boot (release)". Required.
	CommonName string
	// Validity is the certificate lifetime. Zero means DefaultValidity.
	Validity time.Duration
	// NotBefore is the start of the validity window. Zero means now (UTC).
	NotBefore time.Time
}

// Material is a generated Secure Boot signing key and its self-signed
// certificate, in the encodings the toolchain needs.
type Material struct {
	// KeyPEM is the RSA private key, PKCS#8 PEM. Fed to sbsign --key.
	KeyPEM []byte
	// CertPEM is the certificate, PEM. Fed to sbsign --cert / sbverify.
	CertPEM []byte
	// CertDER is the certificate, raw DER. This is the form enrolled into
	// firmware db (sbctl, efitools' sign-efi-sig-list, or a firmware UI).
	CertDER []byte
}

// Generate creates a fresh RSA-2048 key and a self-signed X.509 certificate
// suitable for a Secure Boot db entry: it asserts the code-signing EKU and a
// digital-signature key usage, and is marked CA so it can serve as its own
// db trust anchor.
func Generate(o Options) (*Material, error) {
	if o.CommonName == "" {
		return nil, fmt.Errorf("secureboot: CommonName is required")
	}
	validity := o.Validity
	if validity == 0 {
		validity = DefaultValidity
	}
	if validity <= 0 {
		return nil, fmt.Errorf("secureboot: validity must be positive, got %s", validity)
	}
	notBefore := o.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().UTC()
	}

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("secureboot: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("secureboot: serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: o.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("secureboot: create certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("secureboot: marshal key: %w", err)
	}

	return &Material{
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CertDER: der,
	}, nil
}
