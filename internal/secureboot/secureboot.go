// Package secureboot generates the X.509 signing material that backs a
// UEFI Secure Boot db entry. The build pipeline signs the UKI with sbsign
// using this key/cert; the certificate is then enrolled into platform
// firmware (the db variable) so the firmware will load the signed image.
//
// Only Go stdlib crypto is used (crypto/x509, crypto/rsa, crypto/rand).
// The key is RSA, 2048 bits by default and optionally 4096: the UEFI
// specification mandates RSA-2048 PKCS#1 v1.5 support for image
// authentication, whereas ECDSA in db is inconsistently implemented across
// firmware, so RSA-2048 remains the interoperable default. Secure Boot is
// the one place CryptOS chooses RSA over its ECDSA default, for firmware
// interoperability.
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

// DefaultKeyBits is the RSA modulus size used when Options.KeyBits is zero:
// the UEFI spec mandates RSA-2048 for db image authentication, and it is the
// widest-compatibility choice across firmware, so it is the default.
const DefaultKeyBits = 2048

// supportedKeyBits is the allowlist of RSA modulus sizes Generate accepts.
// 4096 is opt-in: it requires firmware that supports RSA-4096 in db, so
// 2048 remains the interoperable default.
var supportedKeyBits = map[int]bool{2048: true, 4096: true}

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
	// KeyBits is the RSA modulus size in bits. Zero means DefaultKeyBits
	// (2048). Only 2048 and 4096 are accepted; 4096 requires firmware that
	// supports RSA-4096 in db, so 2048 remains the interoperable default.
	KeyBits int
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

// Generate creates a fresh RSA key (2048 bits by default, optionally 4096
// via Options.KeyBits) and a self-signed X.509 certificate suitable for a
// Secure Boot db entry: it asserts the code-signing EKU and a
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

	keyBits := o.KeyBits
	if keyBits == 0 {
		keyBits = DefaultKeyBits
	}
	if !supportedKeyBits[keyBits] {
		return nil, fmt.Errorf("secureboot: unsupported key size %d bits (allowed: 2048, 4096)", keyBits)
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
