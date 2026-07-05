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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// Profile is a config-independent description of the certificate to mint.
// It carries the resolved subject, validity window, CA flags, key/extended
// key usages, subject alternative names, and any raw extra extensions. The
// config layer maps its own CertificateProfile onto this struct; ca itself
// has no dependency on internal/config.
type Profile struct {
	// Subject is the X.500 DN placed in the certificate Subject.
	Subject pkix.Name

	// NotBefore and NotAfter bound the validity window.
	NotBefore time.Time
	NotAfter  time.Time

	// IsCA marks the certificate as a CA (basicConstraints cA=true).
	IsCA bool

	// PathLen sets the basicConstraints pathLenConstraint when IsCA is
	// true. nil means unconstrained (the field is omitted); a non-nil
	// value of 0 encodes pathLenConstraint=0 (MaxPathLenZero).
	PathLen *int

	// KeyUsage is the keyUsage bitmask.
	KeyUsage x509.KeyUsage

	// ExtKeyUsage is the extendedKeyUsage set (empty means none).
	ExtKeyUsage []x509.ExtKeyUsage

	// SANs.
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []*url.URL

	// ExtraExtensions carries raw extensions (the raw-OID escape hatch).
	ExtraExtensions []pkix.Extension

	// CRLDistributionPoints lists the URLs placed in the cRLDistributionPoints
	// extension (RFC 5280 §4.2.1.13). Empty omits the extension.
	CRLDistributionPoints []string

	// OCSPServer lists the OCSP responder URLs placed in the authorityInfoAccess
	// extension (RFC 5280 §4.2.2.1). Empty omits the AIA-OCSP access description.
	OCSPServer []string
}

// keyUsageNames maps the config vocabulary to x509 keyUsage bits.
var keyUsageNames = map[string]x509.KeyUsage{
	"cert_sign":         x509.KeyUsageCertSign,
	"crl_sign":          x509.KeyUsageCRLSign,
	"digital_signature": x509.KeyUsageDigitalSignature,
	"key_encipherment":  x509.KeyUsageKeyEncipherment,
	"key_agreement":     x509.KeyUsageKeyAgreement,
}

// extKeyUsageNames maps the config vocabulary to x509 extendedKeyUsage values.
var extKeyUsageNames = map[string]x509.ExtKeyUsage{
	"server_auth": x509.ExtKeyUsageServerAuth,
	"client_auth": x509.ExtKeyUsageClientAuth,
}

// ParseKeyUsage folds a slice of key-usage names into a single x509.KeyUsage
// bitmask. An unknown name is an error.
func ParseKeyUsage(names []string) (x509.KeyUsage, error) {
	var ku x509.KeyUsage
	for _, n := range names {
		bit, ok := keyUsageNames[n]
		if !ok {
			return 0, fmt.Errorf("ca: ParseKeyUsage: unknown key usage %q", n)
		}
		ku |= bit
	}
	return ku, nil
}

// ParseExtKeyUsage maps a slice of extended-key-usage names to their x509
// values. An unknown name is an error.
func ParseExtKeyUsage(names []string) ([]x509.ExtKeyUsage, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make([]x509.ExtKeyUsage, 0, len(names))
	for _, n := range names {
		eku, ok := extKeyUsageNames[n]
		if !ok {
			return nil, fmt.Errorf("ca: ParseExtKeyUsage: unknown extended key usage %q", n)
		}
		out = append(out, eku)
	}
	return out, nil
}

// Sign builds an RFC 5280 v3 certificate template from p and signs it. When
// issuer is nil the certificate is self-signed (the issuer template is the
// subject template and issuerSigner signs its own key). Otherwise the cert is
// signed by issuer using issuerSigner. subjectPub is the public key that goes
// into the certificate; it must be an *ecdsa.PublicKey on P-384 (the Phase-2
// key algorithm). Returns the DER and PEM forms.
func Sign(p Profile, subjectPub crypto.PublicKey, issuer *x509.Certificate, issuerSigner crypto.Signer) (der []byte, pemBytes []byte, err error) {
	if issuerSigner == nil {
		return nil, nil, errors.New("ca: Sign: issuerSigner is required")
	}
	pub, ok := subjectPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("ca: Sign: subject public key must be *ecdsa.PublicKey, got %T", subjectPub)
	}
	if pub.Curve != elliptic.P384() {
		return nil, nil, fmt.Errorf("ca: Sign: Phase 2 requires P-384, got %s", pub.Curve.Params().Name)
	}
	if p.NotBefore.IsZero() || p.NotAfter.IsZero() || !p.NotAfter.After(p.NotBefore) {
		return nil, nil, errors.New("ca: Sign: NotBefore and NotAfter must be set, with NotAfter > NotBefore")
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	ski, err := subjectKeyIdentifier(pub)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               p.Subject,
		NotBefore:             p.NotBefore.UTC().Truncate(time.Second),
		NotAfter:              p.NotAfter.UTC().Truncate(time.Second),
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		BasicConstraintsValid: true,
		IsCA:                  p.IsCA,
		KeyUsage:              p.KeyUsage,
		ExtKeyUsage:           p.ExtKeyUsage,
		DNSNames:              p.DNSNames,
		IPAddresses:           p.IPAddresses,
		EmailAddresses:        p.EmailAddresses,
		URIs:                  p.URIs,
		ExtraExtensions:       p.ExtraExtensions,
		SubjectKeyId:          ski,
		CRLDistributionPoints: p.CRLDistributionPoints,
		OCSPServer:            p.OCSPServer,
	}
	// pathLenConstraint: nil leaves the field omitted; a non-nil 0 encodes
	// pathLenConstraint=0 via MaxPathLenZero (RFC 5280 §4.2.1.9).
	if p.IsCA && p.PathLen != nil {
		template.MaxPathLen = *p.PathLen
		if *p.PathLen == 0 {
			template.MaxPathLenZero = true
		}
	}

	// Pick the issuer template and authorityKeyIdentifier. Self-signed uses
	// the subject template and SKI == AKI; otherwise the issuer's own SKI.
	var issuerTemplate *x509.Certificate
	if issuer == nil {
		template.Issuer = p.Subject
		template.AuthorityKeyId = ski
		issuerTemplate = template
	} else {
		template.AuthorityKeyId = issuer.SubjectKeyId
		issuerTemplate = issuer
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerTemplate, pub, issuerSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: Sign: CreateCertificate: %w", err)
	}
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	return derBytes, pem.EncodeToMemory(pemBlock), nil
}
