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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
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

	// UnknownExtKeyUsage carries extendedKeyUsage OIDs crypto/x509 has no
	// constant for, such as Kerberos KDC Authentication. They are encoded after
	// ExtKeyUsage in the same extension.
	UnknownExtKeyUsage []asn1.ObjectIdentifier

	// SANs.
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []*url.URL

	// OtherNames are otherName SAN entries (see KRB5PrincipalName and UPN).
	// crypto/x509 cannot encode them, so when any are present Sign builds the
	// whole subjectAltName extension itself; see subjectAltNameExtension.
	OtherNames []OtherName

	// ExtraExtensions carries raw extensions (the raw-OID escape hatch).
	ExtraExtensions []pkix.Extension

	// CRLDistributionPoints lists the URLs placed in the cRLDistributionPoints
	// extension (RFC 5280 §4.2.1.13). Empty omits the extension.
	CRLDistributionPoints []string

	// OCSPServer lists the OCSP responder URLs placed in the authorityInfoAccess
	// extension (RFC 5280 §4.2.2.1). Empty omits the AIA-OCSP access description.
	OCSPServer []string

	// IssuingCertificateURL lists the caIssuers URLs placed in the
	// authorityInfoAccess extension (RFC 5280 §4.2.2.1), where a relying party
	// that lacks the issuer can fetch it to build the chain. Empty omits the
	// AIA caIssuers access description.
	IssuingCertificateURL []string
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

// builtinExtKeyUsageOIDs lists the extendedKeyUsage OIDs crypto/x509 has a
// constant for, so a dotted OID naming one maps to the constant and is caught
// as a duplicate of the equivalent name. The table mirrors crypto/x509's own.
var builtinExtKeyUsageOIDs = []struct {
	oid asn1.ObjectIdentifier
	eku x509.ExtKeyUsage
}{
	{asn1.ObjectIdentifier{2, 5, 29, 37, 0}, x509.ExtKeyUsageAny},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, x509.ExtKeyUsageServerAuth},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, x509.ExtKeyUsageClientAuth},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, x509.ExtKeyUsageCodeSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, x509.ExtKeyUsageEmailProtection},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}, x509.ExtKeyUsageIPSECEndSystem},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}, x509.ExtKeyUsageIPSECTunnel},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}, x509.ExtKeyUsageIPSECUser},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, x509.ExtKeyUsageTimeStamping},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, x509.ExtKeyUsageOCSPSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}, x509.ExtKeyUsageMicrosoftServerGatedCrypto},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}, x509.ExtKeyUsageNetscapeServerGatedCrypto},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}, x509.ExtKeyUsageMicrosoftCommercialCodeSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}, x509.ExtKeyUsageMicrosoftKernelCodeSigning},
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

// ParseExtKeyUsage maps extended-key-usage entries to their x509 values. An
// entry is either a name from the config vocabulary or a dotted OID (anything
// starting with a digit), parsed strictly by ParseOID. An OID crypto/x509 has
// a constant for comes back in eku; any other OID comes back in unknown, for
// x509.Certificate.UnknownExtKeyUsage. An unknown name, a malformed OID, or the
// same usage listed twice (by name or OID) is an error.
func ParseExtKeyUsage(entries []string) (eku []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier, err error) {
	seenEKU := make(map[x509.ExtKeyUsage]bool)
	var seenOID []asn1.ObjectIdentifier
	for _, n := range entries {
		if n == "" || n[0] < '0' || n[0] > '9' {
			v, ok := extKeyUsageNames[n]
			if !ok {
				return nil, nil, fmt.Errorf("ca: ParseExtKeyUsage: unknown extended key usage %q", n)
			}
			if seenEKU[v] {
				return nil, nil, fmt.Errorf("ca: ParseExtKeyUsage: extended key usage %q listed twice", n)
			}
			seenEKU[v] = true
			eku = append(eku, v)
			continue
		}
		oid, err := ParseOID(n)
		if err != nil {
			return nil, nil, fmt.Errorf("ca: ParseExtKeyUsage: %w", err)
		}
		if v, ok := builtinExtKeyUsage(oid); ok {
			if seenEKU[v] {
				return nil, nil, fmt.Errorf("ca: ParseExtKeyUsage: extended key usage %q listed twice", n)
			}
			seenEKU[v] = true
			eku = append(eku, v)
			continue
		}
		for _, o := range seenOID {
			if o.Equal(oid) {
				return nil, nil, fmt.Errorf("ca: ParseExtKeyUsage: extended key usage %q listed twice", n)
			}
		}
		seenOID = append(seenOID, oid)
		unknown = append(unknown, oid)
	}
	return eku, unknown, nil
}

func builtinExtKeyUsage(oid asn1.ObjectIdentifier) (x509.ExtKeyUsage, bool) {
	for _, b := range builtinExtKeyUsageOIDs {
		if b.oid.Equal(oid) {
			return b.eku, true
		}
	}
	return 0, false
}

// ParseOID parses a dotted-decimal object identifier strictly: at least two
// arcs, each a run of decimal digits with no sign, whitespace or leading zero,
// a first arc of 0, 1 or 2, a second arc of at most 39 under 0 or 1 (X.660),
// and every arc within 31 bits so it fits asn1.ObjectIdentifier on any
// platform.
func ParseOID(s string) (asn1.ObjectIdentifier, error) {
	arcs := strings.Split(s, ".")
	if len(arcs) < 2 {
		return nil, fmt.Errorf("invalid OID %q: need at least two arcs", s)
	}
	oid := make(asn1.ObjectIdentifier, len(arcs))
	for i, a := range arcs {
		if a == "" {
			return nil, fmt.Errorf("invalid OID %q: empty arc", s)
		}
		for _, r := range a {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("invalid OID %q: non-numeric arc %q", s, a)
			}
		}
		if len(a) > 1 && a[0] == '0' {
			return nil, fmt.Errorf("invalid OID %q: arc %q has a leading zero", s, a)
		}
		n, err := strconv.ParseInt(a, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid OID %q: arc %q out of range", s, a)
		}
		oid[i] = int(n)
	}
	if oid[0] > 2 {
		return nil, fmt.Errorf("invalid OID %q: first arc must be 0, 1 or 2", s)
	}
	if oid[0] < 2 && oid[1] > 39 {
		return nil, fmt.Errorf("invalid OID %q: second arc must be at most 39 under %d", s, oid[0])
	}
	return oid, nil
}

// MinRSASubjectKeyBits is the smallest RSA subject key this CA will certify.
// 3072 matches the security level of the P-384 issuing key, and is what the
// platform CAs we subordinate emit by default.
const MinRSASubjectKeyBits = 3072

// ValidateSubjectKey reports whether pub is an acceptable subject public key,
// that is, the key belonging to the certificate being issued rather than the
// issuer's own signing key. The two are independent: the issuer's key decides
// the signature algorithm (SignatureAlgorithmFor), the subject key is simply
// certified.
//
// ECDSA is accepted on P-384 only, matching the node's own key algorithm. RSA
// is accepted at MinRSASubjectKeyBits or above: platform CAs such as VMware
// VMCA and Microsoft AD CS generate RSA keys and expose no algorithm choice,
// so rejecting RSA outright would make them impossible to subordinate.
func ValidateSubjectKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P384() {
			return fmt.Errorf("subject ECDSA key must be on P-384, got %s", k.Curve.Params().Name)
		}
		return nil
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < MinRSASubjectKeyBits {
			return fmt.Errorf("subject RSA key must be at least %d bits, got %d", MinRSASubjectKeyBits, bits)
		}
		return nil
	default:
		return fmt.Errorf("subject public key must be *ecdsa.PublicKey or *rsa.PublicKey, got %T", pub)
	}
}

// Sign builds an RFC 5280 v3 certificate template from p and signs it. When
// issuer is nil the certificate is self-signed (the issuer template is the
// subject template and issuerSigner signs its own key). Otherwise the cert is
// signed by issuer using issuerSigner. subjectPub is the public key that goes
// into the certificate; see ValidateSubjectKey for the accepted algorithms.
// The signature algorithm is derived from issuerSigner's key, independently of
// the subject key -- see SignatureAlgorithmFor.
// Returns the DER and PEM forms.
func Sign(p Profile, subjectPub crypto.PublicKey, issuer *x509.Certificate, issuerSigner crypto.Signer) (der []byte, pemBytes []byte, err error) {
	if issuerSigner == nil {
		return nil, nil, errors.New("ca: Sign: issuerSigner is required")
	}
	if err := ValidateSubjectKey(subjectPub); err != nil {
		return nil, nil, fmt.Errorf("ca: Sign: %w", err)
	}
	sigAlg, err := SignatureAlgorithmFor(issuerSigner.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("ca: Sign: %w", err)
	}
	if p.NotBefore.IsZero() || p.NotAfter.IsZero() || !p.NotAfter.After(p.NotBefore) {
		return nil, nil, errors.New("ca: Sign: NotBefore and NotAfter must be set, with NotAfter > NotBefore")
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	ski, err := subjectKeyIdentifier(subjectPub)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               p.Subject,
		NotBefore:             p.NotBefore.Add(-ClockSkewBackdate).UTC().Truncate(time.Second),
		NotAfter:              p.NotAfter.UTC().Truncate(time.Second),
		SignatureAlgorithm:    sigAlg,
		BasicConstraintsValid: true,
		IsCA:                  p.IsCA,
		KeyUsage:              p.KeyUsage,
		ExtKeyUsage:           p.ExtKeyUsage,
		UnknownExtKeyUsage:    p.UnknownExtKeyUsage,
		DNSNames:              p.DNSNames,
		IPAddresses:           p.IPAddresses,
		EmailAddresses:        p.EmailAddresses,
		URIs:                  p.URIs,
		ExtraExtensions:       p.ExtraExtensions,
		SubjectKeyId:          ski,
		CRLDistributionPoints: p.CRLDistributionPoints,
		OCSPServer:            p.OCSPServer,
		IssuingCertificateURL: p.IssuingCertificateURL,
	}
	// otherName SANs: crypto/x509 cannot encode them, so build the whole
	// subjectAltName extension here and hand it over as an extra extension.
	// CreateCertificate skips its own SAN extension when ExtraExtensions
	// carries one; the typed fields are cleared as well so exactly one is
	// emitted.
	if len(p.OtherNames) > 0 {
		san, err := subjectAltNameExtension(p)
		if err != nil {
			return nil, nil, fmt.Errorf("ca: Sign: %w", err)
		}
		template.ExtraExtensions = append(slices.Clone(p.ExtraExtensions), san)
		template.DNSNames = nil
		template.IPAddresses = nil
		template.EmailAddresses = nil
		template.URIs = nil
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

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerTemplate, subjectPub, issuerSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: Sign: CreateCertificate: %w", err)
	}
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	return derBytes, pem.EncodeToMemory(pemBlock), nil
}
