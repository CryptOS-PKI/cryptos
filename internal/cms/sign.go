package cms

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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// Signer is one signer of a SignedData.
type Signer struct {
	// Certificate identifies the signer. It is not added to the message;
	// list it in SignOptions.Certificates when the recipient needs it.
	Certificate *x509.Certificate
	// Key signs. Only the crypto.Signer interface is used, so the key can
	// stay in the TPM. It must be RSA or ECDSA and match Certificate.
	Key crypto.Signer
	// Hash is the digest: SHA-256 (the default when zero), SHA-384 or
	// SHA-512.
	Hash crypto.Hash
	// IdentifyBySKI writes the signer identifier as the certificate's
	// subjectKeyIdentifier (SignerInfo version 3) instead of issuer and
	// serial number (version 1).
	IdentifyBySKI bool
	// Attributes are extra signed attributes, such as the SCEP
	// authenticated attributes or the RFC 3161 signing-certificate
	// attribute. content-type and message-digest are always added and must
	// not be passed here.
	Attributes []Attribute
}

// SignOptions tunes Sign.
type SignOptions struct {
	// Certificates are DER certificates to carry, in order.
	Certificates [][]byte
	// CRLs are DER CertificateLists to carry, in order.
	CRLs [][]byte
	// Detached leaves eContent out; the recipient supplies the content.
	Detached bool
}

// Sign builds a ContentInfo carrying a SignedData over content, signed by
// each signer with signed attributes (RFC 5652 sections 5.3 and 5.4).
// contentType is the eContentType: OIDData for SCEP, OIDTSTInfo for an RFC
// 3161 token.
func Sign(contentType asn1.ObjectIdentifier, content []byte, signers []Signer, opts SignOptions) ([]byte, error) {
	if len(signers) == 0 {
		return nil, errors.New("cms: Sign: at least one signer is required")
	}
	if len(contentType) == 0 {
		return nil, errors.New("cms: Sign: a content type is required")
	}

	var signerInfos, digestAlgs [][]byte
	anyV3 := false
	for i, s := range signers {
		si, alg, v3, err := signOne(contentType, content, s)
		if err != nil {
			return nil, fmt.Errorf("cms: Sign: signer %d: %w", i, err)
		}
		signerInfos = append(signerInfos, si)
		if !slices.ContainsFunc(digestAlgs, func(d []byte) bool { return bytes.Equal(d, alg) }) {
			digestAlgs = append(digestAlgs, alg)
		}
		anyV3 = anyV3 || v3
	}

	// RFC 5652 section 5.1: version 3 when any SignerInfo is version 3 or
	// the content is not id-data; version 1 otherwise. (Versions 4 and 5
	// cover certificate and CRL choices this package never writes.)
	version := 1
	if anyV3 || !contentType.Equal(OIDData) {
		version = 3
	}

	var eContent []byte
	if !opts.Detached {
		eContent = content
	}
	return marshalSignedData(version, digestAlgs, contentType, eContent, !opts.Detached, opts.Certificates, opts.CRLs, signerInfos)
}

// Degenerate builds the degenerate SignedData that carries only certificates
// and CRLs: no content and no signers (RFC 5652 section 5.2, and the
// certs-only message of RFC 7030 section 4.1.3 and RFC 8894 sections 3.4 and
// 4.2). Order is preserved, so a chain written leaf first arrives leaf
// first.
func Degenerate(certs, crls [][]byte) ([]byte, error) {
	if len(certs) == 0 && len(crls) == 0 {
		return nil, errors.New("cms: Degenerate: at least one certificate or CRL is required")
	}
	for i, c := range certs {
		if len(c) == 0 {
			return nil, fmt.Errorf("cms: Degenerate: certificate %d is empty", i)
		}
	}
	for i, c := range crls {
		if len(c) == 0 {
			return nil, fmt.Errorf("cms: Degenerate: CRL %d is empty", i)
		}
	}
	// Version 1: id-data with no eContent and no version 3 signers.
	return marshalSignedData(1, nil, OIDData, nil, false, certs, crls, nil)
}

func marshalSignedData(version int, digestAlgs [][]byte, contentType asn1.ObjectIdentifier, content []byte, withContent bool, certs, crls, signerInfos [][]byte) ([]byte, error) {
	v, err := asn1.Marshal(version)
	if err != nil {
		return nil, err
	}
	ct, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, err
	}
	encap := [][]byte{ct}
	if withContent {
		octets, err := asn1.Marshal(content)
		if err != nil {
			return nil, err
		}
		encap = append(encap, tlv(0xa0, octets))
	}

	parts := [][]byte{v, derSetOf(digestAlgs), tlv(0x30, encap...)}
	// CertificateSet and RevocationInfoChoices are SET OFs, but their order
	// is not significant (RFC 5652 section 10.2.3) and every reader takes
	// them as written, which is what lets a chain arrive leaf first. They
	// are outside the signature, so no DER sorting is needed for it to
	// verify.
	if len(certs) > 0 {
		parts = append(parts, tlv(0xa0, certs...))
	}
	if len(crls) > 0 {
		parts = append(parts, tlv(0xa1, crls...))
	}
	parts = append(parts, derSetOf(signerInfos))

	oid, err := asn1.Marshal(OIDSignedData)
	if err != nil {
		return nil, err
	}
	return tlv(0x30, oid, tlv(0xa0, tlv(0x30, parts...))), nil
}

// derSetOf encodes a SET OF with its members in ascending order of their
// encodings (X.690 section 11.6).
func derSetOf(members [][]byte) []byte {
	sorted := slices.Clone(members)
	slices.SortFunc(sorted, bytes.Compare)
	return tlv(0x31, sorted...)
}

// signOne builds one SignerInfo. It returns the SignerInfo, the encoded
// digest AlgorithmIdentifier, and whether the SignerInfo is version 3.
func signOne(contentType asn1.ObjectIdentifier, content []byte, s Signer) (si, digestAlg []byte, v3 bool, err error) {
	if s.Certificate == nil || s.Key == nil {
		return nil, nil, false, errors.New("certificate and key are both required")
	}
	h := s.Hash
	if h == 0 {
		h = crypto.SHA256
	}
	alg, err := digestAlgorithm(h)
	if err != nil {
		return nil, nil, false, err
	}
	if !publicKeysEqual(s.Key.Public(), s.Certificate.PublicKey) {
		return nil, nil, false, errors.New("key does not match the certificate")
	}
	var kind signatureKind
	switch s.Key.Public().(type) {
	case *rsa.PublicKey:
		kind = sigRSA
	case *ecdsa.PublicKey:
		kind = sigECDSA
	default:
		return nil, nil, false, fmt.Errorf("%w: key type %T", ErrUnsupportedAlgorithm, s.Key.Public())
	}

	var sid []byte
	version := 1
	if s.IdentifyBySKI {
		if len(s.Certificate.SubjectKeyId) == 0 {
			return nil, nil, false, errors.New("IdentifyBySKI set but the certificate has no subjectKeyIdentifier")
		}
		sid = tlv(0x80, s.Certificate.SubjectKeyId)
		version = 3
	} else {
		serial, err := asn1.Marshal(s.Certificate.SerialNumber)
		if err != nil {
			return nil, nil, false, err
		}
		sid = tlv(0x30, s.Certificate.RawIssuer, serial)
	}

	d := h.New()
	d.Write(content)
	ctAttr, err := NewAttribute(OIDAttributeContentType, contentType)
	if err != nil {
		return nil, nil, false, err
	}
	mdAttr, err := NewAttribute(OIDAttributeMessageDigest, d.Sum(nil))
	if err != nil {
		return nil, nil, false, err
	}
	attrs := []Attribute{ctAttr, mdAttr}
	for _, a := range s.Attributes {
		if a.Type.Equal(OIDAttributeContentType) || a.Type.Equal(OIDAttributeMessageDigest) {
			return nil, nil, false, fmt.Errorf("attribute %s is set by Sign and must not be supplied", a.Type)
		}
		attrs = append(attrs, a)
	}
	encodedAttrs := make([][]byte, 0, len(attrs))
	for _, a := range attrs {
		enc, err := marshalAttribute(a)
		if err != nil {
			return nil, nil, false, err
		}
		encodedAttrs = append(encodedAttrs, enc)
	}
	signedAttrs := derSetOf(encodedAttrs)

	sd := h.New()
	sd.Write(signedAttrs)
	sig, err := s.Key.Sign(rand.Reader, sd.Sum(nil), h)
	if err != nil {
		return nil, nil, false, fmt.Errorf("sign: %w", err)
	}

	v, err := asn1.Marshal(version)
	if err != nil {
		return nil, nil, false, err
	}
	digestAlg, err = asn1.Marshal(alg)
	if err != nil {
		return nil, nil, false, err
	}
	sigAlg, err := asn1.Marshal(signatureAlgorithm(kind, h))
	if err != nil {
		return nil, nil, false, err
	}
	sigOctets, err := asn1.Marshal(sig)
	if err != nil {
		return nil, nil, false, err
	}
	implicitAttrs := bytes.Clone(signedAttrs)
	implicitAttrs[0] = 0xa0
	si = tlv(0x30, v, sid, digestAlg, implicitAttrs, sigAlg, sigOctets)
	return si, digestAlg, version == 3, nil
}

// marshalAttribute encodes an Attribute with its values DER-sorted, which
// section 5.4 requires of everything under the signature.
func marshalAttribute(a Attribute) ([]byte, error) {
	oid, err := asn1.Marshal(a.Type)
	if err != nil {
		return nil, fmt.Errorf("attribute type: %w", err)
	}
	if len(a.Values) == 0 {
		return nil, fmt.Errorf("attribute %s has no values", a.Type)
	}
	vals := make([][]byte, 0, len(a.Values))
	for _, v := range a.Values {
		enc := v.FullBytes
		if enc == nil {
			if enc, err = asn1.Marshal(v); err != nil {
				return nil, fmt.Errorf("attribute %s value: %w", a.Type, err)
			}
		}
		vals = append(vals, enc)
	}
	return tlv(0x30, oid, derSetOf(vals)), nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}
