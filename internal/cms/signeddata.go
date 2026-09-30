package cms

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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Sentinel errors. Callers match them with errors.Is; the wrapped detail is
// structural only and never carries content, plaintext or key material.
var (
	// ErrVerification means a signature, a message digest or a
	// content-type attribute did not check out.
	ErrVerification = errors.New("cms: verification failed")
	// ErrSignerNotFound means no candidate certificate matches a
	// SignerInfo's signer identifier.
	ErrSignerNotFound = errors.New("cms: signer certificate not found")
	// ErrUnsupportedAlgorithm means an algorithm outside the package's
	// allowlist: SHA-256/384/512, RSA PKCS#1 v1.5 and ECDSA signatures, RSA
	// PKCS#1 v1.5 key transport, and AES-128/256-CBC.
	ErrUnsupportedAlgorithm = errors.New("cms: unsupported algorithm")
	// ErrAttributeNotFound means a requested signed attribute is absent.
	ErrAttributeNotFound = errors.New("cms: attribute not found")
)

// Attribute is an RFC 5652 section 5.3 Attribute: a type and a SET OF values,
// each kept as its DER encoding.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// NewAttribute builds a single-valued attribute. value is anything
// encoding/asn1 can marshal; an asn1.RawValue is written as given, which is
// how a caller picks a string type such as PrintableString.
func NewAttribute(t asn1.ObjectIdentifier, value any) (Attribute, error) {
	der, err := asn1.Marshal(value)
	if err != nil {
		return Attribute{}, fmt.Errorf("cms: attribute %s: %w", t, err)
	}
	return Attribute{Type: t, Values: []asn1.RawValue{{FullBytes: der}}}, nil
}

// IssuerAndSerial is the RFC 5652 section 10.2.4 IssuerAndSerialNumber.
// Issuer holds the DER Name, so it compares directly against
// x509.Certificate.RawIssuer.
type IssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

func (ias *IssuerAndSerial) matches(c *x509.Certificate) bool {
	return bytes.Equal(ias.Issuer.FullBytes, c.RawIssuer) && ias.SerialNumber.Cmp(c.SerialNumber) == 0
}

// SignerInfo is a parsed RFC 5652 section 5.3 SignerInfo. Exactly one of
// IssuerAndSerial and SubjectKeyID is set.
type SignerInfo struct {
	Version            int
	IssuerAndSerial    *IssuerAndSerial
	SubjectKeyID       []byte
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   []Attribute
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []Attribute

	// rawSignedAttrs is the [0] IMPLICIT encoding exactly as received; the
	// signature covers these bytes (with the SET tag), not a re-encoding.
	rawSignedAttrs []byte
}

// SignedAttribute unmarshals the single value of the signed attribute t into
// out. An attribute that appears more than once, or with other than one
// value, is refused: every attribute CMS, SCEP and RFC 3161 define here is
// single-valued, and ambiguity in an authenticated field is not something to
// resolve by picking one.
func (si *SignerInfo) SignedAttribute(t asn1.ObjectIdentifier, out any) error {
	return singleAttribute(si.SignedAttributes, t, out)
}

func singleAttribute(attrs []Attribute, t asn1.ObjectIdentifier, out any) error {
	var found *Attribute
	for i := range attrs {
		if attrs[i].Type.Equal(t) {
			if found != nil {
				return fmt.Errorf("cms: attribute %s appears more than once", t)
			}
			found = &attrs[i]
		}
	}
	if found == nil {
		return fmt.Errorf("%w: %s", ErrAttributeNotFound, t)
	}
	if len(found.Values) != 1 {
		return fmt.Errorf("cms: attribute %s has %d values, want 1", t, len(found.Values))
	}
	rest, err := asn1.Unmarshal(found.Values[0].FullBytes, out)
	if err != nil {
		return fmt.Errorf("cms: attribute %s: %w", t, err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("cms: attribute %s: trailing bytes", t)
	}
	return nil
}

// SignedData is a parsed RFC 5652 section 5.1 SignedData.
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier
	// ContentType is the eContentType.
	ContentType asn1.ObjectIdentifier
	// Content is the eContent, or nil when it is absent (a detached
	// signature, or a degenerate certs-only message).
	Content []byte
	// Certificates are the DER certificates in the order they were
	// written. Other CertificateChoices (attribute certificates) are
	// skipped.
	Certificates [][]byte
	// CRLs are the DER CertificateLists. Other RevocationInfoChoices are
	// skipped.
	CRLs        [][]byte
	SignerInfos []SignerInfo
}

// Wire shapes for encoding/asn1. Optional implicitly tagged fields are
// structs holding RawContent rather than bare RawValues: encoding/asn1 does
// not check the tag of an optional RawValue, so one would swallow whatever
// element comes next.
type (
	rawContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	rawTagged struct {
		Raw asn1.RawContent
	}
	rawEncapContentInfo struct {
		EContentType asn1.ObjectIdentifier
		EContent     rawTagged `asn1:"optional,tag:0"`
	}
	rawSignedData struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		EncapContentInfo rawEncapContentInfo
		Certificates     rawTagged       `asn1:"optional,tag:0"`
		CRLs             rawTagged       `asn1:"optional,tag:1"`
		SignerInfos      []rawSignerInfo `asn1:"set"`
	}
	rawSignerInfo struct {
		Version            int
		SID                asn1.RawValue
		DigestAlgorithm    pkix.AlgorithmIdentifier
		SignedAttrs        rawTagged `asn1:"optional,tag:0"`
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          []byte
		UnsignedAttrs      rawTagged `asn1:"optional,tag:1"`
	}
)

// parseContentInfo normalizes BER to DER, then unwraps the RFC 5652 section 3
// ContentInfo, requiring the given content type. It returns the DER of the
// inner content.
func parseContentInfo(in []byte, want asn1.ObjectIdentifier, what string) ([]byte, error) {
	der, err := normalizeBER(in)
	if err != nil {
		return nil, fmt.Errorf("cms: %s: %w", what, err)
	}
	var ci rawContentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("cms: %s: ContentInfo: %w", what, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("cms: %s: trailing bytes after ContentInfo", what)
	}
	if !ci.ContentType.Equal(want) {
		return nil, fmt.Errorf("cms: %s: content type is %s, want %s", what, ci.ContentType, want)
	}
	if ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 || !ci.Content.IsCompound {
		return nil, fmt.Errorf("cms: %s: content is not the [0] EXPLICIT wrapper", what)
	}
	return ci.Content.Bytes, nil
}

// taggedContents returns the contents of an optional context-tagged field, or
// nil when it was absent.
func taggedContents(t rawTagged) ([]byte, error) {
	if t.Raw == nil {
		return nil, nil
	}
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(t.Raw, &v); err != nil {
		return nil, err
	}
	return v.Bytes, nil
}

// splitElements splits concatenated DER elements, keeping each one's full
// encoding.
func splitElements(b []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}

func parseAttributes(contents []byte) ([]Attribute, error) {
	elems, err := splitElements(contents)
	if err != nil {
		return nil, err
	}
	attrs := make([]Attribute, 0, len(elems))
	for _, e := range elems {
		var a Attribute
		rest, err := asn1.Unmarshal(e.FullBytes, &a)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("trailing bytes in attribute")
		}
		attrs = append(attrs, a)
	}
	return attrs, nil
}

// ParseSignedData parses a ContentInfo carrying a SignedData. BER input
// (indefinite lengths, a chunked eContent) is accepted. Parsing checks
// structure only; call Verify before trusting anything in it.
func ParseSignedData(in []byte) (*SignedData, error) {
	inner, err := parseContentInfo(in, OIDSignedData, "SignedData")
	if err != nil {
		return nil, err
	}
	var raw rawSignedData
	rest, err := asn1.Unmarshal(inner, &raw)
	if err != nil {
		return nil, fmt.Errorf("cms: SignedData: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("cms: SignedData: trailing bytes")
	}

	sd := &SignedData{
		Version:          raw.Version,
		DigestAlgorithms: raw.DigestAlgorithms,
		ContentType:      raw.EncapContentInfo.EContentType,
	}
	if raw.EncapContentInfo.EContent.Raw != nil {
		// [0] EXPLICIT: the tagged element's contents are the OCTET STRING.
		inner, err := taggedContents(raw.EncapContentInfo.EContent)
		if err != nil {
			return nil, fmt.Errorf("cms: SignedData: eContent: %w", err)
		}
		var content []byte
		if rest, err := asn1.Unmarshal(inner, &content); err != nil || len(rest) != 0 {
			return nil, errors.New("cms: SignedData: eContent is not an OCTET STRING")
		}
		if content == nil {
			content = []byte{}
		}
		sd.Content = content
	}

	certs, err := taggedContents(raw.Certificates)
	if err != nil {
		return nil, fmt.Errorf("cms: SignedData: certificates: %w", err)
	}
	elems, err := splitElements(certs)
	if err != nil {
		return nil, fmt.Errorf("cms: SignedData: certificates: %w", err)
	}
	for _, e := range elems {
		if e.Class == asn1.ClassUniversal && e.Tag == asn1.TagSequence {
			sd.Certificates = append(sd.Certificates, e.FullBytes)
		}
	}

	crls, err := taggedContents(raw.CRLs)
	if err != nil {
		return nil, fmt.Errorf("cms: SignedData: crls: %w", err)
	}
	elems, err = splitElements(crls)
	if err != nil {
		return nil, fmt.Errorf("cms: SignedData: crls: %w", err)
	}
	for _, e := range elems {
		if e.Class == asn1.ClassUniversal && e.Tag == asn1.TagSequence {
			sd.CRLs = append(sd.CRLs, e.FullBytes)
		}
	}

	for i, rsi := range raw.SignerInfos {
		si, err := parseSignerInfo(rsi)
		if err != nil {
			return nil, fmt.Errorf("cms: SignedData: signer %d: %w", i, err)
		}
		sd.SignerInfos = append(sd.SignerInfos, si)
	}
	return sd, nil
}

func parseSignerInfo(r rawSignerInfo) (SignerInfo, error) {
	si := SignerInfo{
		Version:            r.Version,
		DigestAlgorithm:    r.DigestAlgorithm,
		SignatureAlgorithm: r.SignatureAlgorithm,
		Signature:          r.Signature,
	}
	switch {
	case r.SID.Class == asn1.ClassUniversal && r.SID.Tag == asn1.TagSequence:
		var ias IssuerAndSerial
		if rest, err := asn1.Unmarshal(r.SID.FullBytes, &ias); err != nil || len(rest) != 0 {
			return SignerInfo{}, errors.New("malformed issuerAndSerialNumber")
		}
		si.IssuerAndSerial = &ias
	case r.SID.Class == asn1.ClassContextSpecific && r.SID.Tag == 0 && !r.SID.IsCompound:
		if len(r.SID.Bytes) == 0 {
			return SignerInfo{}, errors.New("empty subjectKeyIdentifier")
		}
		si.SubjectKeyID = r.SID.Bytes
	default:
		return SignerInfo{}, errors.New("unknown signer identifier")
	}

	if r.SignedAttrs.Raw != nil {
		contents, err := taggedContents(r.SignedAttrs)
		if err != nil {
			return SignerInfo{}, fmt.Errorf("signed attributes: %w", err)
		}
		attrs, err := parseAttributes(contents)
		if err != nil {
			return SignerInfo{}, fmt.Errorf("signed attributes: %w", err)
		}
		// RFC 5652 section 5.3: SIZE (1..MAX).
		if len(attrs) == 0 {
			return SignerInfo{}, errors.New("signed attributes present but empty")
		}
		si.SignedAttributes = attrs
		si.rawSignedAttrs = r.SignedAttrs.Raw
	}
	if r.UnsignedAttrs.Raw != nil {
		contents, err := taggedContents(r.UnsignedAttrs)
		if err != nil {
			return SignerInfo{}, fmt.Errorf("unsigned attributes: %w", err)
		}
		attrs, err := parseAttributes(contents)
		if err != nil {
			return SignerInfo{}, fmt.Errorf("unsigned attributes: %w", err)
		}
		si.UnsignedAttributes = attrs
	}
	return si, nil
}

// VerifyOptions tunes Verify.
type VerifyOptions struct {
	// Content supplies the content of a detached signature. It must be nil
	// when the message carries its own eContent.
	Content []byte
	// Certificates are extra candidates for the signer certificate, beyond
	// those carried in the message: a SCEP RenewalReq signer the server
	// already knows, say.
	Certificates []*x509.Certificate
}

// Verify checks every SignerInfo and returns each signer's certificate, in
// SignerInfo order. For each signer it checks, per RFC 5652 section 5.6,
// that the content-type attribute equals eContentType, that the
// message-digest attribute equals the digest of the content, and that the
// signature over the DER signed attributes verifies under the identified
// certificate's key.
//
// Verify proves who signed, not whether to trust them: it does no path
// validation, validity-period, key-usage or revocation checks. Those are the
// caller's policy, applied to the returned certificates.
func (sd *SignedData) Verify(opts VerifyOptions) ([]*x509.Certificate, error) {
	content := sd.Content
	if opts.Content != nil {
		if sd.Content != nil {
			return nil, errors.New("cms: Verify: detached content supplied for a message that carries its own")
		}
		content = opts.Content
	}
	if content == nil {
		return nil, errors.New("cms: Verify: no content to verify (detached signature without VerifyOptions.Content)")
	}
	if len(sd.SignerInfos) == 0 {
		return nil, errors.New("cms: Verify: the message has no signers")
	}

	candidates := make([]*x509.Certificate, 0, len(sd.Certificates)+len(opts.Certificates))
	for i, der := range sd.Certificates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("cms: Verify: certificate %d: %w", i, err)
		}
		candidates = append(candidates, c)
	}
	candidates = append(candidates, opts.Certificates...)

	signers := make([]*x509.Certificate, 0, len(sd.SignerInfos))
	for i := range sd.SignerInfos {
		si := &sd.SignerInfos[i]
		cert := si.findCertificate(candidates)
		if cert == nil {
			return nil, fmt.Errorf("%w: signer %d", ErrSignerNotFound, i)
		}
		if err := si.verify(cert, content, sd.ContentType); err != nil {
			return nil, fmt.Errorf("cms: Verify: signer %d: %w", i, err)
		}
		signers = append(signers, cert)
	}
	return signers, nil
}

func (si *SignerInfo) findCertificate(candidates []*x509.Certificate) *x509.Certificate {
	for _, c := range candidates {
		switch {
		case si.IssuerAndSerial != nil:
			if si.IssuerAndSerial.matches(c) {
				return c
			}
		case len(c.SubjectKeyId) > 0 && bytes.Equal(si.SubjectKeyID, c.SubjectKeyId):
			return c
		}
	}
	return nil
}

func (si *SignerInfo) verify(cert *x509.Certificate, content []byte, contentType asn1.ObjectIdentifier) error {
	h, err := hashForDigestOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	kind, err := signatureScheme(si.SignatureAlgorithm.Algorithm, h)
	if err != nil {
		return err
	}

	contentDigest := h.New()
	contentDigest.Write(content)
	sum := contentDigest.Sum(nil)

	var signedBytes []byte
	if si.rawSignedAttrs == nil {
		// RFC 5652 section 5.3: signed attributes may be omitted only for
		// id-data, and then the signature is over the content itself.
		if !contentType.Equal(OIDData) {
			return fmt.Errorf("%w: signed attributes are required for content type %s", ErrVerification, contentType)
		}
		signedBytes = content
	} else {
		var ct asn1.ObjectIdentifier
		if err := si.SignedAttribute(OIDAttributeContentType, &ct); err != nil {
			return fmt.Errorf("%w: content-type attribute: %v", ErrVerification, err)
		}
		if !ct.Equal(contentType) {
			return fmt.Errorf("%w: content-type attribute %s does not match eContentType %s", ErrVerification, ct, contentType)
		}
		var md []byte
		if err := si.SignedAttribute(OIDAttributeMessageDigest, &md); err != nil {
			return fmt.Errorf("%w: message-digest attribute: %v", ErrVerification, err)
		}
		if subtle.ConstantTimeCompare(md, sum) != 1 {
			return fmt.Errorf("%w: message digest does not match the content", ErrVerification)
		}
		// Section 5.4: the signature covers the DER of the attributes with
		// an explicit SET OF tag, not the [0] IMPLICIT tag they travel
		// under.
		signedBytes = bytes.Clone(si.rawSignedAttrs)
		signedBytes[0] = 0x31
	}

	sigDigest := h.New()
	sigDigest.Write(signedBytes)
	return checkSignature(cert.PublicKey, kind, h, sigDigest.Sum(nil), si.Signature)
}

func checkSignature(pub crypto.PublicKey, kind signatureKind, h crypto.Hash, digest, sig []byte) error {
	switch kind {
	case sigRSA:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: RSA signature but the certificate key is %T", ErrVerification, pub)
		}
		if err := rsa.VerifyPKCS1v15(k, h, digest, sig); err != nil {
			return fmt.Errorf("%w: RSA signature does not verify", ErrVerification)
		}
	case sigECDSA:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: ECDSA signature but the certificate key is %T", ErrVerification, pub)
		}
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return fmt.Errorf("%w: ECDSA signature does not verify", ErrVerification)
		}
	}
	return nil
}
