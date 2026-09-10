package est

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
	"encoding/asn1"
	"errors"
	"fmt"
)

// PKCS#7 / CMS object identifiers (RFC 5652 section 3 and 4).
var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// contentInfo is the RFC 5652 section 3 outer wrapper. Content is [0]
// EXPLICIT, which is written by hand as a constructed context tag rather than
// with an `explicit` struct tag: encoding/asn1 ignores the tag options on a
// RawValue and emits it verbatim, so the wrapper would silently go missing.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

// encapsulatedContentInfo is the RFC 5652 section 5.2 eContent wrapper. For a
// certs-only message the eContent itself is absent, so only the type remains.
type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
}

// signedData is the RFC 5652 section 5.1 SignedData, restricted to the
// degenerate certs-only shape: no digest algorithms, no encapsulated content,
// and no signers. Only the certificate set carries anything.
type signedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// CertsOnlyPKCS7 builds the degenerate "certs-only" SignedData that EST uses
// to carry certificates (RFC 7030 sections 4.1.3 and 4.2.3; the structure is
// RFC 5652 section 5.2, which explicitly blesses a SignedData with no signers
// as the way to transport a certificate set).
//
// The Go standard library has no CMS writer, and this is the whole of what EST
// needs from CMS: an ASN.1 envelope with a certificate set and nothing else.
// Pulling in a PKCS#7 library to emit forty bytes of fixed structure would put
// a third-party ASN.1 parser next to the CA for no benefit.
//
// certs are DER certificates in the order they should appear, conventionally
// leaf first. At least one is required: an empty certs-only message is legal
// ASN.1 but means nothing to a client.
func CertsOnlyPKCS7(certs [][]byte) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("est: CertsOnlyPKCS7: at least one certificate is required")
	}

	// CertificateSet is [0] IMPLICIT SET OF CertificateChoices. DER wants a
	// SET's members sorted, but RFC 5652 section 10.2.3 defines this as a SET
	// OF whose order is not significant, and every implementation reads it as
	// a sequence of certificates in the order written -- which is what lets
	// the chain arrive leaf-first.
	var certBytes []byte
	for i, der := range certs {
		if len(der) == 0 {
			return nil, fmt.Errorf("est: CertsOnlyPKCS7: certificate %d is empty", i)
		}
		certBytes = append(certBytes, der...)
	}

	sd := signedData{
		// Version 1: no eContent and no version-2 attribute certificates, so
		// the RFC 5652 section 5.1 rules land on 1.
		Version:          1,
		DigestAlgorithms: []asn1.RawValue{},
		EncapContentInfo: encapsulatedContentInfo{EContentType: oidData},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certBytes,
		},
		SignerInfos: []asn1.RawValue{},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("est: CertsOnlyPKCS7: marshal SignedData: %w", err)
	}

	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}
	out, err := asn1.Marshal(ci)
	if err != nil {
		return nil, fmt.Errorf("est: CertsOnlyPKCS7: marshal ContentInfo: %w", err)
	}
	return out, nil
}

// ParseCertsOnlyPKCS7 extracts the DER certificates from a certs-only
// SignedData. It exists so the package can verify its own output in tests and
// so a caller can read a message it was handed; nothing on the serving path
// consumes CMS.
func ParseCertsOnlyPKCS7(der []byte) ([][]byte, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("est: ParseCertsOnlyPKCS7: ContentInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("est: ParseCertsOnlyPKCS7: trailing bytes after ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("est: ParseCertsOnlyPKCS7: content type is %s, want signedData", ci.ContentType)
	}
	if ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 || !ci.Content.IsCompound {
		return nil, errors.New("est: ParseCertsOnlyPKCS7: content is not the [0] EXPLICIT wrapper")
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("est: ParseCertsOnlyPKCS7: SignedData: %w", err)
	}

	var out [][]byte
	remaining := sd.Certificates.Bytes
	for len(remaining) > 0 {
		var one asn1.RawValue
		next, err := asn1.Unmarshal(remaining, &one)
		if err != nil {
			return nil, fmt.Errorf("est: ParseCertsOnlyPKCS7: certificate: %w", err)
		}
		out = append(out, one.FullBytes)
		remaining = next
	}
	return out, nil
}
