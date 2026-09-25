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
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// OIDKRB5PrincipalName is id-pkinit-san (RFC 4556 section 3.2.2), the otherName
// type of a Kerberos principal name.
var OIDKRB5PrincipalName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}

// OIDMicrosoftUPN is szOID_NT_PRINCIPAL_NAME, the otherName type of a
// Microsoft user principal name.
var OIDMicrosoftUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

// oidSubjectAltName is id-ce-subjectAltName (RFC 5280 section 4.2.1.6).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// Kerberos name types (RFC 4120 section 6.2).
const (
	krb5NTPrincipal = 1 // NT-PRINCIPAL: a user or other single-component name
	krb5NTSrvInst   = 2 // NT-SRV-INST: a service with an instance, e.g. krbtgt
)

// ASN.1 universal tags this file emits that encoding/asn1 does not name.
const tagGeneralString = 27

// OtherName is one otherName subjectAltName entry (RFC 5280 section 4.2.1.6):
// a type OID and the DER encoding of its value. The value is wrapped in the
// [0] EXPLICIT tag when the GeneralName is encoded, so Value holds the bare
// value, not the wrapper.
type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  []byte
}

// KRB5PrincipalName parses a Kerberos principal of the form
// component[/component...]@REALM and returns it as an id-pkinit-san otherName,
// the SAN a PKINIT KDC certificate carries for krbtgt/REALM@REALM:
//
//	KRB5PrincipalName ::= SEQUENCE {
//	    realm         [0] Realm,          -- GeneralString
//	    principalName [1] PrincipalName }
//	PrincipalName ::= SEQUENCE {
//	    name-type     [0] Int32,
//	    name-string   [1] SEQUENCE OF KerberosString }
//
// Both modules use explicit tagging. A krbtgt/<instance> principal gets name
// type NT-SRV-INST (2); anything else NT-PRINCIPAL (1). Principal escapes are
// not accepted: every component and the realm must be non-empty printable
// ASCII without '/', '@' or '\'.
func KRB5PrincipalName(principal string) (OtherName, error) {
	name, realm, ok := strings.Cut(principal, "@")
	if !ok || strings.Contains(realm, "@") {
		return OtherName{}, fmt.Errorf("invalid Kerberos principal %q: want name@REALM", principal)
	}
	if err := checkKerberosString(realm); err != nil {
		return OtherName{}, fmt.Errorf("invalid Kerberos principal %q: realm: %w", principal, err)
	}
	components := strings.Split(name, "/")
	for _, c := range components {
		if err := checkKerberosString(c); err != nil {
			return OtherName{}, fmt.Errorf("invalid Kerberos principal %q: name: %w", principal, err)
		}
	}
	nameType := krb5NTPrincipal
	if len(components) == 2 && components[0] == "krbtgt" {
		nameType = krb5NTSrvInst
	}

	var nameStrings []byte
	for _, c := range components {
		nameStrings = append(nameStrings, tlv(asn1.ClassUniversal, tagGeneralString, false, []byte(c))...)
	}
	nameTypeDER, err := asn1.Marshal(nameType)
	if err != nil {
		return OtherName{}, fmt.Errorf("encode Kerberos name type: %w", err)
	}
	principalName := tlv(asn1.ClassUniversal, asn1.TagSequence, true, concat(
		tlv(asn1.ClassContextSpecific, 0, true, nameTypeDER),
		tlv(asn1.ClassContextSpecific, 1, true, tlv(asn1.ClassUniversal, asn1.TagSequence, true, nameStrings)),
	))
	value := tlv(asn1.ClassUniversal, asn1.TagSequence, true, concat(
		tlv(asn1.ClassContextSpecific, 0, true, tlv(asn1.ClassUniversal, tagGeneralString, false, []byte(realm))),
		tlv(asn1.ClassContextSpecific, 1, true, principalName),
	))
	return OtherName{TypeID: OIDKRB5PrincipalName, Value: value}, nil
}

// checkKerberosString accepts a non-empty principal component or realm of
// printable ASCII, excluding the separators '/' and '@' and the escape '\'.
func checkKerberosString(s string) error {
	if s == "" {
		return errors.New("empty")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c > '~' || c == '/' || c == '@' || c == '\\' {
			return fmt.Errorf("character %q not allowed", c)
		}
	}
	return nil
}

// UPN parses a Microsoft user principal name (prefix@suffix) and returns it as
// an otherName of type OIDMicrosoftUPN with a UTF8String value, the form
// Windows smart-card logon reads. Exactly one '@' with a non-empty prefix and
// suffix is required, and the name must be valid UTF-8 with no whitespace or
// control characters.
func UPN(upn string) (OtherName, error) {
	prefix, suffix, ok := strings.Cut(upn, "@")
	if !ok || prefix == "" || suffix == "" || strings.Contains(suffix, "@") {
		return OtherName{}, fmt.Errorf("invalid UPN %q: want prefix@suffix", upn)
	}
	if !utf8.ValidString(upn) {
		return OtherName{}, fmt.Errorf("invalid UPN %q: not valid UTF-8", upn)
	}
	for _, r := range upn {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return OtherName{}, fmt.Errorf("invalid UPN %q: whitespace or control character", upn)
		}
	}
	value, err := asn1.MarshalWithParams(upn, "utf8")
	if err != nil {
		return OtherName{}, fmt.Errorf("encode UPN: %w", err)
	}
	return OtherName{TypeID: OIDMicrosoftUPN, Value: value}, nil
}

// subjectAltNameExtension encodes every SAN in p (dNSName, rfc822Name,
// iPAddress and URI in the order crypto/x509 uses, then the otherNames) as one
// subjectAltName extension. Like crypto/x509 it marks the extension critical
// when the subject is empty, as RFC 5280 section 4.2.1.6 requires, and rejects
// a dNSName, rfc822Name or URI that is not an IA5String.
func subjectAltNameExtension(p Profile) (pkix.Extension, error) {
	for _, e := range p.ExtraExtensions {
		if e.Id.Equal(oidSubjectAltName) {
			return pkix.Extension{}, errors.New("otherName SANs cannot be combined with a raw subjectAltName extra extension")
		}
	}
	var names []byte
	for _, n := range p.DNSNames {
		if err := checkIA5(n); err != nil {
			return pkix.Extension{}, fmt.Errorf("SAN dNSName %q: %w", n, err)
		}
		names = append(names, tlv(asn1.ClassContextSpecific, 2, false, []byte(n))...)
	}
	for _, n := range p.EmailAddresses {
		if err := checkIA5(n); err != nil {
			return pkix.Extension{}, fmt.Errorf("SAN rfc822Name %q: %w", n, err)
		}
		names = append(names, tlv(asn1.ClassContextSpecific, 1, false, []byte(n))...)
	}
	for _, ip := range p.IPAddresses {
		b := ip.To4()
		if b == nil {
			b = ip.To16()
		}
		if b == nil {
			return pkix.Extension{}, fmt.Errorf("SAN iPAddress %v: not an IPv4 or IPv6 address", ip)
		}
		names = append(names, tlv(asn1.ClassContextSpecific, 7, false, b)...)
	}
	for _, u := range p.URIs {
		s := u.String()
		if err := checkIA5(s); err != nil {
			return pkix.Extension{}, fmt.Errorf("SAN URI %q: %w", s, err)
		}
		names = append(names, tlv(asn1.ClassContextSpecific, 6, false, []byte(s))...)
	}
	for _, on := range p.OtherNames {
		typeID, err := asn1.Marshal(on.TypeID)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("SAN otherName type %v: %w", on.TypeID, err)
		}
		names = append(names, tlv(asn1.ClassContextSpecific, 0, true, concat(
			typeID,
			tlv(asn1.ClassContextSpecific, 0, true, on.Value),
		))...)
	}

	subject, err := asn1.Marshal(p.Subject.ToRDNSequence())
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode subject: %w", err)
	}
	return pkix.Extension{
		Id:       oidSubjectAltName,
		Critical: bytes.Equal(subject, []byte{0x30, 0x00}),
		Value:    tlv(asn1.ClassUniversal, asn1.TagSequence, true, names),
	}, nil
}

// checkIA5 reports whether s fits an IA5String (7-bit ASCII).
func checkIA5(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return errors.New("not an IA5String")
		}
	}
	return nil
}

// tlv encodes one DER tag-length-value. encoding/asn1 writes the identifier
// and the definite length; content is taken as already-encoded octets.
func tlv(class, tag int, compound bool, content []byte) []byte {
	// Marshalling a RawValue with a small tag and non-nil class cannot fail.
	out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: content})
	if err != nil {
		panic(fmt.Sprintf("ca: tlv: %v", err))
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
