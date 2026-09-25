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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// leafProfile returns a minimal valid end-entity profile for Sign.
func leafProfile() Profile {
	now := time.Now().UTC().Truncate(time.Second)
	return Profile{
		Subject:   pkix.Name{CommonName: "dc01.ad.example.org"},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
}

// der assembles expected DER from hex fragments (tags and lengths) and plain
// strings (content octets), so the expectations below are written out by hand
// rather than produced by the code under test.
func der(t *testing.T, parts ...any) []byte {
	t.Helper()
	var out []byte
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			if rest, ok := strings.CutPrefix(v, "="); ok {
				out = append(out, rest...)
				continue
			}
			b, err := hex.DecodeString(strings.ReplaceAll(v, " ", ""))
			if err != nil {
				t.Fatalf("bad hex %q: %v", v, err)
			}
			out = append(out, b...)
		default:
			t.Fatalf("unsupported part %T", p)
		}
	}
	return out
}

// krbtgtGeneralName is the hand-encoded GeneralName for the KDC principal
// krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG (RFC 4556 section 3.2.2, explicit tags):
//
//	[0] otherName {
//	  type-id id-pkinit-san (1.3.6.1.5.2.2)
//	  value [0] EXPLICIT KRB5PrincipalName {
//	    realm         [0] GeneralString "AD.EXAMPLE.ORG"
//	    principalName [1] PrincipalName {
//	      name-type   [0] INTEGER 2 (NT-SRV-INST)
//	      name-string [1] SEQUENCE OF GeneralString { "krbtgt", "AD.EXAMPLE.ORG" }
//	}}}
func krbtgtGeneralName(t *testing.T) []byte {
	return der(t,
		"a0 43",
		"06 06 2b 06 01 05 02 02",
		"a0 39",
		"30 37",
		"a0 10", "1b 0e", "=AD.EXAMPLE.ORG",
		"a1 23",
		"30 21",
		"a0 03", "02 01 02",
		"a1 1a",
		"30 18",
		"1b 06", "=krbtgt",
		"1b 0e", "=AD.EXAMPLE.ORG",
	)
}

// upnGeneralName is the hand-encoded GeneralName for the Microsoft UPN
// administrator@ad.example.org: otherName with type-id 1.3.6.1.4.1.311.20.2.3
// and a [0] EXPLICIT UTF8String value.
func upnGeneralName(t *testing.T) []byte {
	return der(t,
		"a0 2c",
		"06 0a 2b 06 01 04 01 82 37 14 02 03",
		"a0 1e",
		"0c 1c", "=administrator@ad.example.org",
	)
}

func TestKRB5PrincipalNameEncoding(t *testing.T) {
	on, err := KRB5PrincipalName("krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG")
	if err != nil {
		t.Fatalf("KRB5PrincipalName: %v", err)
	}
	if !on.TypeID.Equal(OIDKRB5PrincipalName) {
		t.Fatalf("TypeID = %v, want %v", on.TypeID, OIDKRB5PrincipalName)
	}
	// Value is the KRB5PrincipalName SEQUENCE itself; the [0] EXPLICIT wrapper
	// is added when the GeneralName is encoded.
	want := krbtgtGeneralName(t)[12:]
	if !bytes.Equal(on.Value, want) {
		t.Fatalf("value\n got %x\nwant %x", on.Value, want)
	}

	// A user principal is NT-PRINCIPAL (1) with a single name component.
	on, err = KRB5PrincipalName("alice@AD.EXAMPLE.ORG")
	if err != nil {
		t.Fatalf("KRB5PrincipalName(user): %v", err)
	}
	wantUser := der(t,
		"30 26",
		"a0 10", "1b 0e", "=AD.EXAMPLE.ORG",
		"a1 12",
		"30 10",
		"a0 03", "02 01 01",
		"a1 09",
		"30 07",
		"1b 05", "=alice",
	)
	if !bytes.Equal(on.Value, wantUser) {
		t.Fatalf("user value\n got %x\nwant %x", on.Value, wantUser)
	}
}

func TestKRB5PrincipalNameRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"krbtgt/AD.EXAMPLE.ORG",    // no realm
		"@AD.EXAMPLE.ORG",          // no name
		"krbtgt/@AD.EXAMPLE.ORG",   // empty component
		"krbtgt//X@AD.EXAMPLE.ORG", // empty component
		"/X@AD.EXAMPLE.ORG",        // empty component
		"krbtgt/X@",                // empty realm
		"a@b@AD.EXAMPLE.ORG",       // two realm separators
		`a\/b@AD.EXAMPLE.ORG`,      // escapes are not accepted
		"a b@AD.EXAMPLE.ORG",       // whitespace
		"a\x00b@AD.EXAMPLE.ORG",    // control character
		"café@AD.EXAMPLE.ORG",      // GeneralString content is kept to ASCII
	} {
		if _, err := KRB5PrincipalName(in); err == nil {
			t.Errorf("KRB5PrincipalName(%q): expected an error", in)
		}
	}
}

func TestUPNEncoding(t *testing.T) {
	on, err := UPN("administrator@ad.example.org")
	if err != nil {
		t.Fatalf("UPN: %v", err)
	}
	if !on.TypeID.Equal(OIDMicrosoftUPN) {
		t.Fatalf("TypeID = %v, want %v", on.TypeID, OIDMicrosoftUPN)
	}
	if want := upnGeneralName(t)[16:]; !bytes.Equal(on.Value, want) {
		t.Fatalf("value\n got %x\nwant %x", on.Value, want)
	}
	for _, in := range []string{"", "administrator", "@ad.example.org", "administrator@", "a@b@c", "a b@c", "a\tb@c", "a\x7fb@c", "\xff@c"} {
		if _, err := UPN(in); err == nil {
			t.Errorf("UPN(%q): expected an error", in)
		}
	}
}

// sanExtensions returns every subjectAltName extension in cert.
func sanExtensions(cert *x509.Certificate) []pkix.Extension {
	var out []pkix.Extension
	for _, e := range cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			out = append(out, e)
		}
	}
	return out
}

// With otherNames present Sign builds the SAN extension itself. It must emit
// exactly one extension carrying every name, typed names in the order Go uses
// (dNSName, rfc822Name, iPAddress, URI) followed by the otherNames, and the
// result must still parse with crypto/x509.
func TestSignMergesOtherNamesIntoOneSANExtension(t *testing.T) {
	issuerCert, issuerSigner := selfSignedIssuer(t)
	leafKey := p384Key(t)
	krb, err := KRB5PrincipalName("krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG")
	if err != nil {
		t.Fatal(err)
	}
	upn, err := UPN("administrator@ad.example.org")
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("urn:example:dc01")
	p := leafProfile()
	p.DNSNames = []string{"dc01.ad.example.org", "ad.example.org"}
	p.EmailAddresses = []string{"pki@example.org"}
	p.IPAddresses = []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")}
	p.URIs = []*url.URL{uri}
	p.OtherNames = []OtherName{krb, upn}

	certDER, _, err := Sign(p, &leafKey.PublicKey, issuerCert, issuerSigner)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	sans := sanExtensions(cert)
	if len(sans) != 1 {
		t.Fatalf("got %d subjectAltName extensions, want exactly 1", len(sans))
	}
	if sans[0].Critical {
		t.Fatal("SAN extension is critical although the subject is not empty")
	}

	var body []byte
	body = append(body, der(t, "82 13", "=dc01.ad.example.org")...)
	body = append(body, der(t, "82 0e", "=ad.example.org")...)
	body = append(body, der(t, "81 0f", "=pki@example.org")...)
	body = append(body, der(t, "87 04 c0 00 02 0a")...)
	body = append(body, der(t, "87 10 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01")...)
	body = append(body, der(t, "86 10", "=urn:example:dc01")...)
	body = append(body, krbtgtGeneralName(t)...)
	body = append(body, upnGeneralName(t)...)
	want := append(der(t, "30 81"), byte(len(body)))
	want = append(want, body...)
	if !bytes.Equal(sans[0].Value, want) {
		t.Fatalf("SAN extension value\n got %x\nwant %x", sans[0].Value, want)
	}

	// Decode it back generically: a SEQUENCE of context-tagged GeneralNames.
	var names []asn1.RawValue
	if rest, err := asn1.Unmarshal(sans[0].Value, &names); err != nil || len(rest) != 0 {
		t.Fatalf("asn1.Unmarshal SAN: err=%v rest=%d", err, len(rest))
	}
	var tags []int
	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific {
			t.Fatalf("GeneralName class = %d, want context-specific", n.Class)
		}
		tags = append(tags, n.Tag)
	}
	if !slices.Equal(tags, []int{2, 2, 1, 7, 7, 6, 0, 0}) {
		t.Fatalf("GeneralName tags = %v", tags)
	}
	// And each otherName decodes to its type-id and a [0] EXPLICIT value.
	for i, want := range []OtherName{krb, upn} {
		var on struct {
			TypeID asn1.ObjectIdentifier
			Value  asn1.RawValue
		}
		if _, err := asn1.UnmarshalWithParams(names[6+i].FullBytes, &on, "tag:0"); err != nil {
			t.Fatalf("decode otherName %d: %v", i, err)
		}
		if !on.TypeID.Equal(want.TypeID) || on.Value.Class != asn1.ClassContextSpecific || on.Value.Tag != 0 ||
			!on.Value.IsCompound || !bytes.Equal(on.Value.Bytes, want.Value) {
			t.Fatalf("otherName %d = %v [%d/%d] %x", i, on.TypeID, on.Value.Class, on.Value.Tag, on.Value.Bytes)
		}
	}

	// crypto/x509 still sees the typed names; it skips otherName.
	if !slices.Equal(cert.DNSNames, p.DNSNames) || !slices.Equal(cert.EmailAddresses, p.EmailAddresses) ||
		len(cert.IPAddresses) != 2 || len(cert.URIs) != 1 || cert.URIs[0].String() != "urn:example:dc01" {
		t.Fatalf("typed SANs lost: dns=%v email=%v ip=%v uri=%v", cert.DNSNames, cert.EmailAddresses, cert.IPAddresses, cert.URIs)
	}
	if err := cert.CheckSignatureFrom(issuerCert); err != nil {
		t.Fatalf("CheckSignatureFrom: %v", err)
	}
}

// RFC 5280 section 4.2.1.6: with an empty subject the SAN extension MUST be
// critical. Go applies that to the SANs it builds; the manual path must too.
func TestSignOtherNameSANCriticalWithEmptySubject(t *testing.T) {
	issuerCert, issuerSigner := selfSignedIssuer(t)
	leafKey := p384Key(t)
	upn, err := UPN("administrator@ad.example.org")
	if err != nil {
		t.Fatal(err)
	}
	p := leafProfile()
	p.Subject = pkix.Name{}
	p.OtherNames = []OtherName{upn}
	certDER, _, err := Sign(p, &leafKey.PublicKey, issuerCert, issuerSigner)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	sans := sanExtensions(cert)
	if len(sans) != 1 || !sans[0].Critical {
		t.Fatalf("want one critical SAN extension, got %+v", sans)
	}
	want := append(der(t, "30 2e"), upnGeneralName(t)...)
	if !bytes.Equal(sans[0].Value, want) {
		t.Fatalf("SAN extension value\n got %x\nwant %x", sans[0].Value, want)
	}
}

// A profile cannot carry both typed otherNames and a raw subjectAltName
// extension: that would put two SAN extensions on the certificate.
func TestSignRejectsOtherNamesWithRawSANExtension(t *testing.T) {
	issuerCert, issuerSigner := selfSignedIssuer(t)
	leafKey := p384Key(t)
	upn, err := UPN("administrator@ad.example.org")
	if err != nil {
		t.Fatal(err)
	}
	p := leafProfile()
	p.OtherNames = []OtherName{upn}
	p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}}
	if _, _, err := Sign(p, &leafKey.PublicKey, issuerCert, issuerSigner); err == nil {
		t.Fatal("Sign accepted otherNames alongside a raw subjectAltName extension")
	}
}

// The manual SAN path enforces the same IA5String rule Go does for dNSName,
// rfc822Name and URI.
func TestSignOtherNameSANRejectsNonIA5(t *testing.T) {
	issuerCert, issuerSigner := selfSignedIssuer(t)
	leafKey := p384Key(t)
	upn, err := UPN("administrator@ad.example.org")
	if err != nil {
		t.Fatal(err)
	}
	p := leafProfile()
	p.OtherNames = []OtherName{upn}
	p.DNSNames = []string{"dé.example.org"}
	if _, _, err := Sign(p, &leafKey.PublicKey, issuerCert, issuerSigner); err == nil {
		t.Fatal("Sign accepted a non-IA5 dNSName")
	}
}
