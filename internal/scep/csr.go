package scep

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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// oidChallengePassword is the PKCS#9 challengePassword attribute (RFC 2985
// section 5.4.1), which carries the one-time challenge in a PKCSReq.
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// maxChallengeLen bounds a presented challenge. Minted challenges are much
// shorter; the bound only keeps a hostile request from hashing megabytes.
const maxChallengeLen = 255

// challengePassword returns the challengePassword attribute of a certificate
// request, or "" when it has none. crypto/x509 drops attributes whose value is
// not a SET of SEQUENCEs, and a challengePassword is a bare DirectoryString,
// so it is read from the raw request info here.
func challengePassword(csr *x509.CertificateRequest) (string, error) {
	var info struct {
		Version       int
		Subject       asn1.RawValue
		PublicKeyInfo asn1.RawValue
		Attributes    asn1.RawValue
	}
	rest, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &info)
	if err != nil || len(rest) != 0 {
		return "", errors.New("scep: the certificate request info does not parse")
	}
	if info.Attributes.Class != asn1.ClassContextSpecific || info.Attributes.Tag != 0 {
		return "", errors.New("scep: the certificate request has no attributes field")
	}
	var found string
	seen := false
	b := info.Attributes.Bytes
	for len(b) > 0 {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		b, err = asn1.Unmarshal(b, &attr)
		if err != nil {
			return "", errors.New("scep: a certificate request attribute does not parse")
		}
		if !attr.Type.Equal(oidChallengePassword) {
			continue
		}
		if seen || len(attr.Values) != 1 {
			return "", errors.New("scep: the certificate request carries more than one challengePassword")
		}
		seen = true
		if rest, err := asn1.Unmarshal(attr.Values[0].FullBytes, &found); err != nil || len(rest) != 0 {
			return "", errors.New("scep: the challengePassword is not a readable string")
		}
		if len(found) > maxChallengeLen {
			return "", fmt.Errorf("scep: the challengePassword is longer than %d characters", maxChallengeLen)
		}
	}
	return found, nil
}

// keyDescription names a subject key the way ScepEnrollment.key_alg does, for
// example "RSA-2048" or "ECDSA-P384".
func keyDescription(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA-" + strconv.Itoa(k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return "ECDSA-P256"
		case 384:
			return "ECDSA-P384"
		case 521:
			return "ECDSA-P521"
		}
		return "ECDSA"
	}
	return fmt.Sprintf("%T", pub)
}

// keyID is the SHA-256 of a DER SubjectPublicKeyInfo, the handle a
// transaction is pinned to so a retransmit or a poll from another key is not
// mistaken for the original.
func keyID(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return hex.EncodeToString(sum[:])
}
