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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"

	"github.com/CryptOS-PKI/cryptos-node/internal/cms"
)

// SCEP authenticated attributes (RFC 8894 section 3.2.1), under
// id-VeriSign pki attributes 2.16.840.1.113733.1.9.
var (
	oidMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidFailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// Digest algorithm OIDs a SCEP signer may use (RFC 5754). The CMS layer has
// already refused anything else by the time these are read.
var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// MessageType is the SCEP messageType attribute (RFC 8894 section 3.2.1.2).
type MessageType int

// The message types this server reads and writes.
const (
	MessageTypeCertRep    MessageType = 3
	MessageTypeRenewalReq MessageType = 17
	MessageTypePKCSReq    MessageType = 19
	MessageTypeCertPoll   MessageType = 20
	MessageTypeGetCert    MessageType = 21
	MessageTypeGetCRL     MessageType = 22
)

func (m MessageType) String() string {
	switch m {
	case MessageTypeCertRep:
		return "CertRep"
	case MessageTypeRenewalReq:
		return "RenewalReq"
	case MessageTypePKCSReq:
		return "PKCSReq"
	case MessageTypeCertPoll:
		return "CertPoll"
	case MessageTypeGetCert:
		return "GetCert"
	case MessageTypeGetCRL:
		return "GetCRL"
	}
	return "messageType(" + strconv.Itoa(int(m)) + ")"
}

// PKIStatus is the pkiStatus attribute of a CertRep (RFC 8894 section
// 3.2.1.3).
type PKIStatus int

// The pkiStatus values.
const (
	StatusSuccess PKIStatus = 0
	StatusFailure PKIStatus = 2
	StatusPending PKIStatus = 3
)

func (s PKIStatus) String() string {
	switch s {
	case StatusSuccess:
		return "SUCCESS"
	case StatusFailure:
		return "FAILURE"
	case StatusPending:
		return "PENDING"
	}
	return "pkiStatus(" + strconv.Itoa(int(s)) + ")"
}

// FailInfo is the failInfo attribute of a FAILURE CertRep (RFC 8894 section
// 3.2.1.4).
type FailInfo int

// The failInfo values.
const (
	FailBadAlg          FailInfo = 0
	FailBadMessageCheck FailInfo = 1
	FailBadRequest      FailInfo = 2
	FailBadTime         FailInfo = 3
	FailBadCertID       FailInfo = 4
)

func (f FailInfo) String() string {
	switch f {
	case FailBadAlg:
		return "badAlg"
	case FailBadMessageCheck:
		return "badMessageCheck"
	case FailBadRequest:
		return "badRequest"
	case FailBadTime:
		return "badTime"
	case FailBadCertID:
		return "badCertId"
	}
	return "failInfo(" + strconv.Itoa(int(f)) + ")"
}

// nonceLen is the size of the senderNonce this server writes. RFC 8894
// section 3.2.1.5 calls for 16 bytes.
const nonceLen = 16

// errMalformed marks a request that cannot be answered with a CertRep at all,
// because the attributes a reply has to echo are missing or unreadable. The
// HTTP layer answers it with 400.
var errMalformed = errors.New("scep: malformed pkiMessage")

// request is a parsed, signature-checked SCEP pkiMessage.
type request struct {
	Type          MessageType
	TransactionID string
	SenderNonce   []byte
	// Signer is the certificate the message was signed with: a self-signed
	// certificate over the requester's key for PKCSReq, the current
	// certificate for RenewalReq.
	Signer *x509.Certificate
	// Hash is the signer's digest algorithm, mirrored in the reply.
	Hash crypto.Hash
	// Envelope is the pkcsPKIEnvelope, still encrypted.
	Envelope *cms.EnvelopedData
	// VerifyErr is set when the attributes were readable but the signature
	// did not verify. Such a request is answered FAILURE badMessageCheck and
	// nothing else is done with it.
	VerifyErr error
}

// parseRequest parses a pkiMessage (RFC 8894 section 3.2), verifies its
// signature and reads the authenticated attributes. A returned request with
// VerifyErr set carries enough to reply to; an error wrapping errMalformed
// does not.
func parseRequest(der []byte) (*request, error) {
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}
	if !sd.ContentType.Equal(cms.OIDData) || sd.Content == nil {
		return nil, fmt.Errorf("%w: the SignedData does not carry id-data content", errMalformed)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("%w: want exactly one signer, got %d", errMalformed, len(sd.SignerInfos))
	}
	si := &sd.SignerInfos[0]

	req := &request{}
	var msgType string
	if err := si.SignedAttribute(oidMessageType, &msgType); err != nil {
		return nil, fmt.Errorf("%w: messageType: %v", errMalformed, err)
	}
	n, err := strconv.Atoi(msgType)
	if err != nil {
		return nil, fmt.Errorf("%w: messageType %q is not a number", errMalformed, msgType)
	}
	req.Type = MessageType(n)
	if err := si.SignedAttribute(oidTransactionID, &req.TransactionID); err != nil || req.TransactionID == "" {
		return nil, fmt.Errorf("%w: transactionID is missing or unreadable", errMalformed)
	}
	if len(req.TransactionID) > maxTransactionIDLen {
		return nil, fmt.Errorf("%w: transactionID is longer than %d characters", errMalformed, maxTransactionIDLen)
	}
	if err := si.SignedAttribute(oidSenderNonce, &req.SenderNonce); err != nil || len(req.SenderNonce) == 0 {
		return nil, fmt.Errorf("%w: senderNonce is missing or unreadable", errMalformed)
	}
	if req.Hash, err = hashForOID(si.DigestAlgorithm.Algorithm); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}

	signers, verr := sd.Verify(cms.VerifyOptions{})
	if verr != nil {
		req.VerifyErr = verr
		req.Signer = certificateFor(sd, si)
		if req.Signer == nil {
			return nil, fmt.Errorf("%w: the signer certificate is not in the message: %v", errMalformed, verr)
		}
		return req, nil
	}
	req.Signer = signers[0]

	env, err := cms.ParseEnvelopedData(sd.Content)
	if err != nil {
		req.VerifyErr = fmt.Errorf("the pkcsPKIEnvelope does not parse: %w", err)
		return req, nil
	}
	req.Envelope = env
	return req, nil
}

// maxTransactionIDLen bounds a transactionID. The RFC fixes no length; real
// clients send a hex or base64 digest of their key, well under this.
const maxTransactionIDLen = 256

// certificateFor finds the signer's certificate among those carried in the
// message, for replying to a request whose signature did not verify.
func certificateFor(sd *cms.SignedData, si *cms.SignerInfo) *x509.Certificate {
	for _, der := range sd.Certificates {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if si.IssuerAndSerial != nil && si.IssuerAndSerial.SerialNumber.Cmp(c.SerialNumber) == 0 &&
			string(si.IssuerAndSerial.Issuer.FullBytes) == string(c.RawIssuer) {
			return c
		}
		if si.SubjectKeyID != nil && string(si.SubjectKeyID) == string(c.SubjectKeyId) {
			return c
		}
	}
	return nil
}

func hashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("digest algorithm %s is not accepted", oid)
}

// contentEncryptionFor mirrors the request's content encryption in the reply,
// so a client that asked for AES-256 gets AES-256 back.
func contentEncryptionFor(env *cms.EnvelopedData) cms.ContentEncryption {
	if env != nil && env.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256CBC) {
		return cms.AES256CBC
	}
	return cms.AES128CBC
}

// reply is what a CertRep says.
type reply struct {
	Status   PKIStatus
	FailInfo FailInfo
	// Certs are the DER certificates of a SUCCESS reply; CRL is the DER CRL
	// of a GetCRL SUCCESS. Exactly one is set on SUCCESS.
	Certs [][]byte
	CRL   []byte
	// Reason is for the logs and the audit trail only. RFC 8894 gives the
	// client a failInfo code and nothing else.
	Reason string
}

func failure(fi FailInfo, format string, args ...any) reply {
	return reply{Status: StatusFailure, FailInfo: fi, Reason: fmt.Sprintf(format, args...)}
}

// buildCertRep writes the CertRep for req (RFC 8894 section 3.3.2), signed by
// the RA. On SUCCESS the certificates or CRL travel in a degenerate SignedData
// encrypted to the request signer; on FAILURE and PENDING there is no
// pkcsPKIEnvelope and the SignedData carries no content.
func buildCertRep(req *request, ra *raCert, rep reply) ([]byte, error) {
	senderNonce := make([]byte, nonceLen)
	if _, err := rand.Read(senderNonce); err != nil {
		return nil, fmt.Errorf("scep: senderNonce: %w", err)
	}
	attrs := []struct {
		oid asn1.ObjectIdentifier
		val any
	}{
		{oidMessageType, printable(strconv.Itoa(int(MessageTypeCertRep)))},
		{oidPKIStatus, printable(strconv.Itoa(int(rep.Status)))},
		{oidTransactionID, printable(req.TransactionID)},
		{oidSenderNonce, senderNonce},
		{oidRecipientNonce, req.SenderNonce},
	}
	if rep.Status == StatusFailure {
		attrs = append(attrs, struct {
			oid asn1.ObjectIdentifier
			val any
		}{oidFailInfo, printable(strconv.Itoa(int(rep.FailInfo)))})
	}
	signer := cms.Signer{Certificate: ra.Cert, Key: ra.Key, Hash: req.Hash}
	for _, a := range attrs {
		attr, err := cms.NewAttribute(a.oid, a.val)
		if err != nil {
			return nil, err
		}
		signer.Attributes = append(signer.Attributes, attr)
	}

	var content []byte
	detached := true
	if rep.Status == StatusSuccess {
		var crls [][]byte
		if rep.CRL != nil {
			crls = [][]byte{rep.CRL}
		}
		inner, err := cms.Degenerate(rep.Certs, crls)
		if err != nil {
			return nil, fmt.Errorf("scep: degenerate reply: %w", err)
		}
		content, err = cms.Encrypt(inner, []*x509.Certificate{req.Signer}, contentEncryptionFor(req.Envelope), cms.EncryptOptions{})
		if err != nil {
			return nil, fmt.Errorf("scep: encrypt the reply: %w", err)
		}
		detached = false
	}
	return cms.Sign(cms.OIDData, content, []cms.Signer{signer}, cms.SignOptions{
		Certificates: [][]byte{ra.Cert.Raw},
		Detached:     detached,
	})
}

// printable encodes s as an ASN.1 PrintableString, the type RFC 8894 gives
// messageType, pkiStatus, failInfo and transactionID. encoding/asn1 would
// otherwise pick the string type itself.
func printable(s string) asn1.RawValue {
	return asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte(s)}
}

// canEncryptTo reports whether a SUCCESS reply can be encrypted to c: key
// transport here is RSA only, which is all SCEP clients use.
func canEncryptTo(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok
}
