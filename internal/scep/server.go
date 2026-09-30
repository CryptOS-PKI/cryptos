package scep

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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/cms"
)

// Profile is one certificate profile SCEP issues from.
type Profile struct {
	// Name is the certificate profile in pki.profiles.
	Name string
	// MinRSABits is the RSA subject-key floor; zero means the node-wide
	// ca.MinRSASubjectKeyBits.
	MinRSABits int
	// RequireApproval holds initial enrolments for an admin decision.
	RequireApproval bool
}

// IssueFunc issues a leaf for csrDER under profile with exactly the SAN set
// names and the given RSA floor, and returns its DER. In production it is
// node.CASigner.IssueLeafForNamesMinRSA, so the profile decides every other
// extension and the certificate is recorded for revocation before it returns.
type IssueFunc func(ctx context.Context, csrDER []byte, profile string, names []string, minRSABits int) ([]byte, error)

// CAChainFunc returns the node's CA certificate first, then its issuers.
type CAChainFunc func(ctx context.Context) ([]*x509.Certificate, error)

// RevokedFunc reports whether the certificate with the lowercase hex serial
// is revoked.
type RevokedFunc func(ctx context.Context, serialHex string) (bool, error)

// IssuedFunc looks up a certificate this node issued by lowercase hex serial
// and returns its DER and the profile it was issued under.
type IssuedFunc func(ctx context.Context, serialHex string) (der []byte, profile string, ok bool, err error)

// CRLFunc returns the node's current DER CRL.
type CRLFunc func(ctx context.Context) ([]byte, error)

// Auditor records SCEP issuance decisions in the node's audit log.
type Auditor interface {
	Append(event *cryptosv1.AuditEvent) error
}

// Options configures a Server.
type Options struct {
	Profiles []Profile
	// AllowedSuffixes bounds the names an initial enrolment may request.
	AllowedSuffixes []string
	Now             func() time.Time
	Logf            func(format string, args ...any)
}

// Deps are the node facilities a Server uses. Issue, CAChain, Issued and
// CRL are required; Revoked and Auditor may be nil in tests.
type Deps struct {
	Issue   IssueFunc
	CAChain CAChainFunc
	Revoked RevokedFunc
	Issued  IssuedFunc
	CRL     CRLFunc
	Auditor Auditor
}

// Server is the SCEP responder: the HTTP operations and the admin RPCs. It
// holds no CA key; the RA key it holds only decrypts requests and signs
// replies.
type Server struct {
	store *Store
	ras   *RAManager
	deps  Deps
	opts  Options

	// queueMu serializes the approval-queue decisions. The node is the only
	// writer of its etcd, so one lock is enough to stop an approve and a
	// reject (or two approves) racing on one enrolment.
	queueMu sync.Mutex
}

// NewServer validates its inputs and returns a Server.
func NewServer(store *Store, ras *RAManager, deps Deps, opts Options) (*Server, error) {
	if store == nil || ras == nil {
		return nil, errors.New("scep: NewServer: store and RA manager are required")
	}
	if deps.Issue == nil || deps.CAChain == nil || deps.Issued == nil || deps.CRL == nil {
		return nil, errors.New("scep: NewServer: Issue, CAChain, Issued and CRL are required")
	}
	if len(opts.Profiles) == 0 {
		return nil, errors.New("scep: NewServer: at least one profile is required")
	}
	if len(opts.AllowedSuffixes) == 0 {
		return nil, errors.New("scep: NewServer: the identifier allowlist is required; a challenge proves nothing about control of a name")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &Server{store: store, ras: ras, deps: deps, opts: opts}, nil
}

func (s *Server) profile(name string) *Profile {
	for i := range s.opts.Profiles {
		if s.opts.Profiles[i].Name == name {
			return &s.opts.Profiles[i]
		}
	}
	return nil
}

// outcome carries what one PKIOperation decided, for the log and the audit.
type outcome struct {
	// authorizedBy is "challenge" for an initial enrolment and "certificate"
	// for a renewal.
	authorizedBy string
	profile      string
	challengeID  string
	serialHex    string
	names        []string
}

// pkiOperation answers one PKIOperation message with the DER CertRep. An
// error wrapping errMalformed means the message could not be answered with a
// CertRep at all.
func (s *Server) pkiOperation(ctx context.Context, der []byte, remote string) ([]byte, error) {
	start := s.opts.Now()
	req, err := parseRequest(der)
	if err != nil {
		s.opts.Logf("scep: PKIOperation from %s: unanswerable message: %v", remote, err)
		return nil, err
	}
	s.opts.Logf("scep: PKIOperation from %s: %s transaction=%q signer=%q hash=%s",
		remote, req.Type, req.TransactionID, req.Signer.Subject.String(), req.Hash)

	ra, ok := s.ras.Current()
	if !ok {
		return nil, errors.New("scep: no RA certificate is available")
	}
	var out outcome
	rep := s.dispatch(ctx, req, &ra, &out)

	resp, err := buildCertRep(req, &ra, rep)
	if err != nil {
		return nil, err
	}
	s.opts.Logf("scep: PKIOperation from %s: %s transaction=%q -> %s%s profile=%q serial=%q in %s%s",
		remote, req.Type, req.TransactionID, rep.Status, failSuffix(rep), out.profile, out.serialHex,
		s.opts.Now().Sub(start).Round(time.Millisecond), reasonSuffix(rep))
	s.audit(req, rep, out, remote)
	return resp, nil
}

func failSuffix(rep reply) string {
	if rep.Status != StatusFailure {
		return ""
	}
	return " " + rep.FailInfo.String()
}

func reasonSuffix(rep reply) string {
	if rep.Reason == "" {
		return ""
	}
	return " (" + rep.Reason + ")"
}

// dispatch decides the reply. It sets *ra to the RA that decrypted the
// request, which is the one that signs the reply: the device may have cached
// the older RA during a rotation overlap and verifies with that.
func (s *Server) dispatch(ctx context.Context, req *request, ra *raCert, out *outcome) reply {
	if req.VerifyErr != nil {
		return failure(FailBadMessageCheck, "the message does not verify: %v", req.VerifyErr)
	}
	switch req.Type {
	case MessageTypePKCSReq, MessageTypeRenewalReq, MessageTypeCertPoll, MessageTypeGetCert, MessageTypeGetCRL:
	default:
		return failure(FailBadRequest, "messageType %s is not a request this server answers", req.Type)
	}
	if !canEncryptTo(req.Signer) {
		return failure(FailBadAlg, "the signer key is %s; the reply is encrypted to it, which needs RSA", keyDescription(req.Signer.PublicKey))
	}
	content, used, rep, ok := s.decrypt(req)
	if !ok {
		return rep
	}
	*ra = used

	switch req.Type {
	case MessageTypePKCSReq:
		return s.pkcsReq(ctx, req, content, out)
	case MessageTypeRenewalReq:
		return s.renewalReq(ctx, req, content, out)
	case MessageTypeCertPoll:
		return s.certPoll(ctx, req, out)
	case MessageTypeGetCert:
		return s.getCert(ctx, req, content, out)
	default:
		return s.getCRL(ctx, req, content)
	}
}

// decrypt opens the pkcsPKIEnvelope with each usable RA, newest first. Only
// ErrNoRecipient moves on to the next RA; any other failure is final, and all
// of them look the same to the client.
func (s *Server) decrypt(req *request) ([]byte, raCert, reply, bool) {
	for _, ra := range s.ras.All() {
		plain, err := req.Envelope.Decrypt(ra.Cert, ra.Key)
		switch {
		case err == nil:
			return plain, ra, reply{}, true
		case errors.Is(err, cms.ErrNoRecipient):
			continue
		case errors.Is(err, cms.ErrUnsupportedAlgorithm):
			return nil, raCert{}, failure(FailBadAlg, "the envelope uses an algorithm this server refuses: %v", err), false
		default:
			return nil, raCert{}, failure(FailBadMessageCheck, "the envelope does not decrypt"), false
		}
	}
	return nil, raCert{}, failure(FailBadMessageCheck, "the envelope is not encrypted to a current RA certificate; fetch GetCACert again"), false
}

// pkcsReq handles an initial enrolment, authorized by a one-time challenge.
func (s *Server) pkcsReq(ctx context.Context, req *request, csrDER []byte, out *outcome) reply {
	csr, rep, ok := parseCSR(csrDER)
	if !ok {
		return rep
	}
	pw, err := challengePassword(csr)
	if err != nil {
		return failure(FailBadRequest, "%v", err)
	}
	if !selfSigned(req.Signer) {
		// Before RFC 8894 added RenewalReq, a renewal was a PKCSReq signed
		// with the current certificate, and clients still send it that way
		// (sscep, and Cisco IOS auto-enrol rollover, which may repeat the
		// original challenge). Signed by a current certificate from this CA,
		// it gets exactly the RenewalReq rules, whatever challenge it
		// carries. Signed by anything else, only a challenge can authorize
		// it.
		if _, issuedByUs := s.verifyIssuedByUs(ctx, req.Signer); issuedByUs || pw == "" {
			s.opts.Logf("scep: PKCSReq %q is signed by %q; handling it as a renewal", req.TransactionID, req.Signer.Subject.String())
			return s.renew(ctx, req, csr, csrDER, out)
		}
	}
	return s.withTransaction(ctx, req, csr, func(tx *Transaction) reply {
		if pw == "" {
			return failure(FailBadRequest, "the request carries no challengePassword; mint a one-time challenge for the device")
		}
		out.authorizedBy = "challenge"
		sum := sha256.Sum256([]byte(pw))
		ch, found, err := s.store.ConsumeChallenge(ctx, hex.EncodeToString(sum[:]))
		if err != nil {
			s.opts.Logf("scep: consuming a challenge failed: %v", err)
			return failure(FailBadRequest, "the challenge could not be checked")
		}
		if !found {
			return failure(FailBadRequest, "the challenge is unknown, already used, revoked or expired")
		}
		out.challengeID = ch.ID
		s.opts.Logf("scep: challenge %s consumed by transaction %q (profile %q)", ch.ID, req.TransactionID, ch.Profile)
		if !s.opts.Now().Before(ch.ExpiresAt) {
			return failure(FailBadRequest, "challenge %s expired at %s", ch.ID, ch.ExpiresAt.UTC().Format(time.RFC3339))
		}

		prof := s.profile(ch.Profile)
		if prof == nil {
			return failure(FailBadRequest, "challenge %s names profile %q, which SCEP no longer serves", ch.ID, ch.Profile)
		}
		out.profile = prof.Name
		names, err := s.checkInitialRequest(csr, prof, ch.BoundNames)
		if err != nil {
			return failure(FailBadRequest, "%v", err)
		}
		out.names = names
		tx.Profile = prof.Name

		if prof.RequireApproval {
			return s.queue(ctx, req, csr, csrDER, prof, names, ch, tx)
		}
		return s.issueFor(ctx, csrDER, prof, names, tx, out)
	})
}

// checkInitialRequest applies the initial-enrolment policy: DNS names only,
// every name inside the allowlist and the challenge's bound names, and the
// profile's key floor.
func (s *Server) checkInitialRequest(csr *x509.CertificateRequest, prof *Profile, bound []string) ([]string, error) {
	names, err := requestNames(csr)
	if err != nil {
		return nil, err
	}
	if err := checkAllowlist(names, s.opts.AllowedSuffixes); err != nil {
		return nil, err
	}
	if err := checkBound(names, bound); err != nil {
		return nil, err
	}
	if err := ca.ValidateSubjectKeyMin(csr.PublicKey, prof.MinRSABits); err != nil {
		return nil, fmt.Errorf("profile %q: %v", prof.Name, err)
	}
	return names, nil
}

func (s *Server) queue(ctx context.Context, req *request, csr *x509.CertificateRequest, csrDER []byte, prof *Profile, names []string, ch Challenge, tx *Transaction) reply {
	id, err := newID()
	if err != nil {
		return failure(FailBadRequest, "%v", err)
	}
	e := Enrollment{
		ID:            id,
		TransactionID: req.TransactionID,
		Profile:       prof.Name,
		SubjectDN:     csr.Subject.String(),
		Names:         names,
		KeyAlg:        keyDescription(csr.PublicKey),
		CSRDER:        csrDER,
		ChallengeID:   ch.ID,
		ReceivedAt:    s.opts.Now().UTC(),
	}
	if err := s.store.PutEnrollment(ctx, e); err != nil {
		s.opts.Logf("scep: queueing transaction %q failed: %v", req.TransactionID, err)
		return failure(FailBadRequest, "the enrolment could not be queued")
	}
	tx.State = txPending
	tx.EnrollmentID = id
	s.opts.Logf("scep: transaction %q queued as enrolment %s for approval (profile %q, names %v)", req.TransactionID, id, prof.Name, names)
	return reply{Status: StatusPending, Reason: "held for approval as enrolment " + id}
}

func (s *Server) issueFor(ctx context.Context, csrDER []byte, prof *Profile, names []string, tx *Transaction, out *outcome) reply {
	s.opts.Logf("scep: issuing under profile %q for %v (RSA floor %d)", prof.Name, names, floorOf(prof))
	der, err := s.deps.Issue(ctx, csrDER, prof.Name, names, prof.MinRSABits)
	if err != nil {
		return failure(FailBadRequest, "the certificate authority refused the request: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return failure(FailBadRequest, "the issued certificate does not parse: %v", err)
	}
	out.serialHex = cert.SerialNumber.Text(16)
	tx.State = txIssued
	tx.SerialHex = out.serialHex
	return reply{Status: StatusSuccess, Certs: [][]byte{der}}
}

func floorOf(p *Profile) int {
	if p.MinRSABits == 0 {
		return ca.MinRSASubjectKeyBits
	}
	return p.MinRSABits
}

// renewalReq handles a renewal, authorized by the certificate the device
// holds. It keeps that certificate's names and profile and is never queued.
func (s *Server) renewalReq(ctx context.Context, req *request, csrDER []byte, out *outcome) reply {
	csr, rep, ok := parseCSR(csrDER)
	if !ok {
		return rep
	}
	return s.renew(ctx, req, csr, csrDER, out)
}

// renew is the renewal path shared by RenewalReq and a PKCSReq signed with
// the current certificate.
func (s *Server) renew(ctx context.Context, req *request, csr *x509.CertificateRequest, csrDER []byte, out *outcome) reply {
	out.authorizedBy = "certificate"
	if rep, ok := s.verifyIssuedByUs(ctx, req.Signer); !ok {
		return rep
	}
	return s.withTransaction(ctx, req, csr, func(tx *Transaction) reply {
		serial := req.Signer.SerialNumber.Text(16)
		_, profName, found, err := s.deps.Issued(ctx, serial)
		if err != nil {
			s.opts.Logf("scep: looking up %s for renewal failed: %v", serial, err)
			return failure(FailBadRequest, "the current certificate could not be looked up")
		}
		if !found {
			return failure(FailBadCertID, "certificate %s is not in this node's issued set", serial)
		}
		prof := s.profile(profName)
		if prof == nil {
			return failure(FailBadRequest, "certificate %s was issued under profile %q, which SCEP does not serve", serial, profName)
		}
		out.profile = prof.Name
		tx.Profile = prof.Name

		names, err := requestNames(csr)
		if err != nil {
			return failure(FailBadRequest, "%v", err)
		}
		current := certNames(req.Signer)
		if !sameNameSet(names, current) {
			return failure(FailBadRequest, "a renewal must request the names of the certificate it renews (%v), not %v", current, names)
		}
		out.names = current
		if err := ca.ValidateSubjectKeyMin(csr.PublicKey, prof.MinRSABits); err != nil {
			return failure(FailBadRequest, "profile %q: %v", prof.Name, err)
		}
		s.opts.Logf("scep: renewing %s (%v) under profile %q", serial, current, prof.Name)
		return s.issueFor(ctx, csrDER, prof, current, tx, out)
	})
}

// withTransaction runs decide for a new transactionID, recording what it
// decided, and answers a transactionID it has already seen from the record:
// the same certificate for an issued one, PENDING for one queued or still in
// flight, FAILURE for a rejected one. A decision that fails is forgotten, so
// the device can try again with a fresh challenge.
func (s *Server) withTransaction(ctx context.Context, req *request, csr *x509.CertificateRequest, decide func(*Transaction) reply) reply {
	now := s.opts.Now().UTC()
	tx := Transaction{
		TransactionID: req.TransactionID,
		State:         txProcessing,
		KeyID:         keyID(csr.RawSubjectPublicKeyInfo),
		SignerKeyID:   keyID(req.Signer.RawSubjectPublicKeyInfo),
		MessageType:   req.Type,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	existing, claimed, err := s.store.ClaimTransaction(ctx, tx)
	if err != nil {
		s.opts.Logf("scep: recording transaction %q failed: %v", req.TransactionID, err)
		return failure(FailBadRequest, "the transaction could not be recorded")
	}
	if !claimed {
		s.opts.Logf("scep: transaction %q seen before (state %s); answering from the record", req.TransactionID, existing.State)
		if existing.KeyID != tx.KeyID {
			return failure(FailBadRequest, "transactionID %q is already in use for a different key", req.TransactionID)
		}
		return s.fromRecord(ctx, existing)
	}

	rep := s.safeDecide(decide, &tx)
	if rep.Status == StatusFailure {
		if err := s.store.DeleteTransaction(ctx, req.TransactionID); err != nil {
			s.opts.Logf("scep: forgetting failed transaction %q failed: %v", req.TransactionID, err)
		}
		return rep
	}
	tx.UpdatedAt = s.opts.Now().UTC()
	if err := s.store.PutTransaction(ctx, tx); err != nil {
		// The certificate is already issued and recorded for revocation, so
		// the device still gets it; only a later retransmit or poll would
		// miss the record.
		s.opts.Logf("scep: recording the outcome of transaction %q failed: %v", req.TransactionID, err)
	}
	return rep
}

// safeDecide runs decide and turns a panic into a failure, so a bug cannot
// leave a transaction stuck in the processing state.
func (s *Server) safeDecide(decide func(*Transaction) reply, tx *Transaction) (rep reply) {
	defer func() {
		if r := recover(); r != nil {
			s.opts.Logf("scep: transaction %q: internal error: %v", tx.TransactionID, r)
			rep = failure(FailBadRequest, "internal error")
		}
	}()
	return decide(tx)
}

// fromRecord answers from a stored transaction.
func (s *Server) fromRecord(ctx context.Context, tx Transaction) reply {
	switch tx.State {
	case txIssued:
		der, _, found, err := s.deps.Issued(ctx, tx.SerialHex)
		if err != nil || !found {
			s.opts.Logf("scep: transaction %q: the issued certificate %s could not be loaded: found=%t err=%v", tx.TransactionID, tx.SerialHex, found, err)
			return failure(FailBadCertID, "the issued certificate could not be loaded")
		}
		return reply{Status: StatusSuccess, Certs: [][]byte{der}, Reason: "the certificate issued for this transaction"}
	case txPending, txProcessing:
		return reply{Status: StatusPending, Reason: "still waiting (" + tx.State + ")"}
	case txRejected:
		return failure(FailBadRequest, "an administrator rejected this enrolment")
	}
	return failure(FailBadRequest, "transaction in unknown state %q", tx.State)
}

// certPoll answers a CertPoll (formerly GetCertInitial, RFC 8894 section
// 3.3.3) from the transaction record. The poll must be signed by the key that
// signed the original request.
func (s *Server) certPoll(ctx context.Context, req *request, out *outcome) reply {
	tx, found, err := s.store.GetTransaction(ctx, req.TransactionID)
	if err != nil {
		s.opts.Logf("scep: CertPoll: reading transaction %q failed: %v", req.TransactionID, err)
		return failure(FailBadRequest, "the transaction could not be read")
	}
	if !found {
		return failure(FailBadCertID, "no transaction %q", req.TransactionID)
	}
	if tx.SignerKeyID != keyID(req.Signer.RawSubjectPublicKeyInfo) {
		return failure(FailBadRequest, "the poll is not signed by the key that made the request")
	}
	out.profile = tx.Profile
	out.serialHex = tx.SerialHex
	return s.fromRecord(ctx, tx)
}

// issuerAndSerial is the RFC 5652 IssuerAndSerialNumber that GetCert and
// GetCRL carry.
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// getCert returns a certificate this node issued (RFC 8894 section 3.3.4).
// The requester must hold a current certificate from this CA.
func (s *Server) getCert(ctx context.Context, req *request, content []byte, out *outcome) reply {
	if rep, ok := s.verifyIssuedByUs(ctx, req.Signer); !ok {
		return rep
	}
	ias, rep, ok := s.parseIssuerAndSerial(ctx, content)
	if !ok {
		return rep
	}
	serial := ias.SerialNumber.Text(16)
	der, _, found, err := s.deps.Issued(ctx, serial)
	if err != nil {
		s.opts.Logf("scep: GetCert: looking up %s failed: %v", serial, err)
		return failure(FailBadRequest, "the certificate could not be looked up")
	}
	if !found {
		return failure(FailBadCertID, "this node did not issue serial %s", serial)
	}
	out.serialHex = serial
	return reply{Status: StatusSuccess, Certs: [][]byte{der}}
}

// getCRL returns the node's current CRL (RFC 8894 section 3.3.4). The
// requester must hold a current certificate from this CA.
func (s *Server) getCRL(ctx context.Context, req *request, content []byte) reply {
	if rep, ok := s.verifyIssuedByUs(ctx, req.Signer); !ok {
		return rep
	}
	if _, rep, ok := s.parseIssuerAndSerial(ctx, content); !ok {
		return rep
	}
	crl, err := s.deps.CRL(ctx)
	if err != nil {
		s.opts.Logf("scep: GetCRL: building the CRL failed: %v", err)
		return failure(FailBadRequest, "the CRL is unavailable")
	}
	return reply{Status: StatusSuccess, CRL: crl}
}

func (s *Server) parseIssuerAndSerial(ctx context.Context, content []byte) (issuerAndSerial, reply, bool) {
	var ias issuerAndSerial
	if rest, err := asn1.Unmarshal(content, &ias); err != nil || len(rest) != 0 || ias.SerialNumber == nil {
		return ias, failure(FailBadRequest, "the messageData is not an IssuerAndSerialNumber"), false
	}
	chain, err := s.deps.CAChain(ctx)
	if err != nil || len(chain) == 0 {
		s.opts.Logf("scep: loading the CA chain failed: %v", err)
		return ias, failure(FailBadRequest, "the CA chain is unavailable"), false
	}
	if !s.isOurIssuerName(ias.Issuer.FullBytes, chain[0]) {
		return ias, failure(FailBadCertID, "the issuer is not this CA"), false
	}
	return ias, reply{}, true
}

// isOurIssuerName reports whether name is this CA's subject. An RA's subject
// is accepted too: clients that verify replies with the RA certificate (sscep,
// given the RA as its CA certificate) name it as the issuer, and the serial is
// looked up in this node's own issued set either way.
func (s *Server) isOurIssuerName(name []byte, caCert *x509.Certificate) bool {
	if string(name) == string(caCert.RawSubject) {
		return true
	}
	for _, ra := range s.ras.All() {
		if string(name) == string(ra.Cert.RawSubject) {
			return true
		}
	}
	return false
}

// verifyIssuedByUs checks that c chains to this CA, is inside its validity
// period and is not revoked.
func (s *Server) verifyIssuedByUs(ctx context.Context, c *x509.Certificate) (reply, bool) {
	chain, err := s.deps.CAChain(ctx)
	if err != nil || len(chain) == 0 {
		s.opts.Logf("scep: loading the CA chain failed: %v", err)
		return failure(FailBadRequest, "the CA chain is unavailable"), false
	}
	roots := x509.NewCertPool()
	for _, cert := range chain {
		roots.AddCert(cert)
	}
	if _, err := c.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: s.opts.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		var inv x509.CertificateInvalidError
		if errors.As(err, &inv) && inv.Reason == x509.Expired {
			return failure(FailBadTime, "the signer certificate is outside its validity period"), false
		}
		return failure(FailBadRequest, "the signer certificate was not issued by this CA: %v", err), false
	}
	if s.deps.Revoked == nil {
		return reply{}, true
	}
	serial := c.SerialNumber.Text(16)
	revoked, err := s.deps.Revoked(ctx, serial)
	if err != nil {
		s.opts.Logf("scep: revocation lookup for %s failed: %v", serial, err)
		return failure(FailBadRequest, "the revocation status could not be checked"), false
	}
	if revoked {
		return failure(FailBadRequest, "the signer certificate %s is revoked", serial), false
	}
	return reply{}, true
}

// selfSigned reports whether c is signed by its own key, as a device's
// throwaway PKCSReq signer is. CheckSignatureFrom would refuse it for not
// being a CA, so the signature is checked directly.
func selfSigned(c *x509.Certificate) bool {
	return string(c.RawIssuer) == string(c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func parseCSR(der []byte) (*x509.CertificateRequest, reply, bool) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, failure(FailBadRequest, "the messageData is not a PKCS#10 request: %v", err), false
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, failure(FailBadMessageCheck, "the certificate request signature does not verify: %v", err), false
	}
	return csr, reply{}, true
}

// audit records one PKIOperation decision. The challenge never appears: only
// the id of the challenge that was consumed.
func (s *Server) audit(req *request, rep reply, out outcome, remote string) {
	if s.deps.Auditor == nil {
		return
	}
	outcomeCode := cryptosv1.Outcome_OUTCOME_OK
	if rep.Status == StatusFailure {
		outcomeCode = cryptosv1.Outcome_OUTCOME_DENIED
	}
	details := map[string]string{
		"transaction_id": req.TransactionID,
		"pki_status":     rep.Status.String(),
		"remote_addr":    remote,
	}
	if rep.Status == StatusFailure {
		details["fail_info"] = rep.FailInfo.String()
	}
	if rep.Reason != "" {
		details["reason"] = rep.Reason
	}
	if out.profile != "" {
		details["profile"] = out.profile
	}
	if out.authorizedBy != "" {
		details["authorized_by"] = out.authorizedBy
	}
	if out.challengeID != "" {
		details["challenge_id"] = out.challengeID
	}
	if out.serialHex != "" {
		details["serial_hex"] = out.serialHex
	}
	if len(out.names) > 0 {
		details["names"] = strings.Join(out.names, ",")
	}
	if err := s.deps.Auditor.Append(&cryptosv1.AuditEvent{
		ActorSubject: req.Signer.Subject.String(),
		RpcMethod:    "scep/" + req.Type.String(),
		Outcome:      outcomeCode,
		Details:      details,
	}); err != nil {
		s.opts.Logf("scep: writing the audit entry for transaction %q failed: %v", req.TransactionID, err)
	}
}
