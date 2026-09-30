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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// Challenge lifetimes (MintScepChallengeRequest.ttl_seconds).
const (
	DefaultChallengeTTL = time.Hour
	MaxChallengeTTL     = 7 * 24 * time.Hour
)

// challengeBytes is the randomness in a minted challenge: 160 bits, above the
// 128 the contract promises.
const challengeBytes = 20

// maxBoundNames bounds the names one challenge may be bound to.
const maxBoundNames = 100

// challengeEncoding writes challenges as upper-case base32 with no padding:
// letters and digits only, so the challenge can be typed at a device prompt.
var challengeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("scep: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// MintScepChallenge creates a single-use challenge. The challenge is returned
// here and never again; only its SHA-256 is stored, and it is never logged.
func (s *Server) MintScepChallenge(ctx context.Context, req *cryptosv1.MintScepChallengeRequest, actorCN string) (*cryptosv1.MintScepChallengeResponse, error) {
	profName := req.GetProfile()
	if profName == "" {
		if len(s.opts.Profiles) != 1 {
			return nil, status.Errorf(codes.InvalidArgument, "MintScepChallenge: profile is required when %d SCEP profiles are configured", len(s.opts.Profiles))
		}
		profName = s.opts.Profiles[0].Name
	}
	prof := s.profile(profName)
	if prof == nil {
		return nil, status.Errorf(codes.InvalidArgument, "MintScepChallenge: %q is not a configured SCEP profile", profName)
	}

	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if ttl == 0 {
		ttl = DefaultChallengeTTL
	}
	if ttl > MaxChallengeTTL {
		return nil, status.Errorf(codes.InvalidArgument, "MintScepChallenge: ttl_seconds %d is more than the %d-second maximum", req.GetTtlSeconds(), int(MaxChallengeTTL/time.Second))
	}

	if len(req.GetBoundNames()) > maxBoundNames {
		return nil, status.Errorf(codes.InvalidArgument, "MintScepChallenge: %d bound names is more than the %d allowed", len(req.GetBoundNames()), maxBoundNames)
	}
	var bound []string
	for i, n := range req.GetBoundNames() {
		name := normalizeName(n)
		if err := validateDNSName(name); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "MintScepChallenge: bound_names[%d]: %v", i, err)
		}
		if !suffixAllowed(name, s.opts.AllowedSuffixes) {
			return nil, status.Errorf(codes.InvalidArgument, "MintScepChallenge: bound_names[%d]: %s is outside the allowed identifier suffixes", i, name)
		}
		bound = append(bound, name)
	}

	raw := make([]byte, challengeBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, status.Errorf(codes.Internal, "MintScepChallenge: random: %v", err)
	}
	password := challengeEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(password))
	id, err := newID()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	now := s.opts.Now().UTC()
	ch := Challenge{
		ID:          id,
		DigestHex:   hex.EncodeToString(sum[:]),
		Profile:     prof.Name,
		BoundNames:  bound,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		CreatedByCN: actorCN,
	}
	if err := s.store.PutChallenge(ctx, ch, ttl); err != nil {
		return nil, status.Errorf(codes.Internal, "MintScepChallenge: %v", err)
	}
	s.opts.Logf("scep: challenge %s minted by %q for profile %q, expires %s, bound to %v",
		id, actorCN, prof.Name, ch.ExpiresAt.Format(time.RFC3339), bound)
	return &cryptosv1.MintScepChallengeResponse{ChallengePassword: password, Challenge: challengeProto(ch)}, nil
}

// ListScepChallenges returns the usable challenges, soonest to expire first.
func (s *Server) ListScepChallenges(ctx context.Context, _ *cryptosv1.ListScepChallengesRequest) (*cryptosv1.ListScepChallengesResponse, error) {
	all, err := s.store.ListChallenges(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ListScepChallenges: %v", err)
	}
	now := s.opts.Now()
	resp := &cryptosv1.ListScepChallengesResponse{}
	for _, c := range all {
		if now.Before(c.ExpiresAt) {
			resp.Challenges = append(resp.Challenges, challengeProto(c))
		}
	}
	s.opts.Logf("scep: listed %d usable challenge(s)", len(resp.Challenges))
	return resp, nil
}

// RevokeScepChallenge withdraws a usable challenge.
func (s *Server) RevokeScepChallenge(ctx context.Context, req *cryptosv1.RevokeScepChallengeRequest) (*cryptosv1.RevokeScepChallengeResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "RevokeScepChallenge: id is required")
	}
	c, found, err := s.store.DeleteChallenge(ctx, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "RevokeScepChallenge: %v", err)
	}
	if !found || !s.opts.Now().Before(c.ExpiresAt) {
		return nil, status.Errorf(codes.NotFound, "RevokeScepChallenge: no usable challenge %q (unknown, used, revoked or expired)", req.GetId())
	}
	s.opts.Logf("scep: challenge %s revoked before use (profile %q)", c.ID, c.Profile)
	return &cryptosv1.RevokeScepChallengeResponse{Challenge: challengeProto(c)}, nil
}

// ListScepEnrollments returns the waiting enrolments, oldest first.
func (s *Server) ListScepEnrollments(ctx context.Context, req *cryptosv1.ListScepEnrollmentsRequest) (*cryptosv1.ListScepEnrollmentsResponse, error) {
	all, err := s.store.ListEnrollments(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ListScepEnrollments: %v", err)
	}
	resp := &cryptosv1.ListScepEnrollmentsResponse{}
	for _, e := range all {
		if req.GetProfile() != "" && e.Profile != req.GetProfile() {
			continue
		}
		resp.Enrollments = append(resp.Enrollments, enrollmentProto(e))
	}
	s.opts.Logf("scep: listed %d waiting enrolment(s)", len(resp.Enrollments))
	return resp, nil
}

// ApproveScepEnrollment issues a waiting enrolment. The request is checked
// again against the policy in force now; one that no longer passes stays
// queued for rejection.
func (s *Server) ApproveScepEnrollment(ctx context.Context, req *cryptosv1.ApproveScepEnrollmentRequest) (*cryptosv1.ApproveScepEnrollmentResponse, error) {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	e, tx, err := s.waiting(ctx, req.GetId(), "ApproveScepEnrollment")
	if err != nil {
		return nil, err
	}
	prof := s.profile(e.Profile)
	if prof == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "ApproveScepEnrollment: profile %q is no longer served by SCEP; reject the enrolment", e.Profile)
	}
	csr, err := x509.ParseCertificateRequest(e.CSRDER)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "ApproveScepEnrollment: the stored request does not parse: %v; reject the enrolment", err)
	}
	names, err := s.checkInitialRequest(csr, prof, nil)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "ApproveScepEnrollment: the request no longer passes: %v; reject the enrolment", err)
	}
	s.opts.Logf("scep: approving enrolment %s (transaction %q, profile %q, names %v)", e.ID, e.TransactionID, prof.Name, names)
	der, err := s.deps.Issue(ctx, e.CSRDER, prof.Name, names, prof.MinRSABits)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "ApproveScepEnrollment: the certificate authority refused the request: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ApproveScepEnrollment: parse the issued certificate: %v", err)
	}
	tx.State = txIssued
	tx.SerialHex = cert.SerialNumber.Text(16)
	tx.UpdatedAt = s.opts.Now().UTC()
	if err := s.store.FinishEnrollment(ctx, e.ID, tx); err != nil {
		return nil, status.Errorf(codes.Internal, "ApproveScepEnrollment: record the outcome: %v", err)
	}
	s.opts.Logf("scep: enrolment %s approved, issued %s; the device collects it with its next CertPoll", e.ID, tx.SerialHex)
	return &cryptosv1.ApproveScepEnrollmentResponse{Enrollment: enrollmentProto(e), SerialHex: tx.SerialHex}, nil
}

// RejectScepEnrollment refuses a waiting enrolment; the device's next
// CertPoll is answered FAILURE.
func (s *Server) RejectScepEnrollment(ctx context.Context, req *cryptosv1.RejectScepEnrollmentRequest) (*cryptosv1.RejectScepEnrollmentResponse, error) {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	e, tx, err := s.waiting(ctx, req.GetId(), "RejectScepEnrollment")
	if err != nil {
		return nil, err
	}
	tx.State = txRejected
	tx.UpdatedAt = s.opts.Now().UTC()
	if err := s.store.FinishEnrollment(ctx, e.ID, tx); err != nil {
		return nil, status.Errorf(codes.Internal, "RejectScepEnrollment: record the outcome: %v", err)
	}
	s.opts.Logf("scep: enrolment %s rejected (transaction %q, profile %q): %s", e.ID, e.TransactionID, e.Profile, req.GetReason())
	return &cryptosv1.RejectScepEnrollmentResponse{Enrollment: enrollmentProto(e)}, nil
}

// waiting loads a queued enrolment and its transaction.
func (s *Server) waiting(ctx context.Context, id, rpc string) (Enrollment, Transaction, error) {
	if id == "" {
		return Enrollment{}, Transaction{}, status.Errorf(codes.InvalidArgument, "%s: id is required", rpc)
	}
	e, found, err := s.store.GetEnrollment(ctx, id)
	if err != nil {
		return Enrollment{}, Transaction{}, status.Errorf(codes.Internal, "%s: %v", rpc, err)
	}
	if !found {
		return Enrollment{}, Transaction{}, status.Errorf(codes.NotFound, "%s: no waiting enrolment %q", rpc, id)
	}
	tx, found, err := s.store.GetTransaction(ctx, e.TransactionID)
	if err != nil {
		return Enrollment{}, Transaction{}, status.Errorf(codes.Internal, "%s: %v", rpc, err)
	}
	if !found {
		// The enrolment outlived its transaction record; rebuild the record
		// so the device's poll still finds the decision.
		tx = Transaction{TransactionID: e.TransactionID, Profile: e.Profile, EnrollmentID: e.ID, MessageType: MessageTypePKCSReq, CreatedAt: e.ReceivedAt}
		if csr, perr := x509.ParseCertificateRequest(e.CSRDER); perr == nil {
			tx.KeyID = keyID(csr.RawSubjectPublicKeyInfo)
		}
	}
	return e, tx, nil
}

func challengeProto(c Challenge) *cryptosv1.ScepChallenge {
	return &cryptosv1.ScepChallenge{
		Id:          c.ID,
		Profile:     c.Profile,
		BoundNames:  c.BoundNames,
		CreatedAt:   timestamppb.New(c.CreatedAt),
		ExpiresAt:   timestamppb.New(c.ExpiresAt),
		CreatedByCn: c.CreatedByCN,
	}
}

func enrollmentProto(e Enrollment) *cryptosv1.ScepEnrollment {
	var dnsNames []string
	if csr, err := x509.ParseCertificateRequest(e.CSRDER); err == nil {
		dnsNames = csr.DNSNames
	}
	return &cryptosv1.ScepEnrollment{
		Id:            e.ID,
		TransactionId: e.TransactionID,
		Profile:       e.Profile,
		SubjectDn:     e.SubjectDN,
		DnsNames:      dnsNames,
		KeyAlg:        e.KeyAlg,
		CsrPem:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: e.CSRDER})),
		ChallengeId:   e.ChallengeID,
		ReceivedAt:    timestamppb.New(e.ReceivedAt),
	}
}
