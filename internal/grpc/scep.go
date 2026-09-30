package grpc

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
	"context"
	"crypto/x509"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// LocalSocketActor is the created_by_cn recorded for a challenge minted over
// the local UNIX socket, which carries no client certificate.
const LocalSocketActor = "local-socket"

// ScepAdmin backs the SCEP administration RPCs: the one-time enrolment
// challenges and the approval queue. It is wired only when the SCEP listener
// started this boot; otherwise it is nil and every SCEP RPC answers
// FailedPrecondition, which covers maintenance mode, a Root and a node with
// SCEP switched off. Implementations return gRPC status errors.
// Implemented by internal/scep.
type ScepAdmin interface {
	MintScepChallenge(ctx context.Context, req *cryptosv1.MintScepChallengeRequest, actorCN string) (*cryptosv1.MintScepChallengeResponse, error)
	ListScepChallenges(ctx context.Context, req *cryptosv1.ListScepChallengesRequest) (*cryptosv1.ListScepChallengesResponse, error)
	RevokeScepChallenge(ctx context.Context, req *cryptosv1.RevokeScepChallengeRequest) (*cryptosv1.RevokeScepChallengeResponse, error)
	ListScepEnrollments(ctx context.Context, req *cryptosv1.ListScepEnrollmentsRequest) (*cryptosv1.ListScepEnrollmentsResponse, error)
	ApproveScepEnrollment(ctx context.Context, req *cryptosv1.ApproveScepEnrollmentRequest) (*cryptosv1.ApproveScepEnrollmentResponse, error)
	RejectScepEnrollment(ctx context.Context, req *cryptosv1.RejectScepEnrollmentRequest) (*cryptosv1.RejectScepEnrollmentResponse, error)
}

var errScepNotRunning = status.Error(codes.FailedPrecondition,
	"SCEP is not running on this node this boot: it is off in the machine config, the node is a Root, or the node is in maintenance mode")

// scepGate refuses a SCEP RPC before any state is read: first when SCEP is
// not running, then when the caller is not the bootstrap admin.
func (s *Server) scepGate(ctx context.Context) error {
	if s.cfg.ScepAdmin == nil {
		return errScepNotRunning
	}
	return AuthorizeAdmin(ctx, s.cfg.Trust)
}

// MintScepChallenge handles cryptos.v1.NodeService/MintScepChallenge. The
// challenge password goes back to the caller and nowhere else: the audit entry
// records its id, profile and bound names only.
func (s *Server) MintScepChallenge(ctx context.Context, req *cryptosv1.MintScepChallengeRequest) (*cryptosv1.MintScepChallengeResponse, error) {
	if err := s.scepGate(ctx); err != nil {
		return nil, err
	}
	resp, err := s.cfg.ScepAdmin.MintScepChallenge(ctx, req, callerCN(ctx))
	if err != nil {
		return nil, err
	}
	ch := resp.GetChallenge()
	setAuditDetail(ctx, "challenge_id", ch.GetId())
	setAuditDetail(ctx, "profile", ch.GetProfile())
	if len(ch.GetBoundNames()) > 0 {
		setAuditDetail(ctx, "bound_names", strings.Join(ch.GetBoundNames(), ","))
	}
	if ch.GetExpiresAt() != nil {
		setAuditDetail(ctx, "expires_at", ch.GetExpiresAt().AsTime().UTC().Format("2006-01-02T15:04:05Z"))
	}
	return resp, nil
}

// ListScepChallenges handles cryptos.v1.NodeService/ListScepChallenges.
func (s *Server) ListScepChallenges(ctx context.Context, req *cryptosv1.ListScepChallengesRequest) (*cryptosv1.ListScepChallengesResponse, error) {
	if err := s.scepGate(ctx); err != nil {
		return nil, err
	}
	return s.cfg.ScepAdmin.ListScepChallenges(ctx, req)
}

// RevokeScepChallenge handles cryptos.v1.NodeService/RevokeScepChallenge.
func (s *Server) RevokeScepChallenge(ctx context.Context, req *cryptosv1.RevokeScepChallengeRequest) (*cryptosv1.RevokeScepChallengeResponse, error) {
	if err := s.scepGate(ctx); err != nil {
		return nil, err
	}
	setAuditDetail(ctx, "challenge_id", req.GetId())
	return s.cfg.ScepAdmin.RevokeScepChallenge(ctx, req)
}

// ListScepEnrollments handles cryptos.v1.NodeService/ListScepEnrollments.
func (s *Server) ListScepEnrollments(ctx context.Context, req *cryptosv1.ListScepEnrollmentsRequest) (*cryptosv1.ListScepEnrollmentsResponse, error) {
	if err := s.scepGate(ctx); err != nil {
		return nil, err
	}
	return s.cfg.ScepAdmin.ListScepEnrollments(ctx, req)
}

// ApproveScepEnrollment handles cryptos.v1.NodeService/ApproveScepEnrollment.
func (s *Server) ApproveScepEnrollment(ctx context.Context, req *cryptosv1.ApproveScepEnrollmentRequest) (*cryptosv1.ApproveScepEnrollmentResponse, error) {
	if err := s.scepGate(ctx); err != nil {
		return nil, err
	}
	setAuditDetail(ctx, "enrollment_id", req.GetId())
	resp, err := s.cfg.ScepAdmin.ApproveScepEnrollment(ctx, req)
	if err != nil {
		return nil, err
	}
	setAuditDetail(ctx, "profile", resp.GetEnrollment().GetProfile())
	setAuditDetail(ctx, "serial_hex", resp.GetSerialHex())
	return resp, nil
}

// RejectScepEnrollment handles cryptos.v1.NodeService/RejectScepEnrollment.
// The reason goes to the audit log only; the client learns just a failInfo.
func (s *Server) RejectScepEnrollment(ctx context.Context, req *cryptosv1.RejectScepEnrollmentRequest) (*cryptosv1.RejectScepEnrollmentResponse, error) {
	if err := s.scepGate(ctx); err != nil {
		return nil, err
	}
	setAuditDetail(ctx, "enrollment_id", req.GetId())
	if req.GetReason() != "" {
		setAuditDetail(ctx, "reason", req.GetReason())
	}
	resp, err := s.cfg.ScepAdmin.RejectScepEnrollment(ctx, req)
	if err != nil {
		return nil, err
	}
	setAuditDetail(ctx, "profile", resp.GetEnrollment().GetProfile())
	return resp, nil
}

// callerCN is the common name of the caller's client certificate, or
// LocalSocketActor on the local socket.
func callerCN(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return LocalSocketActor
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return LocalSocketActor
	}
	var leaf *x509.Certificate
	if vc := tlsInfo.State.VerifiedChains; len(vc) > 0 && len(vc[0]) > 0 {
		leaf = vc[0][0]
	} else if pc := tlsInfo.State.PeerCertificates; len(pc) > 0 {
		leaf = pc[0]
	}
	if leaf == nil {
		return ""
	}
	return leaf.Subject.CommonName
}
