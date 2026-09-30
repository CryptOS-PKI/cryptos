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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

type mockScepAdmin struct {
	calls   []string
	actorCN string
	mintReq *cryptosv1.MintScepChallengeRequest
	err     error
}

func (m *mockScepAdmin) MintScepChallenge(_ context.Context, req *cryptosv1.MintScepChallengeRequest, actorCN string) (*cryptosv1.MintScepChallengeResponse, error) {
	m.calls = append(m.calls, "mint")
	m.mintReq, m.actorCN = req, actorCN
	if m.err != nil {
		return nil, m.err
	}
	return &cryptosv1.MintScepChallengeResponse{
		ChallengePassword: "s3cret-challenge-value",
		Challenge:         &cryptosv1.ScepChallenge{Id: "ch1", Profile: req.GetProfile(), BoundNames: req.GetBoundNames(), CreatedByCn: actorCN},
	}, nil
}

func (m *mockScepAdmin) ListScepChallenges(context.Context, *cryptosv1.ListScepChallengesRequest) (*cryptosv1.ListScepChallengesResponse, error) {
	m.calls = append(m.calls, "list-challenges")
	return &cryptosv1.ListScepChallengesResponse{}, m.err
}

func (m *mockScepAdmin) RevokeScepChallenge(_ context.Context, req *cryptosv1.RevokeScepChallengeRequest) (*cryptosv1.RevokeScepChallengeResponse, error) {
	m.calls = append(m.calls, "revoke-challenge")
	if m.err != nil {
		return nil, m.err
	}
	return &cryptosv1.RevokeScepChallengeResponse{Challenge: &cryptosv1.ScepChallenge{Id: req.GetId()}}, nil
}

func (m *mockScepAdmin) ListScepEnrollments(context.Context, *cryptosv1.ListScepEnrollmentsRequest) (*cryptosv1.ListScepEnrollmentsResponse, error) {
	m.calls = append(m.calls, "list-enrollments")
	return &cryptosv1.ListScepEnrollmentsResponse{}, m.err
}

func (m *mockScepAdmin) ApproveScepEnrollment(_ context.Context, req *cryptosv1.ApproveScepEnrollmentRequest) (*cryptosv1.ApproveScepEnrollmentResponse, error) {
	m.calls = append(m.calls, "approve")
	if m.err != nil {
		return nil, m.err
	}
	return &cryptosv1.ApproveScepEnrollmentResponse{Enrollment: &cryptosv1.ScepEnrollment{Id: req.GetId(), Profile: "cisco"}, SerialHex: "abc123"}, nil
}

func (m *mockScepAdmin) RejectScepEnrollment(_ context.Context, req *cryptosv1.RejectScepEnrollmentRequest) (*cryptosv1.RejectScepEnrollmentResponse, error) {
	m.calls = append(m.calls, "reject")
	if m.err != nil {
		return nil, m.err
	}
	return &cryptosv1.RejectScepEnrollmentResponse{Enrollment: &cryptosv1.ScepEnrollment{Id: req.GetId(), Profile: "cisco"}}, nil
}

func serverWithScep(t *testing.T, admin ScepAdmin, adminCert *x509.Certificate) *Server {
	t.Helper()
	cfg := ServerConfig{Auditor: &mockAuditor{}, TLSConfig: mtlsTLSConfig(t), Trust: trustForCert(t, adminCert)}
	if admin != nil {
		cfg.ScepAdmin = admin
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// callAllScep runs each SCEP admin RPC once and returns their status codes.
func callAllScep(ctx context.Context, srv *Server) map[string]codes.Code {
	got := map[string]codes.Code{}
	_, err := srv.MintScepChallenge(ctx, &cryptosv1.MintScepChallengeRequest{Profile: "cisco"})
	got["mint"] = status.Code(err)
	_, err = srv.ListScepChallenges(ctx, &cryptosv1.ListScepChallengesRequest{})
	got["list-challenges"] = status.Code(err)
	_, err = srv.RevokeScepChallenge(ctx, &cryptosv1.RevokeScepChallengeRequest{Id: "ch1"})
	got["revoke-challenge"] = status.Code(err)
	_, err = srv.ListScepEnrollments(ctx, &cryptosv1.ListScepEnrollmentsRequest{})
	got["list-enrollments"] = status.Code(err)
	_, err = srv.ApproveScepEnrollment(ctx, &cryptosv1.ApproveScepEnrollmentRequest{Id: "en1"})
	got["approve"] = status.Code(err)
	_, err = srv.RejectScepEnrollment(ctx, &cryptosv1.RejectScepEnrollmentRequest{Id: "en1", Reason: "unknown device"})
	got["reject"] = status.Code(err)
	return got
}

// Without a SCEP listener this boot (maintenance mode, a Root, or SCEP
// switched off) every SCEP RPC is FailedPrecondition, as the contract says.
func TestScepRPCs_FailedPreconditionWhenNotRunning(t *testing.T) {
	admin := authzTestCert(t)
	srv := serverWithScep(t, nil, admin)
	for rpc, code := range callAllScep(authzMTLSContext(admin), srv) {
		if code != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", rpc, code)
		}
	}
}

func TestScepRPCs_NonAdminIsDenied(t *testing.T) {
	admin := authzTestCert(t)
	m := &mockScepAdmin{}
	srv := serverWithScep(t, m, admin)
	for rpc, code := range callAllScep(authzMTLSContext(authzTestCert(t)), srv) {
		if code != codes.PermissionDenied {
			t.Errorf("%s: code = %v, want PermissionDenied", rpc, code)
		}
	}
	if len(m.calls) != 0 {
		t.Fatalf("the SCEP admin was reached for a non-admin caller: %v", m.calls)
	}
}

func TestScepRPCs_AdminReachesEveryOperation(t *testing.T) {
	admin := authzTestCert(t)
	m := &mockScepAdmin{}
	srv := serverWithScep(t, m, admin)
	for rpc, code := range callAllScep(authzMTLSContext(admin), srv) {
		if code != codes.OK {
			t.Errorf("%s: code = %v, want OK", rpc, code)
		}
	}
	if len(m.calls) != 6 {
		t.Fatalf("admin calls = %v, want all six", m.calls)
	}
}

func TestMintScepChallenge_PassesTheActorAndKeepsThePasswordOutOfTheAudit(t *testing.T) {
	admin := authzTestCert(t)
	m := &mockScepAdmin{}
	srv := serverWithScep(t, m, admin)
	details := map[string]string{}
	ctx := context.WithValue(authzMTLSContext(admin), auditDetailsKey{}, details)

	resp, err := srv.MintScepChallenge(ctx, &cryptosv1.MintScepChallengeRequest{Profile: "cisco", TtlSeconds: 600, BoundNames: []string{"switch01.example.com"}})
	if err != nil {
		t.Fatalf("MintScepChallenge: %v", err)
	}
	if resp.GetChallengePassword() == "" {
		t.Fatal("the minted challenge was not returned")
	}
	if m.actorCN != admin.Subject.CommonName {
		t.Fatalf("actor CN = %q, want %q", m.actorCN, admin.Subject.CommonName)
	}
	if m.mintReq.GetTtlSeconds() != 600 || len(m.mintReq.GetBoundNames()) != 1 {
		t.Fatalf("request not passed through: %v", m.mintReq)
	}
	if details["challenge_id"] != "ch1" || details["profile"] != "cisco" || details["bound_names"] != "switch01.example.com" {
		t.Fatalf("audit details = %v, want the challenge id, profile and bound names", details)
	}
	for k, v := range details {
		if strings.Contains(v, resp.GetChallengePassword()) {
			t.Fatalf("audit detail %q carries the challenge password", k)
		}
	}
}

func TestMintScepChallenge_LocalSocketActor(t *testing.T) {
	admin := authzTestCert(t)
	m := &mockScepAdmin{}
	srv := serverWithScep(t, m, admin)
	if _, err := srv.MintScepChallenge(context.Background(), &cryptosv1.MintScepChallengeRequest{}); err != nil {
		t.Fatalf("MintScepChallenge over the local socket: %v", err)
	}
	if m.actorCN != LocalSocketActor {
		t.Fatalf("actor CN = %q, want %q", m.actorCN, LocalSocketActor)
	}
}

func TestScepRPCs_PassAdminErrorsThrough(t *testing.T) {
	admin := authzTestCert(t)
	m := &mockScepAdmin{err: status.Error(codes.NotFound, "no such enrolment")}
	srv := serverWithScep(t, m, admin)
	_, err := srv.ApproveScepEnrollment(authzMTLSContext(admin), &cryptosv1.ApproveScepEnrollmentRequest{Id: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

func TestApproveAndRejectScepEnrollment_RecordAuditDetails(t *testing.T) {
	admin := authzTestCert(t)
	m := &mockScepAdmin{}
	srv := serverWithScep(t, m, admin)

	details := map[string]string{}
	ctx := context.WithValue(authzMTLSContext(admin), auditDetailsKey{}, details)
	if _, err := srv.ApproveScepEnrollment(ctx, &cryptosv1.ApproveScepEnrollmentRequest{Id: "en1"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if details["enrollment_id"] != "en1" || details["serial_hex"] != "abc123" || details["profile"] != "cisco" {
		t.Fatalf("approve audit details = %v", details)
	}

	details = map[string]string{}
	ctx = context.WithValue(authzMTLSContext(admin), auditDetailsKey{}, details)
	if _, err := srv.RejectScepEnrollment(ctx, &cryptosv1.RejectScepEnrollmentRequest{Id: "en2", Reason: "unknown device"}); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if details["enrollment_id"] != "en2" || details["reason"] != "unknown device" {
		t.Fatalf("reject audit details = %v", details)
	}
}
