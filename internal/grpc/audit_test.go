package grpc

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
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	stdgrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/audit"
)

var auditBase = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

type auditFixture struct {
	dir string
	log *audit.Logger
}

// newAuditFixture writes one entry per method, the i-th stamped auditBase + i
// minutes, and returns the open log.
func newAuditFixture(t *testing.T, entries ...*cryptosv1.AuditEvent) auditFixture {
	t.Helper()
	seed := make([]byte, audit.SeedLength)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dir := t.TempDir()
	log, err := audit.Open(dir, seed)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i, ev := range entries {
		ev.Ts = timestamppb.New(auditBase.Add(time.Duration(i) * time.Minute))
		if err := log.Append(ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	return auditFixture{dir: dir, log: log}
}

func auditEntry(method, actor string) *cryptosv1.AuditEvent {
	return &cryptosv1.AuditEvent{
		RpcMethod:    "/cryptos.v1.NodeService/" + method,
		ActorSubject: actor,
		Outcome:      cryptosv1.Outcome_OUTCOME_OK,
	}
}

func auditServer(t *testing.T, log AuditLog) *Server {
	t.Helper()
	srv, err := New(ServerConfig{Auditor: &mockAuditor{}, TLSConfig: mtlsTLSConfig(t), AuditLog: log})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func entrySeqs(entries []*cryptosv1.AuditLogEntry) []uint64 {
	var out []uint64
	for _, e := range entries {
		out = append(out, e.GetEvent().GetSeq())
	}
	return out
}

func sameSeqs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAuditRPCs_FailedPreconditionInMaintenanceMode(t *testing.T) {
	srv := auditServer(t, nil)
	if _, err := srv.ListAuditEvents(context.Background(), &cryptosv1.ListAuditEventsRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("ListAuditEvents code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := srv.VerifyAuditChain(context.Background(), &cryptosv1.VerifyAuditChainRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("VerifyAuditChain code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestAuditRPCs_AuthorizedLikeListIssued(t *testing.T) {
	fx := newAuditFixture(t, auditEntry("GetStatus", "CN=admin"))
	admin := authzTestCert(t)
	srv, err := New(ServerConfig{Auditor: &mockAuditor{}, TLSConfig: mtlsTLSConfig(t), AuditLog: fx.log, Trust: trustForCert(t, admin)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	other := authzMTLSContext(authzTestCert(t))
	if _, err := srv.ListAuditEvents(other, &cryptosv1.ListAuditEventsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ListAuditEvents for another certificate: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := srv.VerifyAuditChain(other, &cryptosv1.VerifyAuditChainRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("VerifyAuditChain for another certificate: code = %v, want PermissionDenied", status.Code(err))
	}
	for name, ctx := range map[string]context.Context{"admin": authzMTLSContext(admin), "local socket": context.Background()} {
		if _, err := srv.ListAuditEvents(ctx, &cryptosv1.ListAuditEventsRequest{}); err != nil {
			t.Errorf("ListAuditEvents as %s: %v", name, err)
		}
		if _, err := srv.VerifyAuditChain(ctx, &cryptosv1.VerifyAuditChainRequest{}); err != nil {
			t.Errorf("VerifyAuditChain as %s: %v", name, err)
		}
	}
}

func TestListAuditEvents_PagesWithTokens(t *testing.T) {
	fx := newAuditFixture(t,
		auditEntry("StartCeremony", "CN=admin"),
		auditEntry("ApplyConfig", "CN=admin"),
		auditEntry("IssueLeaf", "CN=admin"),
		auditEntry("RevokeCertificate", "CN=admin"),
		auditEntry("Reboot", "CN=admin"),
	)
	srv := auditServer(t, fx.log)
	var got []*cryptosv1.AuditLogEntry
	token := ""
	pages := 0
	for {
		resp, err := srv.ListAuditEvents(context.Background(), &cryptosv1.ListAuditEventsRequest{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatalf("ListAuditEvents page %d: %v", pages, err)
		}
		pages++
		if len(resp.GetEntries()) > 2 {
			t.Fatalf("page %d has %d entries, want at most 2", pages, len(resp.GetEntries()))
		}
		got = append(got, resp.GetEntries()...)
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
		if pages > 5 {
			t.Fatal("paging did not end")
		}
	}
	if pages != 3 || !sameSeqs(entrySeqs(got), []uint64{1, 2, 3, 4, 5}) {
		t.Fatalf("%d pages with seqs %v, want 3 pages with 1..5", pages, entrySeqs(got))
	}
	for i := 0; i+1 < len(got); i++ {
		if !bytes.Equal(got[i].GetEntrySha256(), got[i+1].GetEvent().GetPrevEntrySha256()) {
			t.Fatalf("entry_sha256 of seq %d is not seq %d's prev_entry_sha256", i+1, i+2)
		}
	}
	if s := got[4].GetSummary(); s != "rebooted or powered off the node" {
		t.Errorf("summary of the Reboot entry = %q", s)
	}
}

func TestListAuditEvents_Filters(t *testing.T) {
	fx := newAuditFixture(t,
		auditEntry("StartCeremony", "CN=admin,O=Example"),          // 1 @ +0m
		auditEntry("IssueLeaf", "CN=operator-a,O=Example"),         // 2 @ +1m
		auditEntry("RevokeCertificate", "CN=operator-b,O=Example"), // 3 @ +2m
		auditEntry("IssueLeaf", "CN=operator-b,O=Example"),         // 4 @ +3m
	)
	srv := auditServer(t, fx.log)
	for _, tc := range []struct {
		name string
		req  *cryptosv1.ListAuditEventsRequest
		want []uint64
	}{
		{"event type by name", &cryptosv1.ListAuditEventsRequest{EventType: "IssueLeaf"}, []uint64{2, 4}},
		{"event type by full method", &cryptosv1.ListAuditEventsRequest{EventType: "/cryptos.v1.NodeService/RevokeCertificate"}, []uint64{3}},
		{"actor", &cryptosv1.ListAuditEventsRequest{Actor: "operator-b"}, []uint64{3, 4}},
		{"actor is case-sensitive", &cryptosv1.ListAuditEventsRequest{Actor: "OPERATOR-B"}, nil},
		{"from is inclusive", &cryptosv1.ListAuditEventsRequest{FromTime: auditBase.Add(2 * time.Minute).Format(time.RFC3339)}, []uint64{3, 4}},
		{"to is exclusive", &cryptosv1.ListAuditEventsRequest{ToTime: auditBase.Add(time.Minute).Format(time.RFC3339)}, []uint64{1}},
		{"combined", &cryptosv1.ListAuditEventsRequest{EventType: "IssueLeaf", Actor: "operator-a"}, []uint64{2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := srv.ListAuditEvents(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("ListAuditEvents: %v", err)
			}
			if got := entrySeqs(resp.GetEntries()); !sameSeqs(got, tc.want) {
				t.Fatalf("seqs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestListAuditEvents_InvalidArguments(t *testing.T) {
	fx := newAuditFixture(t, auditEntry("A", "CN=a"), auditEntry("B", "CN=a"), auditEntry("C", "CN=a"))
	srv := auditServer(t, fx.log)
	first, err := srv.ListAuditEvents(context.Background(), &cryptosv1.ListAuditEventsRequest{PageSize: 1, Actor: "CN=a"})
	if err != nil || first.GetNextPageToken() == "" {
		t.Fatalf("first page: token %q err %v", first.GetNextPageToken(), err)
	}
	for _, tc := range []struct {
		name string
		req  *cryptosv1.ListAuditEventsRequest
	}{
		{"negative page size", &cryptosv1.ListAuditEventsRequest{PageSize: -1}},
		{"from not RFC3339", &cryptosv1.ListAuditEventsRequest{FromTime: "yesterday"}},
		{"to not RFC3339", &cryptosv1.ListAuditEventsRequest{ToTime: "2026-06-03"}},
		{"to before from", &cryptosv1.ListAuditEventsRequest{
			FromTime: auditBase.Format(time.RFC3339), ToTime: auditBase.Add(-time.Minute).Format(time.RFC3339)}},
		{"a token the node did not issue", &cryptosv1.ListAuditEventsRequest{PageToken: "not-a-token"}},
		{"a token reused with other filters", &cryptosv1.ListAuditEventsRequest{PageSize: 1, Actor: "CN=b", PageToken: first.GetNextPageToken()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := srv.ListAuditEvents(context.Background(), tc.req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v (err %v), want InvalidArgument", status.Code(err), err)
			}
		})
	}
	// The same filters with the token carry on.
	next, err := srv.ListAuditEvents(context.Background(), &cryptosv1.ListAuditEventsRequest{PageSize: 1, Actor: "CN=a", PageToken: first.GetNextPageToken()})
	if err != nil || !sameSeqs(entrySeqs(next.GetEntries()), []uint64{2}) {
		t.Fatalf("second page = %v, err %v, want seq 2", entrySeqs(next.GetEntries()), err)
	}
}

func TestVerifyAuditChain_IntactAndTampered(t *testing.T) {
	fx := newAuditFixture(t,
		auditEntry("StartCeremony", "CN=operator-a"),
		auditEntry("IssueLeaf", "CN=operator-a"),
		auditEntry("RevokeCertificate", "CN=operator-a"),
		auditEntry("Reboot", "CN=operator-a"),
	)
	srv := auditServer(t, fx.log)
	resp, err := srv.VerifyAuditChain(context.Background(), &cryptosv1.VerifyAuditChainRequest{})
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !resp.GetIntact() || resp.GetEntryCount() != 4 || resp.GetFirstBrokenSequence() != 0 || resp.GetReason() != "" {
		t.Fatalf("intact chain = %v, want intact with 4 entries", resp)
	}

	files, err := filepath.Glob(filepath.Join(fx.dir, "*.log"))
	if err != nil || len(files) != 1 {
		t.Fatalf("log files %v err %v", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	lines[2] = strings.Replace(lines[2], "operator-a", "operator-z", 1)
	if err := os.WriteFile(files[0], []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err = srv.VerifyAuditChain(context.Background(), &cryptosv1.VerifyAuditChainRequest{})
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if resp.GetIntact() || resp.GetFirstBrokenSequence() != 3 || resp.GetEntryCount() != 4 || resp.GetReason() == "" {
		t.Fatalf("tampered chain = %v, want broken at seq 3 with 4 entries and a reason", resp)
	}
}

// A revocation's entry names the serial, so audit list can show what was
// revoked.
func TestRevokeCertificateAuditsTheSerial(t *testing.T) {
	auditor := &mockAuditor{}
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   auditor,
		Revoker:   &fakeRevoker{revocation: &cryptosv1.Revocation{SerialHex: "1a2b"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := &cryptosv1.RevokeCertificateRequest{SerialHex: "0x1A:2B"}
	_, err = srv.unaryAudit(context.Background(), req, &stdgrpc.UnaryServerInfo{FullMethod: "/cryptos.v1.NodeService/RevokeCertificate"},
		func(ctx context.Context, r interface{}) (interface{}, error) {
			return srv.RevokeCertificate(ctx, r.(*cryptosv1.RevokeCertificateRequest))
		})
	if err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	events := auditor.snapshot()
	if len(events) != 1 || events[0].GetDetails()[audit.DetailSerial] != "1a2b" {
		t.Fatalf("audit events = %v, want one naming serial 1a2b", events)
	}
}
