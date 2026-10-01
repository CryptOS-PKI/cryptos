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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/audit"
	"github.com/CryptOS-PKI/cryptos-node/internal/scep"
)

// knownAuditEventTypes holds every event_type ListAuditEvents accepts, less
// any leading slash: each NodeService method and each SCEP operation the audit
// log records, both by full name and by name alone.
var knownAuditEventTypes = func() map[string]bool {
	known := map[string]bool{}
	add := func(full string) {
		known[full] = true
		known[audit.MethodName(full)] = true
	}
	desc := nodev1.NodeService_ServiceDesc
	for _, m := range desc.Methods {
		add(desc.ServiceName + "/" + m.MethodName)
	}
	for _, st := range desc.Streams {
		add(desc.ServiceName + "/" + st.StreamName)
	}
	for _, m := range scep.AuditMethods() {
		add(m)
	}
	return known
}()

// AuditLog reads the node's hash-chained audit log. It is wired on the mTLS
// and local servers of a running node, where the state partition holding the
// log is open; the maintenance servers leave it nil, so the audit RPCs answer
// FailedPrecondition there. Implemented by *audit.Logger.
type AuditLog interface {
	List(q audit.Query) (audit.Page, error)
	Verify() (audit.VerifyResult, error)
}

// auditTokenPrefix versions the page token format.
const auditTokenPrefix = "a1"

// ListAuditEvents handles cryptos.node.v1.NodeService/ListAuditEvents: it returns
// the audit log a page at a time, oldest first, filtered by time range, event
// type and actor. It is authorized like ListIssued. The page token carries
// the last sequence number returned and a digest of the filters, so a token
// reused with other filters, or one the node did not issue, is refused.
func (s *Server) ListAuditEvents(ctx context.Context, req *nodev1.ListAuditEventsRequest) (*nodev1.ListAuditEventsResponse, error) {
	if s.cfg.AuditLog == nil {
		return nil, status.Error(codes.FailedPrecondition, "the audit log is not open in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if req.GetPageSize() < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "ListAuditEvents: page_size must not be negative, got %d", req.GetPageSize())
	}
	from, err := parseAuditTime("from_time", req.GetFromTime())
	if err != nil {
		return nil, err
	}
	to, err := parseAuditTime("to_time", req.GetToTime())
	if err != nil {
		return nil, err
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		return nil, status.Error(codes.InvalidArgument, "ListAuditEvents: to_time is earlier than from_time")
	}
	if t := req.GetEventType(); t != "" && !knownAuditEventTypes[strings.TrimPrefix(t, "/")] {
		return nil, status.Errorf(codes.InvalidArgument,
			"ListAuditEvents: unknown event_type %q: want a method name such as RevokeCertificate (case-sensitive), "+
				"its full name /%s/RevokeCertificate, or a SCEP operation such as PKCSReq", t, nodev1.NodeService_ServiceDesc.ServiceName)
	}
	filters := auditFilterDigest(req)
	after, err := decodeAuditToken(req.GetPageToken(), filters)
	if err != nil {
		return nil, err
	}

	page, err := s.cfg.AuditLog.List(audit.Query{
		Since:    from,
		Until:    to,
		Method:   req.GetEventType(),
		Actor:    req.GetActor(),
		PageSize: int(req.GetPageSize()),
		AfterSeq: after,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ListAuditEvents: %v", err)
	}
	resp := &nodev1.ListAuditEventsResponse{}
	for _, e := range page.Entries {
		target, summary := audit.Describe(e.Event)
		resp.Entries = append(resp.Entries, &nodev1.AuditLogEntry{
			Event:       e.Event,
			EntrySha256: e.SHA256[:],
			Target:      target,
			Summary:     summary,
		})
	}
	if page.NextAfterSeq != 0 {
		resp.NextPageToken = encodeAuditToken(page.NextAfterSeq, filters)
	}
	return resp, nil
}

// VerifyAuditChain handles cryptos.node.v1.NodeService/VerifyAuditChain: it checks
// every entry's signature and the hash chain over the whole stored log. A
// broken chain is a result; the RPC fails only when the log can't be read. It
// is authorized like ListIssued.
func (s *Server) VerifyAuditChain(ctx context.Context, _ *nodev1.VerifyAuditChainRequest) (*nodev1.VerifyAuditChainResponse, error) {
	if s.cfg.AuditLog == nil {
		return nil, status.Error(codes.FailedPrecondition, "the audit log is not open in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	res, err := s.cfg.AuditLog.Verify()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VerifyAuditChain: %v", err)
	}
	return &nodev1.VerifyAuditChainResponse{
		EntryCount:          res.Entries,
		Intact:              res.Intact,
		FirstBrokenSequence: res.FirstBrokenSeq,
		Reason:              res.Reason,
	}, nil
}

func parseAuditTime(field, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, status.Errorf(codes.InvalidArgument, "ListAuditEvents: %s %q is not an RFC3339 time", field, v)
	}
	return t, nil
}

// auditFilterDigest binds a page token to the filters it was issued for.
func auditFilterDigest(req *nodev1.ListAuditEventsRequest) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		req.GetFromTime(), req.GetToTime(), req.GetEventType(), req.GetActor(),
	}, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func encodeAuditToken(afterSeq uint64, filters string) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%s:%d:%s", auditTokenPrefix, afterSeq, filters)))
}

func decodeAuditToken(token, filters string) (uint64, error) {
	if token == "" {
		return 0, nil
	}
	bad := status.Error(codes.InvalidArgument, "ListAuditEvents: page_token was not issued for this query; start again without it")
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, bad
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 || parts[0] != auditTokenPrefix || parts[2] != filters {
		return 0, bad
	}
	seq, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || seq == 0 {
		return 0, bad
	}
	return seq, nil
}
