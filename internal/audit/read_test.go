package audit

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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

var readBase = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

// seedLog writes the given events, the i-th stamped readBase + i minutes, and
// returns the closed logger (still usable for reads).
func seedLog(t *testing.T, events ...*nodev1.AuditEvent) *Logger {
	t.Helper()
	logger, err := Open(t.TempDir(), mustSeed(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	logger.now = func() time.Time { return readBase }
	for i, ev := range events {
		ev.Ts = timestamppb.New(readBase.Add(time.Duration(i) * time.Minute))
		if err := logger.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return logger
}

func mustVerify(t *testing.T, logger *Logger) VerifyResult {
	t.Helper()
	res, err := logger.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return res
}

func actorEvent(method, actor string) *nodev1.AuditEvent {
	ev := newEvent(method)
	ev.ActorSubject = actor
	return ev
}

func seqs(entries []Entry) []uint64 {
	out := make([]uint64, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Event.GetSeq())
	}
	return out
}

func equalSeqs(a, b []uint64) bool {
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

func TestList_PagesInSequenceOrder(t *testing.T) {
	logger := seedLog(t,
		newEvent("/cryptos.node.v1.NodeService/GetStatus"),
		newEvent("/cryptos.node.v1.NodeService/GetStatus"),
		newEvent("/cryptos.node.v1.NodeService/GetStatus"),
		newEvent("/cryptos.node.v1.NodeService/GetStatus"),
		newEvent("/cryptos.node.v1.NodeService/GetStatus"),
	)
	want := [][]uint64{{1, 2}, {3, 4}, {5}}
	var after uint64
	for i, w := range want {
		page, err := logger.List(Query{PageSize: 2, AfterSeq: after})
		if err != nil {
			t.Fatalf("List page %d: %v", i, err)
		}
		if got := seqs(page.Entries); !equalSeqs(got, w) {
			t.Fatalf("page %d seqs = %v, want %v", i, got, w)
		}
		last := i == len(want)-1
		if last && page.NextAfterSeq != 0 {
			t.Fatalf("last page NextAfterSeq = %d, want 0", page.NextAfterSeq)
		}
		if !last && page.NextAfterSeq != w[len(w)-1] {
			t.Fatalf("page %d NextAfterSeq = %d, want %d", i, page.NextAfterSeq, w[len(w)-1])
		}
		after = page.NextAfterSeq
	}
}

func TestList_FullPageAtTheEndHasNoNextPage(t *testing.T) {
	logger := seedLog(t, newEvent("a"), newEvent("b"))
	page, err := logger.List(Query{PageSize: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Entries) != 2 || page.NextAfterSeq != 0 {
		t.Fatalf("got %v next=%d, want 2 events and no next page", seqs(page.Entries), page.NextAfterSeq)
	}
}

func TestList_DefaultAndMaximumPageSize(t *testing.T) {
	events := make([]*nodev1.AuditEvent, DefaultPageSize+1)
	for i := range events {
		events[i] = newEvent("/cryptos.node.v1.NodeService/GetStatus")
	}
	logger := seedLog(t, events...)
	page, err := logger.List(Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Entries) != DefaultPageSize || page.NextAfterSeq != uint64(DefaultPageSize) {
		t.Fatalf("default page: %d events next=%d, want %d events next=%d",
			len(page.Entries), page.NextAfterSeq, DefaultPageSize, DefaultPageSize)
	}
	page, err = logger.List(Query{PageSize: MaxPageSize + 1})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Entries) != DefaultPageSize+1 {
		t.Fatalf("an oversized page size must be clamped, not rejected: got %d events", len(page.Entries))
	}
}

func TestList_FiltersByMethodActorAndTime(t *testing.T) {
	logger := seedLog(t,
		actorEvent("/cryptos.node.v1.NodeService/StartCeremony", "CN=admin,O=Example"),          // 1 @ +0m
		actorEvent("/cryptos.node.v1.NodeService/IssueLeaf", "CN=operator-a,O=Example"),         // 2 @ +1m
		actorEvent("/cryptos.node.v1.NodeService/RevokeCertificate", "CN=operator-b,O=Example"), // 3 @ +2m
		actorEvent("/cryptos.node.v1.NodeService/IssueLeaf", "CN=operator-b,O=Example"),         // 4 @ +3m
		actorEvent("/cryptos.node.v1.NodeService/ApplyConfig", "CN=admin,O=Example"),            // 5 @ +4m
	)
	cases := []struct {
		name string
		q    Query
		want []uint64
	}{
		{"short method name", Query{Method: "IssueLeaf"}, []uint64{2, 4}},
		{"method name is case-sensitive", Query{Method: "issueleaf"}, nil},
		{"full method name", Query{Method: "/cryptos.node.v1.NodeService/RevokeCertificate"}, []uint64{3}},
		{"full method name without the leading slash", Query{Method: "cryptos.node.v1.NodeService/RevokeCertificate"}, []uint64{3}},
		{"method never matches a prefix", Query{Method: "Issue"}, nil},
		{"actor substring", Query{Actor: "operator-b"}, []uint64{3, 4}},
		{"actor is case-sensitive", Query{Actor: "cn=admin"}, nil},
		{"actor prefix", Query{Actor: "CN=admin"}, []uint64{1, 5}},
		{"since is inclusive", Query{Since: readBase.Add(3 * time.Minute)}, []uint64{4, 5}},
		{"until is exclusive", Query{Until: readBase.Add(2 * time.Minute)}, []uint64{1, 2}},
		{"window", Query{Since: readBase.Add(time.Minute), Until: readBase.Add(4 * time.Minute)}, []uint64{2, 3, 4}},
		{"combined", Query{Method: "IssueLeaf", Actor: "operator-b"}, []uint64{4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := logger.List(tc.q)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if got := seqs(page.Entries); !equalSeqs(got, tc.want) {
				t.Fatalf("seqs = %v, want %v", got, tc.want)
			}
		})
	}
}

// A filtered page counts only matching entries, and its cursor resumes after
// the last match, so the next page skips entries the filter already passed.
func TestList_FilteredPaging(t *testing.T) {
	logger := seedLog(t,
		newEvent("/cryptos.node.v1.NodeService/IssueLeaf"),
		newEvent("/cryptos.node.v1.NodeService/GetStatus"),
		newEvent("/cryptos.node.v1.NodeService/IssueLeaf"),
		newEvent("/cryptos.node.v1.NodeService/GetStatus"),
		newEvent("/cryptos.node.v1.NodeService/IssueLeaf"),
	)
	page, err := logger.List(Query{Method: "IssueLeaf", PageSize: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := seqs(page.Entries); !equalSeqs(got, []uint64{1, 3}) || page.NextAfterSeq != 3 {
		t.Fatalf("first page %v next=%d, want [1 3] next=3", got, page.NextAfterSeq)
	}
	page, err = logger.List(Query{Method: "IssueLeaf", PageSize: 2, AfterSeq: page.NextAfterSeq})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := seqs(page.Entries); !equalSeqs(got, []uint64{5}) || page.NextAfterSeq != 0 {
		t.Fatalf("second page %v next=%d, want [5] next=0", got, page.NextAfterSeq)
	}
}

func TestList_EmptyLog(t *testing.T) {
	logger, err := Open(t.TempDir(), mustSeed(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	page, err := logger.List(Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Entries) != 0 || page.NextAfterSeq != 0 {
		t.Fatalf("empty log: got %v next=%d", seqs(page.Entries), page.NextAfterSeq)
	}
}

func TestList_ReturnsTheStoredFields(t *testing.T) {
	ev := actorEvent("/cryptos.node.v1.NodeService/IssueLeaf", "CN=operator-a,O=Example")
	ev.Outcome = nodev1.Outcome_OUTCOME_DENIED
	ev.Details = map[string]string{"request_dns_names": "www.example.org"}
	logger := seedLog(t, ev)
	page, err := logger.List(Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("got %d events, want 1", len(page.Entries))
	}
	got := page.Entries[0].Event
	if got.GetActorSubject() != "CN=operator-a,O=Example" || got.GetRpcMethod() != "/cryptos.node.v1.NodeService/IssueLeaf" ||
		got.GetOutcome() != nodev1.Outcome_OUTCOME_DENIED || got.GetDetails()["request_dns_names"] != "www.example.org" ||
		!got.GetTs().AsTime().Equal(readBase) || len(got.GetPrevEntrySha256()) != 32 {
		t.Fatalf("stored fields not returned intact: %v", got)
	}
}

// An entry's hash is taken over its bytes on disk, so it is the value the next
// entry chains to.
func TestList_EntryHashIsWhatTheNextEntryChainsTo(t *testing.T) {
	logger := seedLog(t, newEvent("a"), newEvent("b"), newEvent("c"))
	page, err := logger.List(Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for i := 0; i+1 < len(page.Entries); i++ {
		if !bytes.Equal(page.Entries[i].SHA256[:], page.Entries[i+1].Event.GetPrevEntrySha256()) {
			t.Fatalf("entry %d hash %x is not entry %d's prev_entry_sha256 %x", i+1,
				page.Entries[i].SHA256, i+2, page.Entries[i+1].Event.GetPrevEntrySha256())
		}
	}
}

// The logger keeps appending to the same file after a read.
func TestList_DoesNotDisturbAppends(t *testing.T) {
	logger, err := Open(t.TempDir(), mustSeed(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := logger.Append(newEvent("a")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := logger.List(Query{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := logger.Append(newEvent("b")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	page, err := logger.List(Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := seqs(page.Entries); !equalSeqs(got, []uint64{1, 2}) {
		t.Fatalf("seqs = %v, want [1 2]", got)
	}
	if res := mustVerify(t, logger); !res.Intact {
		t.Fatalf("Verify after interleaved reads: %+v", res)
	}
	_ = logger.Close()
}

func TestVerify_IntactChain(t *testing.T) {
	logger := seedLog(t, newEvent("a"), newEvent("b"), newEvent("c"), newEvent("d"))
	res := mustVerify(t, logger)
	if !res.Intact || res.Entries != 4 || res.FirstBrokenSeq != 0 || res.Reason != "" {
		t.Fatalf("Verify = %+v, want intact with 4 entries", res)
	}
}

func TestVerify_EmptyLogIsIntact(t *testing.T) {
	logger, err := Open(t.TempDir(), mustSeed(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if res := mustVerify(t, logger); !res.Intact || res.Entries != 0 {
		t.Fatalf("Verify = %+v, want intact with 0 entries", res)
	}
}

// rewriteLine applies edit to the n-th (1-based) line of the only log file.
func rewriteLine(t *testing.T, logger *Logger, n int, edit func(string) string) {
	t.Helper()
	files, err := listLogFiles(logger.dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("listLogFiles: %v %v", files, err)
	}
	path := filepath.Join(logger.dir, files[0])
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines[n-1] = edit(lines[n-1])
	var kept []string
	for _, l := range lines {
		if l != "" {
			kept = append(kept, l)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestVerify_DetectsATamperedEntryAtItsSequence(t *testing.T) {
	logger := seedLog(t,
		actorEvent("a", "CN=operator-a,O=Example"),
		actorEvent("b", "CN=operator-a,O=Example"),
		actorEvent("c", "CN=operator-a,O=Example"),
		actorEvent("d", "CN=operator-a,O=Example"),
		actorEvent("e", "CN=operator-a,O=Example"),
	)
	rewriteLine(t, logger, 3, func(l string) string {
		return strings.Replace(l, "operator-a", "operator-z", 1)
	})
	res := mustVerify(t, logger)
	if res.Intact {
		t.Fatalf("Verify reported a tampered chain as intact: %+v", res)
	}
	if res.FirstBrokenSeq != 3 {
		t.Fatalf("FirstBrokenSeq = %d, want 3 (%+v)", res.FirstBrokenSeq, res)
	}
	if res.Entries != 5 {
		t.Fatalf("Entries = %d, want 5, the whole log counted", res.Entries)
	}
	if !strings.Contains(res.Reason, "signature") {
		t.Fatalf("Reason = %q, want it to name the signature mismatch", res.Reason)
	}
}

// With an entry removed, the first failing entry is the one after the gap,
// and it is reported by the seq it holds.
func TestVerify_DetectsARemovedEntryAtTheEntryAfterIt(t *testing.T) {
	logger := seedLog(t, newEvent("a"), newEvent("b"), newEvent("c"), newEvent("d"))
	rewriteLine(t, logger, 2, func(string) string { return "" })
	res := mustVerify(t, logger)
	if res.Intact || res.FirstBrokenSeq != 3 {
		t.Fatalf("Verify = %+v, want broken at seq 3", res)
	}
	if res.Entries != 3 {
		t.Fatalf("Entries = %d, want 3", res.Entries)
	}
}

func TestVerify_DetectsAMalformedLine(t *testing.T) {
	logger := seedLog(t, newEvent("a"), newEvent("b"), newEvent("c"))
	rewriteLine(t, logger, 2, func(string) string { return "not an audit entry" })
	res := mustVerify(t, logger)
	if res.Intact || res.FirstBrokenSeq != 2 {
		t.Fatalf("Verify = %+v, want broken at seq 2", res)
	}
}

// VerifyChain keeps its error contract on top of the structured result.
func TestVerifyChain_ReportsTheBrokenSequence(t *testing.T) {
	logger := seedLog(t, newEvent("a"), newEvent("b"), newEvent("c"))
	if err := VerifyChain(logger.dir, logger.PublicKey()); err != nil {
		t.Fatalf("VerifyChain on an intact log: %v", err)
	}
	rewriteLine(t, logger, 2, func(l string) string { return strings.Replace(l, `"b"`, `"x"`, 1) })
	err := VerifyChain(logger.dir, logger.PublicKey())
	if err == nil || !strings.Contains(err.Error(), "seq 2") {
		t.Fatalf("VerifyChain error = %v, want it to name seq 2", err)
	}
}
