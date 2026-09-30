package acme

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
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// newTestStore spins up an embedded etcd and returns a Store over it.
func newTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	srv, err := etcd.Open(t.TempDir())
	if err != nil {
		t.Fatalf("etcd.Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("etcd.Client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return NewStore(cli), ctx
}

func TestStoreMissingRecords(t *testing.T) {
	s, ctx := newTestStore(t)
	if _, err := s.GetAccount(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAccount err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetOrder(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetOrder err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetAuthorization(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAuthorization err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetCertificate(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCertificate err = %v, want ErrNotFound", err)
	}
	if _, err := s.AccountByThumbprint(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AccountByThumbprint err = %v, want ErrNotFound", err)
	}
	if _, err := s.CertificateBySerial(ctx, "0a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CertificateBySerial err = %v, want ErrNotFound", err)
	}
}

func TestStoreAccountIndexedByThumbprint(t *testing.T) {
	s, ctx := newTestStore(t)
	acct := Account{ID: "acct1", Status: StatusValid, KeyThumbprint: "thumb1",
		Key: JWK{Kty: "EC", Crv: "P-256"}, CreatedAt: time.Unix(100, 0).UTC()}
	if err := s.PutAccount(ctx, acct); err != nil {
		t.Fatalf("PutAccount: %v", err)
	}
	got, err := s.AccountByThumbprint(ctx, "thumb1")
	if err != nil {
		t.Fatalf("AccountByThumbprint: %v", err)
	}
	if got.ID != "acct1" {
		t.Fatalf("account = %+v", got)
	}
}

// TestConsumeNonceIsSingleUse is the store-level half of the anti-replay
// guarantee: the delete is the check, so exactly one consumer can win.
func TestConsumeNonceIsSingleUse(t *testing.T) {
	s, ctx := newTestStore(t)
	nonce, err := s.NewNonce(ctx, time.Minute)
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	ok, err := s.ConsumeNonce(ctx, nonce)
	if err != nil || !ok {
		t.Fatalf("first ConsumeNonce ok=%v err=%v", ok, err)
	}
	ok, err = s.ConsumeNonce(ctx, nonce)
	if err != nil {
		t.Fatalf("second ConsumeNonce: %v", err)
	}
	if ok {
		t.Fatal("a nonce was consumed twice")
	}
	if ok, err := s.ConsumeNonce(ctx, "never-issued"); err != nil || ok {
		t.Fatalf("an unknown nonce was accepted: ok=%v err=%v", ok, err)
	}
}

// TestPutOrderIfUnchangedRejectsStaleRevision is the guard that stops two
// concurrent finalizes from both issuing. Testing the primitive directly
// keeps it deterministic: a racing-goroutine test would only sometimes
// exercise the losing branch.
func TestPutOrderIfUnchangedRejectsStaleRevision(t *testing.T) {
	s, ctx := newTestStore(t)
	order := Order{ID: "o1", AccountID: "a1", Status: StatusReady,
		Identifiers: []Identifier{{Type: IdentifierTypeDNS, Value: "web.example.org"}}}
	if err := s.PutOrder(ctx, order); err != nil {
		t.Fatalf("PutOrder: %v", err)
	}

	// Both readers see the same revision, as two concurrent finalizes would.
	first, rev, err := s.GetOrderRev(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrderRev: %v", err)
	}
	second := first

	first.Status = StatusProcessing
	ok, err := s.PutOrderIfUnchanged(ctx, first, rev)
	if err != nil || !ok {
		t.Fatalf("the first writer lost: ok=%v err=%v", ok, err)
	}

	second.Status = StatusProcessing
	ok, err = s.PutOrderIfUnchanged(ctx, second, rev)
	if err != nil {
		t.Fatalf("second PutOrderIfUnchanged: %v", err)
	}
	if ok {
		t.Fatal("a stale revision was allowed to write; two finalizes could both issue")
	}

	got, err := s.GetOrder(ctx, "o1")
	if err != nil {
		t.Fatalf("GetOrder: %v", err)
	}
	if got.Status != StatusProcessing {
		t.Fatalf("order status = %q", got.Status)
	}
}

func TestListOrderIDsIsScopedToAccount(t *testing.T) {
	s, ctx := newTestStore(t)
	for _, o := range []Order{
		{ID: "o1", AccountID: "a1"},
		{ID: "o2", AccountID: "a1"},
		{ID: "o3", AccountID: "a2"},
	} {
		if err := s.PutOrder(ctx, o); err != nil {
			t.Fatalf("PutOrder %s: %v", o.ID, err)
		}
	}
	ids, err := s.ListOrderIDs(ctx, "a1")
	if err != nil {
		t.Fatalf("ListOrderIDs: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("ids = %v, want two orders for a1", ids)
	}
	for _, id := range ids {
		if id == "o3" {
			t.Fatal("another account's order leaked into the list")
		}
	}
}

// A record written by an older build must not be silently treated as absent.
func TestGetJSONReportsCorruptRecord(t *testing.T) {
	s, ctx := newTestStore(t)
	if _, err := s.cli.Put(ctx, etcd.PrefixACMEOrders+"bad", "{not json"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, err := s.GetOrder(ctx, "bad")
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want a decode error rather than ErrNotFound", err)
	}
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("err = %v, want it to wrap a JSON syntax error", err)
	}
}

// TestFinalizeIsClaimedOnce: once an order has been finalized, a second
// finalize is refused rather than issuing a second certificate.
func TestFinalizeIsClaimedOnce(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	orderURL, order := c.newOrder("web.example.org")
	c.solveAll(order)
	order = c.getOrder(orderURL)

	csr := makeCSR(t, "", "web.example.org")
	resp, body := c.post(order.Finalize, map[string]any{"csr": b64.EncodeToString(csr)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first finalize: status %d body %s", resp.StatusCode, body)
	}

	resp, body = c.post(order.Finalize, map[string]any{"csr": b64.EncodeToString(csr)})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a second finalize succeeded: %s", body)
	}
	if p := decodeProblem(t, body); p.Type != ErrOrderNotReady {
		t.Fatalf("problem = %q, want orderNotReady", p.Type)
	}
	if len(f.issued) != 1 {
		t.Fatalf("the CA issued %d certificates for one order", len(f.issued))
	}
}
