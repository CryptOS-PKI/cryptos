package revocation

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
	"errors"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// newRevStore spins up an embedded etcd in a temp dir and returns a
// revocation Store plus a context.
func newRevStore(t *testing.T) (*Store, context.Context) {
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
	s := NewStore(cli)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return s, ctx
}

func TestRecordAndListIssued(t *testing.T) {
	s, ctx := newRevStore(t)
	r := IssuedRecord{SerialHex: "0a", SubjectDN: "CN=leaf", NotBefore: time.Unix(100, 0).UTC(), NotAfter: time.Unix(1000, 0).UTC(), SKIHex: "ab", ProfileName: "leaf", IssuedAt: time.Unix(100, 0).UTC()}
	if err := s.RecordIssued(ctx, r); err != nil {
		t.Fatalf("RecordIssued: %v", err)
	}
	got, ok, err := s.GetIssued(ctx, "0a")
	if err != nil || !ok {
		t.Fatalf("GetIssued ok=%v err=%v", ok, err)
	}
	if got.SubjectDN != "CN=leaf" || !got.NotAfter.Equal(r.NotAfter) {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	all, err := s.ListIssued(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("ListIssued len=%d err=%v", len(all), err)
	}
}

func TestRevokeIdempotentAndUnknown(t *testing.T) {
	s, ctx := newRevStore(t)
	if _, err := s.Revoke(ctx, "ff", 1, time.Unix(200, 0).UTC()); !errors.Is(err, ErrNotIssued) {
		t.Fatalf("revoke unknown = %v, want ErrNotIssued", err)
	}
	_ = s.RecordIssued(ctx, IssuedRecord{SerialHex: "ff", NotAfter: time.Unix(1000, 0).UTC()})
	rec, err := s.Revoke(ctx, "ff", 1, time.Unix(200, 0).UTC())
	if err != nil || rec.ReasonCode != 1 {
		t.Fatalf("revoke: %+v err=%v", rec, err)
	}
	// Idempotent: second revoke returns the ORIGINAL record, does not overwrite.
	rec2, err := s.Revoke(ctx, "ff", 4, time.Unix(300, 0).UTC())
	if err != nil || !rec2.RevokedAt.Equal(rec.RevokedAt) || rec2.ReasonCode != 1 {
		t.Fatalf("re-revoke changed record: %+v", rec2)
	}
}

func TestNextCRLNumberMonotonic(t *testing.T) {
	s, ctx := newRevStore(t)
	a, _ := s.NextCRLNumber(ctx)
	b, _ := s.NextCRLNumber(ctx)
	if b != a+1 {
		t.Fatalf("crl number not monotonic: %d then %d", a, b)
	}
}
