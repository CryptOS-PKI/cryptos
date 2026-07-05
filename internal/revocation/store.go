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
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// ErrNotIssued is returned by Revoke when the serial to revoke is not
// present in the issued set. A node only revokes certificates it issued.
var ErrNotIssued = errors.New("revocation: serial not in issued set")

// IssuedRecord is the persisted record of one certificate this CA issued,
// stored as JSON under etcd PrefixIssued + SerialHex.
type IssuedRecord struct {
	SerialHex   string    `json:"serial_hex"`
	SubjectDN   string    `json:"subject_dn"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SKIHex      string    `json:"ski_hex"`
	ProfileName string    `json:"profile_name"`
	IssuedAt    time.Time `json:"issued_at"`
}

// RevokedRecord is the persisted record of one revoked certificate, stored
// as JSON under etcd PrefixRevoked + SerialHex. ReasonCode is an RFC 5280
// CRL reason code.
type RevokedRecord struct {
	SerialHex  string    `json:"serial_hex"`
	RevokedAt  time.Time `json:"revoked_at"`
	ReasonCode int       `json:"reason_code"`
}

// Store is the typed accessor over the issued/revoked revocation state in
// the embedded etcd datastore. It does not own the client's lifecycle: the
// caller supplies a connected *clientv3.Client and closes it on shutdown.
type Store struct {
	cli *clientv3.Client
}

// NewStore returns a Store backed by cli. cli must be non-nil and connected.
func NewStore(cli *clientv3.Client) *Store {
	return &Store{cli: cli}
}

// RecordIssued persists r under PrefixIssued + r.SerialHex. Re-recording the
// same serial overwrites the prior record.
func (s *Store) RecordIssued(ctx context.Context, r IssuedRecord) error {
	buf, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("revocation: RecordIssued: marshal: %w", err)
	}
	if _, err := s.cli.Put(ctx, etcd.PrefixIssued+r.SerialHex, string(buf)); err != nil {
		return fmt.Errorf("revocation: RecordIssued: put: %w", err)
	}
	return nil
}

// GetIssued returns the issued record for serialHex. ok is false when no
// record exists.
func (s *Store) GetIssued(ctx context.Context, serialHex string) (IssuedRecord, bool, error) {
	return getRecord[IssuedRecord](ctx, s.cli, etcd.PrefixIssued+serialHex)
}

// ListIssued returns every issued record.
func (s *Store) ListIssued(ctx context.Context) ([]IssuedRecord, error) {
	return listRecords[IssuedRecord](ctx, s.cli, etcd.PrefixIssued)
}

// GetRevoked returns the revoked record for serialHex. ok is false when no
// record exists.
func (s *Store) GetRevoked(ctx context.Context, serialHex string) (RevokedRecord, bool, error) {
	return getRecord[RevokedRecord](ctx, s.cli, etcd.PrefixRevoked+serialHex)
}

// ListRevoked returns every revoked record.
func (s *Store) ListRevoked(ctx context.Context) ([]RevokedRecord, error) {
	return listRecords[RevokedRecord](ctx, s.cli, etcd.PrefixRevoked)
}

// Revoke marks serialHex revoked at time at with the given RFC 5280 reason
// code. It is idempotent: a serial already revoked returns the existing
// record unchanged. It returns ErrNotIssued when the serial is absent from
// the issued set (a node only revokes what it issued). The record is written
// in a single transaction guarded on the issued key existing and the revoked
// key not yet existing, so a concurrent second Revoke does not overwrite.
func (s *Store) Revoke(ctx context.Context, serialHex string, reason int, at time.Time) (RevokedRecord, error) {
	rec := RevokedRecord{SerialHex: serialHex, RevokedAt: at, ReasonCode: reason}
	buf, err := json.Marshal(rec)
	if err != nil {
		return RevokedRecord{}, fmt.Errorf("revocation: Revoke: marshal: %w", err)
	}
	issuedKey := etcd.PrefixIssued + serialHex
	revokedKey := etcd.PrefixRevoked + serialHex

	resp, err := s.cli.Txn(ctx).
		If(
			clientv3.Compare(clientv3.CreateRevision(issuedKey), "!=", 0),
			clientv3.Compare(clientv3.CreateRevision(revokedKey), "=", 0),
		).
		Then(clientv3.OpPut(revokedKey, string(buf))).
		Commit()
	if err != nil {
		return RevokedRecord{}, fmt.Errorf("revocation: Revoke: txn: %w", err)
	}
	if resp.Succeeded {
		return rec, nil
	}

	// The guard failed: either the serial was never issued, or it is already
	// revoked. Distinguish the two.
	existing, ok, err := s.GetRevoked(ctx, serialHex)
	if err != nil {
		return RevokedRecord{}, err
	}
	if ok {
		// Already revoked: return the original record unchanged.
		return existing, nil
	}
	return RevokedRecord{}, ErrNotIssued
}

// NextCRLNumber atomically increments and returns the monotonic CRL sequence
// number stored at etcd KeyCRLNumber. It retries on a concurrent update; on a
// single-writer node the loop runs at most twice.
func (s *Store) NextCRLNumber(ctx context.Context) (uint64, error) {
	for {
		resp, err := s.cli.Get(ctx, etcd.KeyCRLNumber)
		if err != nil {
			return 0, fmt.Errorf("revocation: NextCRLNumber: get: %w", err)
		}
		var n uint64
		var rev int64
		if len(resp.Kvs) > 0 {
			n, err = strconv.ParseUint(string(resp.Kvs[0].Value), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("revocation: NextCRLNumber: parse %q: %w", resp.Kvs[0].Value, err)
			}
			rev = resp.Kvs[0].ModRevision
		}
		next := n + 1
		txn, err := s.cli.Txn(ctx).
			If(clientv3.Compare(clientv3.ModRevision(etcd.KeyCRLNumber), "=", rev)).
			Then(clientv3.OpPut(etcd.KeyCRLNumber, strconv.FormatUint(next, 10))).
			Commit()
		if err != nil {
			return 0, fmt.Errorf("revocation: NextCRLNumber: txn: %w", err)
		}
		if txn.Succeeded {
			return next, nil
		}
		// Lost the race; retry with the fresh revision.
	}
}

// getRecord fetches a single JSON record at key. ok is false when the key
// does not exist.
func getRecord[T any](ctx context.Context, cli *clientv3.Client, key string) (T, bool, error) {
	var zero T
	resp, err := cli.Get(ctx, key)
	if err != nil {
		return zero, false, fmt.Errorf("revocation: get %q: %w", key, err)
	}
	if len(resp.Kvs) == 0 {
		return zero, false, nil
	}
	var rec T
	if err := json.Unmarshal(resp.Kvs[0].Value, &rec); err != nil {
		return zero, false, fmt.Errorf("revocation: unmarshal %q: %w", key, err)
	}
	return rec, true, nil
}

// listRecords fetches every JSON record under prefix.
func listRecords[T any](ctx context.Context, cli *clientv3.Client, prefix string) ([]T, error) {
	resp, err := cli.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("revocation: list %q: %w", prefix, err)
	}
	out := make([]T, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var rec T
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			return nil, fmt.Errorf("revocation: unmarshal %q: %w", kv.Key, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
