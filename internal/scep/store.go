package scep

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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// Challenge is a stored one-time challenge. It holds the SHA-256 of the
// challenge, never the challenge itself.
type Challenge struct {
	ID          string    `json:"id"`
	DigestHex   string    `json:"digest_hex"`
	Profile     string    `json:"profile"`
	BoundNames  []string  `json:"bound_names,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedByCN string    `json:"created_by_cn,omitempty"`
}

// Transaction states.
const (
	// txProcessing is a request being handled right now; a concurrent
	// retransmit is told PENDING and polls.
	txProcessing = "processing"
	txIssued     = "issued"
	txPending    = "pending"
	txRejected   = "rejected"
)

// Transaction records one SCEP transactionID, so a retransmitted request or a
// CertPoll gets the same answer as the original.
type Transaction struct {
	TransactionID string `json:"transaction_id"`
	State         string `json:"state"`
	// KeyID is the SHA-256 of the requested SubjectPublicKeyInfo: a
	// retransmit must ask for the same key.
	KeyID string `json:"key_id"`
	// SignerKeyID is the SHA-256 of the request signer's public key: a
	// CertPoll must be signed by the same key.
	SignerKeyID  string      `json:"signer_key_id"`
	MessageType  MessageType `json:"message_type"`
	Profile      string      `json:"profile"`
	SerialHex    string      `json:"serial_hex,omitempty"`
	EnrollmentID string      `json:"enrollment_id,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

// Enrollment is an initial enrolment held for an admin decision.
type Enrollment struct {
	ID            string    `json:"id"`
	TransactionID string    `json:"transaction_id"`
	Profile       string    `json:"profile"`
	SubjectDN     string    `json:"subject_dn"`
	Names         []string  `json:"names"`
	KeyAlg        string    `json:"key_alg"`
	CSRDER        []byte    `json:"csr_der"`
	ChallengeID   string    `json:"challenge_id"`
	ReceivedAt    time.Time `json:"received_at"`
}

// storedRA is one persisted RA certificate and its key.
type storedRA struct {
	CertDER  []byte `json:"cert_der"`
	KeyPKCS8 []byte `json:"key_pkcs8"`
}

// Store persists SCEP state in the node's embedded etcd, which lives on the
// encrypted state partition.
type Store struct {
	cli *clientv3.Client
}

// NewStore returns a Store backed by cli.
func NewStore(cli *clientv3.Client) *Store {
	return &Store{cli: cli}
}

func transactionKey(tid string) string {
	sum := sha256.Sum256([]byte(tid))
	return etcd.PrefixSCEPTransactions + hex.EncodeToString(sum[:])
}

// PutChallenge stores c under a lease of ttl, so it expires unused without a
// sweeper.
func (s *Store) PutChallenge(ctx context.Context, c Challenge, ttl time.Duration) error {
	secs := int64(ttl / time.Second)
	if secs < 1 {
		secs = 1
	}
	lease, err := s.cli.Grant(ctx, secs)
	if err != nil {
		return fmt.Errorf("scep: PutChallenge: grant lease: %w", err)
	}
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("scep: PutChallenge: marshal: %w", err)
	}
	digestKey := etcd.PrefixSCEPChallengeDigests + c.DigestHex
	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(digestKey), "=", 0)).
		Then(
			clientv3.OpPut(etcd.PrefixSCEPChallenges+c.ID, string(buf), clientv3.WithLease(lease.ID)),
			clientv3.OpPut(digestKey, c.ID, clientv3.WithLease(lease.ID)),
		).Commit()
	if err != nil {
		return fmt.Errorf("scep: PutChallenge: txn: %w", err)
	}
	if !resp.Succeeded {
		return errors.New("scep: PutChallenge: a challenge with the same digest already exists")
	}
	return nil
}

// ConsumeChallenge atomically removes the challenge whose SHA-256 is
// digestHex and returns it. ok is false when no such challenge exists, which
// covers never minted, already consumed, revoked and lease-expired alike. The
// delete is the check, so two requests presenting one challenge cannot both
// have it.
func (s *Store) ConsumeChallenge(ctx context.Context, digestHex string) (Challenge, bool, error) {
	digestKey := etcd.PrefixSCEPChallengeDigests + digestHex
	idResp, err := s.cli.Get(ctx, digestKey)
	if err != nil {
		return Challenge{}, false, fmt.Errorf("scep: ConsumeChallenge: get: %w", err)
	}
	if len(idResp.Kvs) == 0 {
		return Challenge{}, false, nil
	}
	chKey := etcd.PrefixSCEPChallenges + string(idResp.Kvs[0].Value)
	resp, err := s.cli.Txn(ctx).
		If(
			clientv3.Compare(clientv3.CreateRevision(digestKey), ">", 0),
			clientv3.Compare(clientv3.CreateRevision(chKey), ">", 0),
		).
		Then(clientv3.OpGet(chKey), clientv3.OpDelete(chKey), clientv3.OpDelete(digestKey)).
		Commit()
	if err != nil {
		return Challenge{}, false, fmt.Errorf("scep: ConsumeChallenge: txn: %w", err)
	}
	if !resp.Succeeded {
		return Challenge{}, false, nil
	}
	kvs := resp.Responses[0].GetResponseRange().GetKvs()
	if len(kvs) == 0 {
		return Challenge{}, false, nil
	}
	var c Challenge
	if err := json.Unmarshal(kvs[0].Value, &c); err != nil {
		return Challenge{}, false, fmt.Errorf("scep: ConsumeChallenge: unmarshal: %w", err)
	}
	return c, true, nil
}

// ListChallenges returns every stored challenge, soonest to expire first.
func (s *Store) ListChallenges(ctx context.Context) ([]Challenge, error) {
	out, err := listJSON[Challenge](ctx, s.cli, etcd.PrefixSCEPChallenges)
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out, nil
}

// DeleteChallenge removes the challenge with the given ID and returns it; ok
// is false when there is none.
func (s *Store) DeleteChallenge(ctx context.Context, id string) (Challenge, bool, error) {
	chKey := etcd.PrefixSCEPChallenges + id
	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(chKey), ">", 0)).
		Then(clientv3.OpGet(chKey), clientv3.OpDelete(chKey)).
		Commit()
	if err != nil {
		return Challenge{}, false, fmt.Errorf("scep: DeleteChallenge: txn: %w", err)
	}
	if !resp.Succeeded {
		return Challenge{}, false, nil
	}
	var c Challenge
	if err := json.Unmarshal(resp.Responses[0].GetResponseRange().GetKvs()[0].Value, &c); err != nil {
		return Challenge{}, false, fmt.Errorf("scep: DeleteChallenge: unmarshal: %w", err)
	}
	if _, err := s.cli.Delete(ctx, etcd.PrefixSCEPChallengeDigests+c.DigestHex); err != nil {
		return Challenge{}, false, fmt.Errorf("scep: DeleteChallenge: delete the digest index: %w", err)
	}
	return c, true, nil
}

// ClaimTransaction writes t unless its transactionID is already recorded.
// claimed reports whether t was written; when it was not, existing is the
// record already there.
func (s *Store) ClaimTransaction(ctx context.Context, t Transaction) (existing Transaction, claimed bool, err error) {
	buf, err := json.Marshal(t)
	if err != nil {
		return Transaction{}, false, fmt.Errorf("scep: ClaimTransaction: marshal: %w", err)
	}
	key := transactionKey(t.TransactionID)
	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
		Then(clientv3.OpPut(key, string(buf))).
		Else(clientv3.OpGet(key)).
		Commit()
	if err != nil {
		return Transaction{}, false, fmt.Errorf("scep: ClaimTransaction: txn: %w", err)
	}
	if resp.Succeeded {
		return Transaction{}, true, nil
	}
	if err := json.Unmarshal(resp.Responses[0].GetResponseRange().GetKvs()[0].Value, &existing); err != nil {
		return Transaction{}, false, fmt.Errorf("scep: ClaimTransaction: unmarshal: %w", err)
	}
	return existing, false, nil
}

// GetTransaction returns the record for a transactionID.
func (s *Store) GetTransaction(ctx context.Context, tid string) (Transaction, bool, error) {
	return getJSON[Transaction](ctx, s.cli, transactionKey(tid))
}

// PutTransaction writes t.
func (s *Store) PutTransaction(ctx context.Context, t Transaction) error {
	return putJSON(ctx, s.cli, transactionKey(t.TransactionID), t)
}

// DeleteTransaction removes the record for a transactionID. A request that
// failed is not remembered, so the device can try again with a new challenge.
func (s *Store) DeleteTransaction(ctx context.Context, tid string) error {
	if _, err := s.cli.Delete(ctx, transactionKey(tid)); err != nil {
		return fmt.Errorf("scep: DeleteTransaction: %w", err)
	}
	return nil
}

// PutEnrollment writes e.
func (s *Store) PutEnrollment(ctx context.Context, e Enrollment) error {
	return putJSON(ctx, s.cli, etcd.PrefixSCEPEnrollments+e.ID, e)
}

// GetEnrollment returns the waiting enrolment with the given ID.
func (s *Store) GetEnrollment(ctx context.Context, id string) (Enrollment, bool, error) {
	return getJSON[Enrollment](ctx, s.cli, etcd.PrefixSCEPEnrollments+id)
}

// ListEnrollments returns the waiting enrolments, oldest first.
func (s *Store) ListEnrollments(ctx context.Context) ([]Enrollment, error) {
	out, err := listJSON[Enrollment](ctx, s.cli, etcd.PrefixSCEPEnrollments)
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt.Before(out[j].ReceivedAt) })
	return out, nil
}

// FinishEnrollment takes an enrolment out of the queue and records its
// transaction's outcome in one step, so a poll never sees one without the
// other.
func (s *Store) FinishEnrollment(ctx context.Context, id string, t Transaction) error {
	buf, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("scep: FinishEnrollment: marshal: %w", err)
	}
	if _, err := s.cli.Txn(ctx).Then(
		clientv3.OpDelete(etcd.PrefixSCEPEnrollments+id),
		clientv3.OpPut(transactionKey(t.TransactionID), string(buf)),
	).Commit(); err != nil {
		return fmt.Errorf("scep: FinishEnrollment: txn: %w", err)
	}
	return nil
}

func (s *Store) listRAs(ctx context.Context) ([]storedRA, error) {
	return listJSON[storedRA](ctx, s.cli, etcd.PrefixSCEPRA)
}

func (s *Store) putRA(ctx context.Context, serialHex string, r storedRA) error {
	return putJSON(ctx, s.cli, etcd.PrefixSCEPRA+serialHex, r)
}

func (s *Store) deleteRA(ctx context.Context, serialHex string) error {
	if _, err := s.cli.Delete(ctx, etcd.PrefixSCEPRA+serialHex); err != nil {
		return fmt.Errorf("scep: delete RA %s: %w", serialHex, err)
	}
	return nil
}

func putJSON[T any](ctx context.Context, cli *clientv3.Client, key string, v T) error {
	buf, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("scep: marshal %s: %w", key, err)
	}
	if _, err := cli.Put(ctx, key, string(buf)); err != nil {
		return fmt.Errorf("scep: put %s: %w", key, err)
	}
	return nil
}

func getJSON[T any](ctx context.Context, cli *clientv3.Client, key string) (T, bool, error) {
	var out T
	resp, err := cli.Get(ctx, key)
	if err != nil {
		return out, false, fmt.Errorf("scep: get %s: %w", key, err)
	}
	if len(resp.Kvs) == 0 {
		return out, false, nil
	}
	if err := json.Unmarshal(resp.Kvs[0].Value, &out); err != nil {
		return out, false, fmt.Errorf("scep: unmarshal %s: %w", key, err)
	}
	return out, true, nil
}

func listJSON[T any](ctx context.Context, cli *clientv3.Client, prefix string) ([]T, error) {
	resp, err := cli.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("scep: list %s: %w", prefix, err)
	}
	out := make([]T, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var v T
		if err := json.Unmarshal(kv.Value, &v); err != nil {
			return nil, fmt.Errorf("scep: unmarshal %s: %w", kv.Key, err)
		}
		out = append(out, v)
	}
	return out, nil
}
