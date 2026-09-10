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
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// ErrNotFound is returned by the Store getters when a record is absent. The
// handlers translate it to the RFC 8555 problem appropriate to the resource,
// which is why it is a sentinel rather than a Problem: the store has no
// opinion about whether a missing order is a 404 or a 403.
var ErrNotFound = errors.New("acme: record not found")

// Account is the stored ACME account. The account key is held as a public JWK
// only; there is never private material here.
type Account struct {
	ID            string    `json:"id"`
	Status        string    `json:"status"`
	Contact       []string  `json:"contact,omitempty"`
	KeyThumbprint string    `json:"key_thumbprint"`
	Key           JWK       `json:"key"`
	EABKeyID      string    `json:"eab_key_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Order is the stored ACME order.
type Order struct {
	ID          string       `json:"id"`
	AccountID   string       `json:"account_id"`
	Status      string       `json:"status"`
	Expires     time.Time    `json:"expires"`
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   time.Time    `json:"not_before,omitempty"`
	NotAfter    time.Time    `json:"not_after,omitempty"`
	AuthzIDs    []string     `json:"authz_ids"`
	CertID      string       `json:"cert_id,omitempty"`
	Error       *Problem     `json:"error,omitempty"`
}

// Authorization is the stored ACME authorization. It carries its single
// http-01 challenge inline: with one challenge type there is nothing for a
// separate record to hold, and keeping them together makes the authz status
// and the challenge status impossible to write apart.
type Authorization struct {
	ID              string     `json:"id"`
	AccountID       string     `json:"account_id"`
	OrderID         string     `json:"order_id"`
	Status          string     `json:"status"`
	Expires         time.Time  `json:"expires"`
	Identifier      Identifier `json:"identifier"`
	Token           string     `json:"token"`
	ChallengeStatus string     `json:"challenge_status"`
	Validated       time.Time  `json:"validated,omitempty"`
	Error           *Problem   `json:"error,omitempty"`
}

// CertificateRecord is the ACME-facing handle on an issued chain. The
// authoritative issuance record still lives in the revocation issued set
// under etcd.PrefixIssued; this exists so a certificate URL can be served
// without reconstructing the chain, and so revoke-cert can check that the
// account asking is the account that ordered it.
type CertificateRecord struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	OrderID   string    `json:"order_id"`
	SerialHex string    `json:"serial_hex"`
	ChainPEM  string    `json:"chain_pem"`
	IssuedAt  time.Time `json:"issued_at"`
}

// Store is the typed accessor over ACME state in the embedded etcd datastore.
// Like revocation.Store it does not own the client's lifecycle: the caller
// supplies a connected *clientv3.Client and closes it on shutdown.
type Store struct {
	cli *clientv3.Client
}

// NewStore returns a Store backed by cli. cli must be non-nil and connected.
func NewStore(cli *clientv3.Client) *Store {
	return &Store{cli: cli}
}

// NewID returns a random 128-bit URL-safe identifier used for account, order,
// authorization and certificate IDs. These appear in URLs and must be
// unguessable: a POST-as-GET is authorized by the account signature, but an ID
// that could be enumerated would still leak the shape of the deployment.
func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("acme: NewID: rand: %w", err)
	}
	return b64.EncodeToString(buf), nil
}

// NewToken returns a challenge token. RFC 8555 section 8.3 requires at least
// 128 bits of entropy; 256 costs nothing here.
func NewToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("acme: NewToken: rand: %w", err)
	}
	return b64.EncodeToString(buf), nil
}

// PutAccount writes a, and indexes it by key thumbprint so a JWS carrying a
// bare jwk resolves to the same account on a repeat new-account.
func (s *Store) PutAccount(ctx context.Context, a Account) error {
	buf, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("acme: PutAccount: marshal: %w", err)
	}
	// Both writes go in one transaction so an account is never reachable by
	// ID without also being reachable by thumbprint: a half-written account
	// would make a repeat new-account mint a duplicate.
	_, err = s.cli.Txn(ctx).Then(
		clientv3.OpPut(etcd.PrefixACMEAccounts+a.ID, string(buf)),
		clientv3.OpPut(etcd.PrefixACMEAccountKeys+a.KeyThumbprint, a.ID),
	).Commit()
	if err != nil {
		return fmt.Errorf("acme: PutAccount: txn: %w", err)
	}
	return nil
}

// GetAccount returns the account with the given ID.
func (s *Store) GetAccount(ctx context.Context, id string) (Account, error) {
	return getJSON[Account](ctx, s.cli, etcd.PrefixACMEAccounts+id)
}

// AccountByThumbprint returns the account registered with the given RFC 7638
// key thumbprint.
func (s *Store) AccountByThumbprint(ctx context.Context, thumbprint string) (Account, error) {
	resp, err := s.cli.Get(ctx, etcd.PrefixACMEAccountKeys+thumbprint)
	if err != nil {
		return Account{}, fmt.Errorf("acme: AccountByThumbprint: get index: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return Account{}, ErrNotFound
	}
	return s.GetAccount(ctx, string(resp.Kvs[0].Value))
}

// PutOrder writes o and indexes it under its account for the orders list.
func (s *Store) PutOrder(ctx context.Context, o Order) error {
	buf, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("acme: PutOrder: marshal: %w", err)
	}
	_, err = s.cli.Txn(ctx).Then(
		clientv3.OpPut(etcd.PrefixACMEOrders+o.ID, string(buf)),
		clientv3.OpPut(etcd.PrefixACMEAccountOrders+o.AccountID+"/"+o.ID, ""),
	).Commit()
	if err != nil {
		return fmt.Errorf("acme: PutOrder: txn: %w", err)
	}
	return nil
}

// GetOrder returns the order with the given ID.
func (s *Store) GetOrder(ctx context.Context, id string) (Order, error) {
	o, _, err := s.GetOrderRev(ctx, id)
	return o, err
}

// GetOrderRev returns the order with the given ID together with the etcd
// revision it was read at, for use with PutOrderIfUnchanged.
func (s *Store) GetOrderRev(ctx context.Context, id string) (Order, int64, error) {
	key := etcd.PrefixACMEOrders + id
	resp, err := s.cli.Get(ctx, key)
	if err != nil {
		return Order{}, 0, fmt.Errorf("acme: GetOrderRev: get: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return Order{}, 0, ErrNotFound
	}
	var o Order
	if err := json.Unmarshal(resp.Kvs[0].Value, &o); err != nil {
		return Order{}, 0, fmt.Errorf("acme: GetOrderRev: unmarshal: %w", err)
	}
	return o, resp.Kvs[0].ModRevision, nil
}

// PutOrderIfUnchanged writes o only if its key is still at rev, and reports
// whether the write happened. It is the guard on finalize: two clients (or
// one client retrying after a timeout) racing to finalize the same ready
// order would otherwise both pass the status check and both be issued a
// certificate. The loser of the compare sees the order already moved on.
func (s *Store) PutOrderIfUnchanged(ctx context.Context, o Order, rev int64) (bool, error) {
	buf, err := json.Marshal(o)
	if err != nil {
		return false, fmt.Errorf("acme: PutOrderIfUnchanged: marshal: %w", err)
	}
	key := etcd.PrefixACMEOrders + o.ID
	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", rev)).
		Then(clientv3.OpPut(key, string(buf))).
		Commit()
	if err != nil {
		return false, fmt.Errorf("acme: PutOrderIfUnchanged: txn: %w", err)
	}
	return resp.Succeeded, nil
}

// ListOrderIDs returns the IDs of every order belonging to accountID, oldest
// key first (etcd returns a prefix range in key order).
func (s *Store) ListOrderIDs(ctx context.Context, accountID string) ([]string, error) {
	prefix := etcd.PrefixACMEAccountOrders + accountID + "/"
	resp, err := s.cli.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("acme: ListOrderIDs: get: %w", err)
	}
	out := make([]string, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		out = append(out, string(kv.Key)[len(prefix):])
	}
	return out, nil
}

// PutAuthorization writes a.
func (s *Store) PutAuthorization(ctx context.Context, a Authorization) error {
	return putJSON(ctx, s.cli, etcd.PrefixACMEAuthz+a.ID, a, "PutAuthorization")
}

// GetAuthorization returns the authorization with the given ID.
func (s *Store) GetAuthorization(ctx context.Context, id string) (Authorization, error) {
	return getJSON[Authorization](ctx, s.cli, etcd.PrefixACMEAuthz+id)
}

// PutCertificate writes c.
func (s *Store) PutCertificate(ctx context.Context, c CertificateRecord) error {
	return putJSON(ctx, s.cli, etcd.PrefixACMECerts+c.ID, c, "PutCertificate")
}

// GetCertificate returns the certificate record with the given ID.
func (s *Store) GetCertificate(ctx context.Context, id string) (CertificateRecord, error) {
	return getJSON[CertificateRecord](ctx, s.cli, etcd.PrefixACMECerts+id)
}

// CertificateBySerial scans the certificate records for one matching
// serialHex. revoke-cert arrives with a certificate, not a URL, so the serial
// is the only handle the client can offer. The scan is linear in the number of
// ACME-issued certificates, which is acceptable for the revocation path: it is
// rare, and the alternative is a second index to keep consistent.
func (s *Store) CertificateBySerial(ctx context.Context, serialHex string) (CertificateRecord, error) {
	resp, err := s.cli.Get(ctx, etcd.PrefixACMECerts, clientv3.WithPrefix())
	if err != nil {
		return CertificateRecord{}, fmt.Errorf("acme: CertificateBySerial: get: %w", err)
	}
	for _, kv := range resp.Kvs {
		var rec CertificateRecord
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			return CertificateRecord{}, fmt.Errorf("acme: CertificateBySerial: unmarshal %s: %w", kv.Key, err)
		}
		if rec.SerialHex == serialHex {
			return rec, nil
		}
	}
	return CertificateRecord{}, ErrNotFound
}

// NewNonce mints an anti-replay nonce and stores it under a lease of ttl, so
// an unused nonce expires on its own rather than accumulating.
func (s *Store) NewNonce(ctx context.Context, ttl time.Duration) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("acme: NewNonce: rand: %w", err)
	}
	nonce := b64.EncodeToString(buf)

	lease, err := s.cli.Grant(ctx, int64(ttl.Seconds()))
	if err != nil {
		return "", fmt.Errorf("acme: NewNonce: grant lease: %w", err)
	}
	if _, err := s.cli.Put(ctx, etcd.PrefixACMENonces+nonce, "", clientv3.WithLease(lease.ID)); err != nil {
		return "", fmt.Errorf("acme: NewNonce: put: %w", err)
	}
	return nonce, nil
}

// ConsumeNonce atomically removes nonce and reports whether it was present.
// A nonce is single-use: the delete is the check, so two concurrent requests
// carrying the same nonce cannot both succeed.
func (s *Store) ConsumeNonce(ctx context.Context, nonce string) (bool, error) {
	resp, err := s.cli.Delete(ctx, etcd.PrefixACMENonces+nonce)
	if err != nil {
		return false, fmt.Errorf("acme: ConsumeNonce: delete: %w", err)
	}
	return resp.Deleted == 1, nil
}

// putJSON marshals v and writes it at key. op names the calling method for
// the error message.
func putJSON[T any](ctx context.Context, cli *clientv3.Client, key string, v T, op string) error {
	buf, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("acme: %s: marshal: %w", op, err)
	}
	if _, err := cli.Put(ctx, key, string(buf)); err != nil {
		return fmt.Errorf("acme: %s: put: %w", op, err)
	}
	return nil
}

// getJSON reads key and unmarshals it into T, returning ErrNotFound when the
// key is absent.
func getJSON[T any](ctx context.Context, cli *clientv3.Client, key string) (T, error) {
	var zero T
	resp, err := cli.Get(ctx, key)
	if err != nil {
		return zero, fmt.Errorf("acme: get %q: %w", key, err)
	}
	if len(resp.Kvs) == 0 {
		return zero, ErrNotFound
	}
	var out T
	if err := json.Unmarshal(resp.Kvs[0].Value, &out); err != nil {
		return zero, fmt.Errorf("acme: unmarshal %q: %w", key, err)
	}
	return out, nil
}
