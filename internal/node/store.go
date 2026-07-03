package node

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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// Phase is the node lifecycle phase persisted at etcd KeyStatePhase. It is
// the single source of truth for where in the boot/ceremony flow the node
// is.
type Phase string

const (
	// PhaseFormatting: the state partition is being formatted (first boot).
	PhaseFormatting Phase = "formatting"
	// PhaseUnsealed: the state partition is open but no identity exists yet.
	PhaseUnsealed Phase = "unsealed"
	// PhaseNoIdentity: ready to run the first-boot ceremony.
	PhaseNoIdentity Phase = "no-identity"
	// PhaseCeremonyInProgress: a ceremony started but has not committed.
	PhaseCeremonyInProgress Phase = "ceremony-in-progress"
	// PhaseIdentityEstablished: steady state — the Root identity exists.
	PhaseIdentityEstablished Phase = "identity-established"
)

// IdentityState maps a Phase to the proto IdentityState reported by
// GetStatus.
func (p Phase) IdentityState() cryptosv1.IdentityState {
	switch p {
	case PhaseIdentityEstablished:
		return cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED
	case PhaseCeremonyInProgress:
		return cryptosv1.IdentityState_IDENTITY_STATE_CEREMONY_IN_PROGRESS
	default:
		return cryptosv1.IdentityState_IDENTITY_STATE_NONE
	}
}

// ErrNoIdentity is returned by Identity when the Root identity has not
// been established yet.
var ErrNoIdentity = errors.New("node: no identity established")

// ErrIdentityExists is returned by CommitFirstCeremony when an identity
// already exists, so the guarded transaction did not apply.
var ErrIdentityExists = errors.New("node: identity already exists")

// Store is the typed accessor over the embedded etcd datastore. It is
// the only place outside internal/storage/etcd that reads or writes
// CryptOS state keys; callers go through these methods rather than
// hardcoding paths.
//
// Store does not own the client's lifecycle — the caller (PID 1)
// supplies a connected *clientv3.Client and closes it on shutdown.
type Store struct {
	cli *clientv3.Client
}

// New returns a Store backed by cli. cli must be non-nil and connected.
func New(cli *clientv3.Client) (*Store, error) {
	if cli == nil {
		return nil, errors.New("node: New: nil etcd client")
	}
	return &Store{cli: cli}, nil
}

// Phase reads the current lifecycle phase. A missing key returns
// PhaseNoIdentity (a freshly-initialized store with no phase written
// yet is, semantically, awaiting a ceremony).
func (s *Store) Phase(ctx context.Context) (Phase, error) {
	v, ok, err := s.getString(ctx, etcd.KeyStatePhase)
	if err != nil {
		return "", err
	}
	if !ok {
		return PhaseNoIdentity, nil
	}
	return Phase(v), nil
}

// SetPhase writes the lifecycle phase.
func (s *Store) SetPhase(ctx context.Context, p Phase) error {
	if _, err := s.cli.Put(ctx, etcd.KeyStatePhase, string(p)); err != nil {
		return fmt.Errorf("node: SetPhase: %w", err)
	}
	return nil
}

// BootCount reads the boot counter, defaulting to 0 when unset.
func (s *Store) BootCount(ctx context.Context) (uint64, error) {
	v, ok, err := s.getString(ctx, etcd.KeyBootCount)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("node: BootCount: parse %q: %w", v, err)
	}
	return n, nil
}

// IncrementBootCount atomically increments and returns the boot counter.
// It retries on a concurrent update; on a single-writer node the loop
// runs at most twice.
func (s *Store) IncrementBootCount(ctx context.Context) (uint64, error) {
	for {
		cur, ok, err := s.getKV(ctx, etcd.KeyBootCount)
		if err != nil {
			return 0, err
		}
		var n uint64
		var rev int64
		if ok {
			n, err = strconv.ParseUint(string(cur.Value), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("node: IncrementBootCount: parse %q: %w", cur.Value, err)
			}
			rev = cur.ModRevision
		}
		next := n + 1
		cmp := clientv3.Compare(clientv3.ModRevision(etcd.KeyBootCount), "=", rev)
		resp, err := s.cli.Txn(ctx).
			If(cmp).
			Then(clientv3.OpPut(etcd.KeyBootCount, strconv.FormatUint(next, 10))).
			Commit()
		if err != nil {
			return 0, fmt.Errorf("node: IncrementBootCount: %w", err)
		}
		if resp.Succeeded {
			return next, nil
		}
		// Lost the race; retry with the fresh revision.
	}
}

// HasIdentity reports whether the Root certificate has been committed.
func (s *Store) HasIdentity(ctx context.Context) (bool, error) {
	_, ok, err := s.getKV(ctx, etcd.KeyRootCert)
	return ok, err
}

// Identity returns the node's Identity (the Root cert chain). For a
// Phase 1 Root the chain has length 1. Returns ErrNoIdentity when the
// ceremony has not yet committed.
func (s *Store) Identity(ctx context.Context) (*cryptosv1.Identity, error) {
	kv, ok, err := s.getKV(ctx, etcd.KeyRootCert)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoIdentity
	}
	der := append([]byte(nil), kv.Value...)
	leaf := sha256.Sum256(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &cryptosv1.Identity{
		ChainDer:   [][]byte{der},
		ChainPem:   string(pemBytes),
		LeafSha256: leaf[:],
	}, nil
}

// AdminRecord is the persisted representation of a trusted administrator
// certificate stored under etcd PrefixAdmins.
type AdminRecord struct {
	SubjectDN string    `json:"subject_dn"`
	SHA256Hex string    `json:"sha256"`
	NotAfter  time.Time `json:"not_after"`
	CertPEM   string    `json:"cert_pem"`
}

func adminRecordFrom(a bootstrap.Admin) AdminRecord {
	return AdminRecord{
		SubjectDN: a.Subject,
		SHA256Hex: hex.EncodeToString(a.SHA256[:]),
		NotAfter:  a.NotAfter,
		CertPEM:   a.CertPEM,
	}
}

// FirstCeremonyCommit bundles every artifact written atomically at the
// end of the first-boot Root ceremony.
type FirstCeremonyCommit struct {
	// RootCertDER is the DER of the self-signed Root certificate.
	RootCertDER []byte
	// RootKeyBlob is the TPM-wrapped Root private key blob.
	RootKeyBlob []byte
	// RootKeyPublic is the TPM public blob for the Root key.
	RootKeyPublic []byte
	// ManifestID identifies the ceremony manifest (the etcd key suffix).
	ManifestID string
	// ManifestBytes is the serialized, signed Ceremony Manifest.
	ManifestBytes []byte
	// Admin is the administrator promoted to steady-state on completion.
	Admin bootstrap.Admin
}

func (c FirstCeremonyCommit) validate() error {
	switch {
	case len(c.RootCertDER) == 0:
		return errors.New("RootCertDER is empty")
	case len(c.RootKeyBlob) == 0:
		return errors.New("RootKeyBlob is empty")
	case len(c.RootKeyPublic) == 0:
		return errors.New("RootKeyPublic is empty")
	case c.ManifestID == "":
		return errors.New("ManifestID is empty")
	case len(c.ManifestBytes) == 0:
		return errors.New("ManifestBytes is empty")
	case c.Admin.SHA256 == [32]byte{}:
		return errors.New("admin record is empty")
	}
	return nil
}

// CommitFirstCeremony writes all identity-creating artifacts in a single
// etcd transaction guarded by "no current identity exists". On success
// the node transitions to PhaseIdentityEstablished. If an identity
// already exists the transaction does not apply and ErrIdentityExists is
// returned, which makes ceremony re-entry after a crash idempotent.
func (s *Store) CommitFirstCeremony(ctx context.Context, c FirstCeremonyCommit) error {
	if err := c.validate(); err != nil {
		return fmt.Errorf("node: CommitFirstCeremony: %w", err)
	}
	adminJSON, err := json.Marshal(adminRecordFrom(c.Admin))
	if err != nil {
		return fmt.Errorf("node: CommitFirstCeremony: marshal admin: %w", err)
	}
	adminKey := etcd.PrefixAdmins + hex.EncodeToString(c.Admin.SHA256[:])

	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(etcd.KeyRootCert), "=", 0)).
		Then(
			clientv3.OpPut(etcd.KeyRootCert, string(c.RootCertDER)),
			clientv3.OpPut(etcd.KeyRootKeyBlob, string(c.RootKeyBlob)),
			clientv3.OpPut(etcd.KeyRootKeyPublic, string(c.RootKeyPublic)),
			clientv3.OpPut(etcd.PrefixCeremonyManifests+c.ManifestID, string(c.ManifestBytes)),
			clientv3.OpPut(adminKey, string(adminJSON)),
			clientv3.OpPut(etcd.KeyStatePhase, string(PhaseIdentityEstablished)),
		).
		Commit()
	if err != nil {
		return fmt.Errorf("node: CommitFirstCeremony: txn: %w", err)
	}
	if !resp.Succeeded {
		return ErrIdentityExists
	}
	return nil
}

// RootKeyBlobs returns the stored TPM private + public blobs for the
// Root key, for loading the signer on a subsequent boot. ok is false
// when no identity has been committed.
func (s *Store) RootKeyBlobs(ctx context.Context) (private, public []byte, ok bool, err error) {
	privKV, okPriv, err := s.getKV(ctx, etcd.KeyRootKeyBlob)
	if err != nil {
		return nil, nil, false, err
	}
	pubKV, okPub, err := s.getKV(ctx, etcd.KeyRootKeyPublic)
	if err != nil {
		return nil, nil, false, err
	}
	if !okPriv || !okPub {
		return nil, nil, false, nil
	}
	return append([]byte(nil), privKV.Value...), append([]byte(nil), pubKV.Value...), true, nil
}

// getString returns the value at key as a string and whether it exists.
func (s *Store) getString(ctx context.Context, key string) (string, bool, error) {
	kv, ok, err := s.getKV(ctx, key)
	if err != nil || !ok {
		return "", ok, err
	}
	return string(kv.Value), true, nil
}

// getKV returns the single KV at key (exact match) and whether it exists.
func (s *Store) getKV(ctx context.Context, key string) (kv *kvPair, ok bool, err error) {
	resp, err := s.cli.Get(ctx, key)
	if err != nil {
		return nil, false, fmt.Errorf("node: get %q: %w", key, err)
	}
	if len(resp.Kvs) == 0 {
		return nil, false, nil
	}
	return &kvPair{Value: resp.Kvs[0].Value, ModRevision: resp.Kvs[0].ModRevision}, true, nil
}

// kvPair is the minimal slice of an etcd KV that Store needs.
type kvPair struct {
	Value       []byte
	ModRevision int64
}
