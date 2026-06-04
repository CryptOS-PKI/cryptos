package ceremony

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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// CeremonySignerLabel is the HKDF info parameter for deriving the
// ceremony manifest signing key. It is a distinct label from the audit
// signer so the two keys never collide, while sharing the same master
// state-partition seed.
const CeremonySignerLabel = "cryptos.dev/ceremony-signer/v1"

// SeedLength is the required length of the master seed (bytes).
const SeedLength = 32

// manifestVersion is the Phase 1 Ceremony Manifest schema version.
const manifestVersion = 1

// ceremonyKindRootFirstBoot is the manifest's ceremony_kind value for the
// Phase 1 first-boot Root ceremony.
const ceremonyKindRootFirstBoot = "root_first_boot"

// manifestSigAlg names the algorithm recorded in OperatorSignature.sig_alg.
const manifestSigAlg = "ed25519"

// TPM is the subset of *tpm.TPM the ceremony drives. Defined as an
// interface so tests can substitute a fake, though the production and
// test wiring both use a simulator- or device-backed *tpm.TPM.
type TPM interface {
	ProvisionSRK() error
	CreateKey(alg tpm.KeyAlgorithm) (*tpm.CreatedKey, error)
	LoadKey(private, public []byte) (*tpm.Key, error)
}

// Config holds the Engine's dependencies.
type Config struct {
	// TPM provisions the SRK and creates/loads the Root signing key.
	TPM TPM
	// Store persists ceremony output atomically.
	Store *node.Store
	// Trust is the loaded bootstrap admin credential used to authorize
	// the streaming caller and to promote the steady-state admin.
	Trust *bootstrap.Trust
	// Seed is the 32-byte master state-partition seed; the manifest
	// signing key is HKDF-derived from it.
	Seed []byte
}

// Engine runs the first-boot Root ceremony. It satisfies the
// grpc.Ceremony interface via Start.
type Engine struct {
	cfg    Config
	signer ed25519.PrivateKey
	now    func() time.Time
	newID  func() (string, error)

	// running serializes ceremonies: the gRPC server dispatches each RPC
	// on its own goroutine, but the ceremony drives the shared, single-
	// threaded TPM, so only one may run at a time.
	running sync.Mutex
}

// New constructs an Engine, deriving the manifest signing key from the
// master seed.
func New(cfg Config) (*Engine, error) {
	switch {
	case cfg.TPM == nil:
		return nil, errors.New("ceremony: New: TPM is required")
	case cfg.Store == nil:
		return nil, errors.New("ceremony: New: Store is required")
	case cfg.Trust == nil:
		return nil, errors.New("ceremony: New: Trust is required")
	}
	signer, err := deriveCeremonySigner(cfg.Seed)
	if err != nil {
		return nil, err
	}
	return &Engine{
		cfg:    cfg,
		signer: signer,
		now:    time.Now,
		newID:  newUUIDv4,
	}, nil
}

// PublicKey returns the manifest verifying key so operators can verify
// the signed manifest offline.
func (e *Engine) PublicKey() ed25519.PublicKey {
	return e.signer.Public().(ed25519.PublicKey)
}

// Start runs the ceremony to completion, streaming CeremonyEvents via
// send. It satisfies grpc.Ceremony. Errors carrying a gRPC status code
// are returned verbatim so the handler can preserve the code.
func (e *Engine) Start(ctx context.Context, req *cryptosv1.StartCeremonyRequest, send func(*cryptosv1.StartCeremonyResponse) error) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "ceremony: nil request")
	}
	if req.Kind != cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT &&
		req.Kind != cryptosv1.CeremonyKind_CEREMONY_KIND_UNSPECIFIED {
		return status.Errorf(codes.InvalidArgument, "ceremony: unsupported kind %v", req.Kind)
	}

	// Only one ceremony at a time — it drives the single-threaded TPM, and
	// two concurrent runs could both pass the no-identity check below.
	// Reject (don't queue) a second concurrent caller.
	if !e.running.TryLock() {
		return status.Error(codes.FailedPrecondition, "ceremony already in progress")
	}
	defer e.running.Unlock()

	// Step 1: authorize the caller. The presented bootstrap admin cert
	// (if any — the local UNIX socket has none) is promoted at the end.
	adminCert, err := authorizeCaller(ctx, e.cfg.Trust)
	if err != nil {
		return err
	}

	// Refuse to re-run once an identity exists.
	if ok, err := e.cfg.Store.HasIdentity(ctx); err != nil {
		return status.Errorf(codes.Internal, "ceremony: check identity: %v", err)
	} else if ok {
		return status.Error(codes.FailedPrecondition, "IDENTITY_EXISTS")
	}

	// Parse + validate the operator's machine config from the request.
	if len(req.MachineConfigYaml) == 0 {
		return status.Error(codes.InvalidArgument, "ceremony: machine_config_yaml is required")
	}
	cfg, err := config.Parse(req.MachineConfigYaml)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "ceremony: %v", err)
	}

	started := e.now().UTC().Truncate(time.Second)

	// Step 2: mark ceremony-in-progress, persist the config.
	if err := e.cfg.Store.SetPhase(ctx, node.PhaseCeremonyInProgress); err != nil {
		return status.Errorf(codes.Internal, "ceremony: set phase: %v", err)
	}
	if _, err := e.cfg.Store.PutCurrentConfig(ctx, req.MachineConfigYaml); err != nil {
		return status.Errorf(codes.Internal, "ceremony: persist config: %v", err)
	}

	// Steps 3–4: create the Root key inside the TPM.
	if err := e.cfg.TPM.ProvisionSRK(); err != nil {
		return status.Errorf(codes.Internal, "ceremony: provision SRK: %v", err)
	}
	created, err := e.cfg.TPM.CreateKey(tpm.AlgorithmECDSAP384)
	if err != nil {
		return status.Errorf(codes.Internal, "ceremony: create key: %v", err)
	}
	if err := e.emit(send, &cryptosv1.CeremonyEvent{
		Kind: cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_KEY_CREATED,
		Detail: &cryptosv1.CeremonyEvent_KeyCreated{KeyCreated: &cryptosv1.KeyCreated{
			TpmPublic:    created.Public,
			CreationData: created.CreationData,
		}},
	}); err != nil {
		return err
	}

	// Steps 5–6: self-sign the Root certificate via the TPM signer.
	key, err := e.cfg.TPM.LoadKey(created.Private, created.Public)
	if err != nil {
		return status.Errorf(codes.Internal, "ceremony: load key: %v", err)
	}
	defer func() { _ = key.Close() }()

	rootDER, _, err := ca.SelfSignRoot(ca.RootParams{
		Signer:            key,
		Subject:           subjectFromConfig(cfg),
		NotBefore:         started,
		NotAfter:          started.AddDate(int(cfg.PKI.RootValidityYears), 0, 0),
		PathLenConstraint: int(cfg.PKI.PathLenConstraint),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "ceremony: self-sign root: %v", err)
	}
	certSHA := sha256.Sum256(rootDER)
	if err := e.emit(send, &cryptosv1.CeremonyEvent{
		Kind:   cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_CERT_SIGNED,
		Detail: &cryptosv1.CeremonyEvent_CertSigned{CertSigned: &cryptosv1.CertSigned{CertSha256: certSHA[:]}},
	}); err != nil {
		return err
	}

	// Determine the admin to promote: prefer the cert actually presented
	// over mTLS; fall back to the configured trust.
	admin, err := e.resolveAdmin(adminCert)
	if err != nil {
		return status.Errorf(codes.Internal, "ceremony: resolve admin: %v", err)
	}

	// Step 7: build + sign the Ceremony Manifest.
	ceremonyID, err := e.newID()
	if err != nil {
		return status.Errorf(codes.Internal, "ceremony: id: %v", err)
	}
	manifestBytes, err := e.signedManifest(ceremonyID, started, e.now().UTC().Truncate(time.Second), created, certSHA[:], hex.EncodeToString(admin.SHA256[:]))
	if err != nil {
		return status.Errorf(codes.Internal, "ceremony: build manifest: %v", err)
	}

	// Step 9: commit everything atomically.
	commitErr := e.cfg.Store.CommitFirstCeremony(ctx, node.FirstCeremonyCommit{
		RootCertDER:   rootDER,
		RootKeyBlob:   created.Private,
		RootKeyPublic: created.Public,
		ManifestID:    ceremonyID,
		ManifestBytes: manifestBytes,
		Admin:         admin,
	})
	if errors.Is(commitErr, node.ErrIdentityExists) {
		return status.Error(codes.FailedPrecondition, "IDENTITY_EXISTS")
	}
	if commitErr != nil {
		return status.Errorf(codes.Internal, "ceremony: commit: %v", commitErr)
	}

	if err := e.emit(send, &cryptosv1.CeremonyEvent{
		Kind:   cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_MANIFEST_WRITTEN,
		Detail: &cryptosv1.CeremonyEvent_ManifestWritten{ManifestWritten: &cryptosv1.ManifestWritten{ManifestId: ceremonyID}},
	}); err != nil {
		return err
	}

	// Step 10: the bootstrap admin is now the steady-state admin
	// (full CSR-based rotation deferred to Phase 2).
	if err := e.emit(send, &cryptosv1.CeremonyEvent{
		Kind:   cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_ADMIN_ROTATED,
		Detail: &cryptosv1.CeremonyEvent_AdminRotated{AdminRotated: &cryptosv1.AdminRotated{AdminCertSha256: admin.SHA256[:]}},
	}); err != nil {
		return err
	}

	// Step 11: complete.
	return e.emit(send, &cryptosv1.CeremonyEvent{
		Kind:   cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
		Detail: &cryptosv1.CeremonyEvent_Complete{Complete: &cryptosv1.Complete{}},
	})
}

// resolveAdmin returns the Admin record to promote. The presented mTLS
// cert is preferred (it carries the full certificate even when the
// config only pinned a fingerprint); otherwise the configured trust is
// used, falling back to a fingerprint-only record for the local socket.
func (e *Engine) resolveAdmin(presented *x509.Certificate) (bootstrap.Admin, error) {
	if presented != nil {
		return bootstrap.AdminFromCertDER(presented.Raw)
	}
	if a, ok := e.cfg.Trust.Admin(); ok {
		return a, nil
	}
	return bootstrap.Admin{SHA256: e.cfg.Trust.Fingerprint()}, nil
}

// signedManifest builds the CeremonyManifest, signs the payload (with
// operator_signatures cleared) using the ceremony key, attaches the
// signature, and returns the deterministic-marshaled manifest.
func (e *Engine) signedManifest(ceremonyID string, started, completed time.Time, created *tpm.CreatedKey, certSHA []byte, signerID string) ([]byte, error) {
	m := &cryptosv1.CeremonyManifest{
		ManifestVersion: manifestVersion,
		CeremonyId:      ceremonyID,
		CeremonyKind:    ceremonyKindRootFirstBoot,
		NodeId:          e.cfg.nodeID(),
		StartedAt:       timestamppb.New(started),
		CompletedAt:     timestamppb.New(completed),
		KeyCreationAttestation: &cryptosv1.KeyCreationAttestation{
			TpmPublic:         created.Public,
			TpmCreationData:   created.CreationData,
			TpmCreationTicket: created.CreationTicket,
		},
		ResultingCertSha256: certSHA,
		PrevManifestSha256:  nil, // first ceremony — no predecessor
	}
	payload, err := marshalDeterministic(m)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(e.signer, payload)
	m.OperatorSignatures = []*cryptosv1.OperatorSignature{{
		SignerId: signerID,
		SigAlg:   manifestSigAlg,
		SigBytes: sig,
	}}
	return marshalDeterministic(m)
}

// nodeID returns the node identifier recorded in the manifest. Phase 1 is
// single-node, so a constant suffices; Phase 2 derives it per node.
func (c Config) nodeID() string {
	return "cryptos"
}

// emit sets the event timestamp and streams it.
func (e *Engine) emit(send func(*cryptosv1.StartCeremonyResponse) error, ev *cryptosv1.CeremonyEvent) error {
	ev.Ts = timestamppb.New(e.now())
	return send(&cryptosv1.StartCeremonyResponse{Event: ev})
}

// VerifyManifest verifies every operator signature on a marshaled
// CeremonyManifest against pub. It reconstructs the signed payload by
// clearing operator_signatures and re-marshaling deterministically.
func VerifyManifest(manifestBytes []byte, pub ed25519.PublicKey) error {
	var m cryptosv1.CeremonyManifest
	if err := proto.Unmarshal(manifestBytes, &m); err != nil {
		return fmt.Errorf("ceremony: VerifyManifest: unmarshal: %w", err)
	}
	if len(m.OperatorSignatures) == 0 {
		return errors.New("ceremony: VerifyManifest: no operator signatures")
	}
	clone := proto.Clone(&m).(*cryptosv1.CeremonyManifest)
	clone.OperatorSignatures = nil
	payload, err := marshalDeterministic(clone)
	if err != nil {
		return err
	}
	for i, s := range m.OperatorSignatures {
		if !ed25519.Verify(pub, payload, s.SigBytes) {
			return fmt.Errorf("ceremony: VerifyManifest: signature %d (signer %s) invalid", i, s.SignerId)
		}
	}
	return nil
}

// authorizeCaller extracts and validates the streaming caller's
// certificate. A connection with no TLS peer info is the local UNIX
// socket (root-only, no auth) and is trusted, returning a nil cert. A
// TLS connection must present the pinned bootstrap admin certificate.
func authorizeCaller(ctx context.Context, trust *bootstrap.Trust) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil, nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		// Non-TLS transport (local UNIX socket): trusted.
		return nil, nil
	}
	var leaf *x509.Certificate
	if vc := tlsInfo.State.VerifiedChains; len(vc) > 0 && len(vc[0]) > 0 {
		leaf = vc[0][0]
	} else if pc := tlsInfo.State.PeerCertificates; len(pc) > 0 {
		leaf = pc[0]
	}
	if leaf == nil {
		return nil, status.Error(codes.Unauthenticated, "ceremony: no client certificate presented")
	}
	if sha256.Sum256(leaf.Raw) != trust.Fingerprint() {
		return nil, status.Error(codes.PermissionDenied, "ceremony: client certificate is not the authorized bootstrap admin")
	}
	return leaf, nil
}

// subjectFromConfig builds the Root pkix.Name, omitting empty RDNs.
func subjectFromConfig(cfg *config.Config) pkix.Name {
	n := pkix.Name{CommonName: cfg.PKI.RootSubject.CommonName}
	if o := cfg.PKI.RootSubject.Organization; o != "" {
		n.Organization = []string{o}
	}
	if c := cfg.PKI.RootSubject.Country; c != "" {
		n.Country = []string{c}
	}
	return n
}

// deriveCeremonySigner derives the Ed25519 manifest signing key from the
// master seed via HKDF-SHA256 with the ceremony label.
func deriveCeremonySigner(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != SeedLength {
		return nil, fmt.Errorf("ceremony: seed must be %d bytes, got %d", SeedLength, len(seed))
	}
	r := hkdf.New(sha256.New, seed, nil, []byte(CeremonySignerLabel))
	out := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("ceremony: derive signer: %w", err)
	}
	return ed25519.NewKeyFromSeed(out), nil
}

// marshalDeterministic marshals m with deterministic field ordering so
// signatures over the bytes are reproducible.
func marshalDeterministic(m proto.Message) ([]byte, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("ceremony: marshal: %w", err)
	}
	return b, nil
}

// newUUIDv4 returns a random RFC 4122 version-4 UUID string using
// crypto/rand, avoiding a third-party UUID dependency.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("ceremony: uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
