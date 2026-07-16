// Package grpc serves the NodeService gRPC API defined in the api/
// module over mTLS TLS 1.3. Handlers route to small dependency
// interfaces so this package owns no business logic.
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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/backup"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
	"github.com/CryptOS-PKI/cryptos/internal/revocation"
)

// ErrNotExportable is returned by an Exporter when the node's CA key cannot be
// exported because it is TPM-backed (sealed and non-portable). The ExportCAKey
// handler maps it to codes.FailedPrecondition.
var ErrNotExportable = errors.New("grpc: CA key is non-exportable (TPM-backed)")

// ErrIdentityExists is returned by an Importer when the target node already
// has an identity, so the restore did not apply. The ImportCAKey handler maps
// it to codes.FailedPrecondition. The init-layer importer translates the
// store's node.ErrIdentityExists to this package-local sentinel so this
// package need not import internal/node (which would form a cycle with the
// node package's test-time interface assertions).
var ErrIdentityExists = errors.New("grpc: node already has an identity")

// Auditor records authenticated gRPC calls. Implementations are expected
// to fill in seq + prev_entry_sha256 themselves (see internal/audit).
type Auditor interface {
	Append(event *cryptosv1.AuditEvent) error
}

// Identity provides the node's current identity (certificate chain).
// Returns NoIdentity when GetIdentity is called before the first-boot
// ceremony has completed.
type Identity interface {
	Get(ctx context.Context) (*cryptosv1.Identity, error)
}

// StatusProvider provides the live NodeStatus.
type StatusProvider interface {
	Status(ctx context.Context) (*cryptosv1.NodeStatus, error)
}

// Ceremony drives a ceremony, emitting events on the supplied stream
// until completion (or error).
type Ceremony interface {
	Start(ctx context.Context, req *cryptosv1.StartCeremonyRequest, send func(*cryptosv1.StartCeremonyResponse) error) error
}

// ConfigStore applies and persists machine configurations.
type ConfigStore interface {
	Apply(ctx context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error)
}

// Installer performs a bare-metal install from a maintenance-mode ApplyConfig
// call. It is only consulted when ConfigStore is nil (maintenance mode): it
// validates the config, writes the UKI and staged config to the target disk,
// and returns RequiresReboot: true so the caller knows a reboot is imminent.
type Installer interface {
	Install(ctx context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error)
}

// Signer signs a CSR with the Root CA key. Only consulted in
// debug-tagged builds (see signcsr_debug.go).
type Signer interface {
	SignCSR(ctx context.Context, csrDER []byte, profile string) (certDER []byte, err error)
}

// SubordinateSigner signs a subordinate-CA CSR with this node's CA key,
// returning the resulting chain leaf-first (the child certificate followed by
// this node's issuer chain) in DER and PEM. It is wired on the mTLS and local
// servers of a running node; the maintenance servers leave it nil so
// SignSubordinateCSR is refused there. Implemented by *node.CASigner.
type SubordinateSigner interface {
	SignSubordinate(ctx context.Context, csrDER []byte, profileName string) (chainDER [][]byte, chainPEM string, err error)
}

// LeafSigner issues an end-entity certificate from a CSR with this node's CA
// key, returning the leaf DER. It is wired on the mTLS and local servers of a
// running node; the maintenance servers leave it nil so IssueLeaf is refused
// there. Implemented by *node.CASigner.
type LeafSigner interface {
	IssueLeaf(ctx context.Context, csrDER []byte, profileName string) (certDER []byte, err error)
}

// SubordinateEnroller drives the child side of the subordinate ceremony: it
// exposes the CSR this node staged on first boot and accepts the parent-signed
// certificate chain. AcceptCertificate owns the trust decision (it verifies the
// chain roots to the pinned parent anchor and that the leaf carries this node's
// staged key before committing); this package stays thin. It is wired on the
// mTLS and local servers of a subordinate node; a Root and the maintenance
// servers leave it nil so the RPCs return Unimplemented there. Implemented by
// *node.SubordinateEnroller.
type SubordinateEnroller interface {
	CSR(ctx context.Context) (csrDER []byte, err error)
	AcceptCertificate(ctx context.Context, chainDER [][]byte) (*cryptosv1.Identity, error)
}

// Rekeyer drives CA key rotation on an established subordinate: BeginRotation
// generates a new CA key and stages its CSR (the node keeps serving with its
// current key), and CompleteRotation verifies the parent-signed chain for the
// new key and atomically swaps to it. It is wired on the mTLS and local servers
// of an established subordinate node; a Root and the maintenance servers leave
// it nil so the RPCs return Unimplemented there. A no-identity node or any
// other precondition failure surfaces as FailedPrecondition from the impl.
// Implemented in internal/init over the RootKeyBackend, the store, and the
// pinned parent trust.
type Rekeyer interface {
	BeginRotation(ctx context.Context) (csrDER []byte, err error)
	CompleteRotation(ctx context.Context, chainDER [][]byte) (*cryptosv1.Identity, error)
}

// Revoker revokes a certificate this node issued and lists the issued and
// revoked inventories. It is wired on the mTLS and local servers of a running
// node; the maintenance servers leave it nil so the revocation RPCs return
// Unimplemented there. Revoke reports revocation.ErrNotIssued when the serial
// was never issued by this node (mapped to NotFound by the handler). Implemented
// in internal/init over a revocation.Store plus a CRL rebuild.
type Revoker interface {
	Revoke(ctx context.Context, serialHex string, reason int) (*cryptosv1.Revocation, error)
	ListIssued(ctx context.Context) ([]*cryptosv1.IssuedCert, error)
	ListRevocations(ctx context.Context) ([]*cryptosv1.Revocation, error)
}

// Exporter seals this node's software CA key + identity chain under an
// operator passphrase, returning an encrypted backup envelope. It is refused
// on a TPM node (the key is non-exportable there) by returning an error the
// handler maps to FailedPrecondition. It is wired on the mTLS and local
// servers of a running node; the maintenance servers leave it nil so
// ExportCAKey returns Unimplemented there. Implemented in internal/init.
type Exporter interface {
	ExportCAKey(ctx context.Context, passphrase []byte) (envelope []byte, err error)
}

// Importer restores a CA identity from an encrypted backup envelope onto a
// node that has none, the recovery sibling of the first-boot ceremony. It
// returns ErrIdentityExists (mapped to FailedPrecondition) when the node
// already has an identity, and backup.ErrBadPassphrase (mapped to
// InvalidArgument) when the envelope cannot be opened. It is wired on the mTLS
// and local servers; the maintenance servers leave it nil so ImportCAKey
// returns Unimplemented there. Implemented in internal/init.
type Importer interface {
	ImportCAKey(ctx context.Context, envelope, passphrase []byte) (*cryptosv1.Identity, error)
}

// Attester signs a challenge nonce with the node's CA identity key and
// returns the signature plus the identity public key (PKIX/DER). It backs
// the FM enrollment challenge-response (Attest RPC): the Fleet Manager sends
// a random nonce and verifies the returned signature against the identity
// public key it already pinned during enrollment, proving this node holds
// the corresponding private key. It is wired on the mTLS and local servers
// of a running node; the maintenance servers leave it nil so Attest returns
// Unimplemented there. Implemented in internal/init over the same CA key
// loader the signing handlers use.
type Attester interface {
	SignNonce(ctx context.Context, nonce []byte) (signature, identityPubDER []byte, err error)
}

// Resetter performs a destructive, confirmed node reset. It verifies the
// caller-supplied confirmCommonName against the node's Root CA CN, erases
// the state-partition key material, clears the staged config, and reboots.
// It is wired only on the local console socket; the mTLS and maintenance
// servers leave it nil so Reset is refused there.
type Resetter interface {
	Reset(ctx context.Context, confirmCommonName string) error
}

// ServerConfig holds the dependencies a Server needs.
type ServerConfig struct {
	TLSConfig   *tls.Config
	Auditor     Auditor
	Identity    Identity
	Status      StatusProvider
	Ceremony    Ceremony
	ConfigStore ConfigStore

	// Installer drives bare-metal install in maintenance mode. Only
	// consulted when ConfigStore is nil. May be nil on a running node.
	Installer Installer

	// Resetter drives the destructive node reset. It is set only on the
	// local console socket; nil elsewhere, so Reset is refused with
	// Unimplemented on the mTLS and maintenance servers.
	Resetter Resetter

	// Signer is only used in debug-tagged builds. May be nil otherwise.
	Signer Signer

	// SubordinateSigner and LeafSigner back the P3a signing RPCs. They are
	// wired on the mTLS and local servers of a running node; the maintenance
	// servers leave them nil, so the RPCs return Unimplemented there.
	SubordinateSigner SubordinateSigner
	LeafSigner        LeafSigner

	// SubordinateEnroller backs the child side of the P3b subordinate ceremony
	// (GetSubordinateCSR + SubmitSubordinateCertificate). It is wired on the
	// mTLS and local servers of a subordinate node awaiting its certificate; a
	// Root and the maintenance servers leave it nil, so those RPCs return
	// Unimplemented there.
	SubordinateEnroller SubordinateEnroller

	// Rekeyer backs the CA key rotation RPCs (BeginKeyRotation,
	// CompleteKeyRotation). It is wired on the mTLS and local servers of an
	// established subordinate node; a Root and the maintenance servers leave it
	// nil, so those RPCs return Unimplemented there.
	Rekeyer Rekeyer

	// Revoker backs the revocation RPCs (RevokeCertificate, ListIssued,
	// ListRevocations). It is wired on the mTLS and local servers of a running
	// node; the maintenance servers leave it nil, so those RPCs return
	// Unimplemented there.
	Revoker Revoker

	// Exporter and Importer back the CA key escrow RPCs (ExportCAKey,
	// ImportCAKey). They are wired on the mTLS and local servers of a running
	// node; the maintenance servers leave them nil, so those RPCs return
	// Unimplemented there.
	Exporter Exporter
	Importer Importer

	// Attester backs the FM enrollment challenge-response RPC (Attest). It is
	// wired on the mTLS and local servers of a running node; the maintenance
	// servers leave it nil, so Attest returns Unimplemented there.
	Attester Attester

	// Trust is the pinned bootstrap admin trust used to authorize the signing
	// RPCs (AuthorizeAdmin). A nil Trust means the caller could not be denied,
	// so it is set only alongside the signers on the authenticated servers.
	Trust *bootstrap.Trust
}

// Server is a running gRPC server.
type Server struct {
	cfg     ServerConfig
	grpcSrv *grpc.Server
	mu      sync.Mutex
	closed  bool
}

// New constructs a Server. The supplied TLSConfig must already be
// configured for mTLS (MinVersion >= TLS 1.3, RequireAndVerifyClientCert).
// New enforces those minima as a defense-in-depth check.
func New(cfg ServerConfig) (*Server, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("grpc: New: TLSConfig is required")
	}
	if cfg.TLSConfig.MinVersion < tls.VersionTLS13 {
		cfg.TLSConfig.MinVersion = tls.VersionTLS13
	}
	if cfg.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, errors.New("grpc: New: TLSConfig.ClientAuth must be RequireAndVerifyClientCert")
	}
	if cfg.Auditor == nil {
		return nil, errors.New("grpc: New: Auditor is required")
	}

	s := &Server{cfg: cfg}
	s.grpcSrv = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(cfg.TLSConfig)),
		grpc.UnaryInterceptor(s.unaryAudit),
		grpc.StreamInterceptor(s.streamAudit),
	)
	cryptosv1.RegisterNodeServiceServer(s.grpcSrv, s)
	return s, nil
}

// NewMaintenance builds a management server for maintenance mode: it presents
// server TLS but does NOT request or verify a client certificate (Talos
// --insecure), because no bootstrap trust exists yet. Use only in maintenance;
// the normal listener uses New with RequireAndVerifyClientCert.
func NewMaintenance(cfg ServerConfig) (*Server, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("grpc: NewMaintenance: TLSConfig is required")
	}
	if cfg.TLSConfig.ClientAuth != tls.NoClientCert {
		return nil, errors.New("grpc: NewMaintenance: TLSConfig.ClientAuth must be NoClientCert")
	}
	if cfg.TLSConfig.MinVersion < tls.VersionTLS13 {
		cfg.TLSConfig.MinVersion = tls.VersionTLS13
	}
	if cfg.Auditor == nil {
		return nil, errors.New("grpc: NewMaintenance: Auditor is required")
	}
	s := &Server{cfg: cfg}
	s.grpcSrv = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(cfg.TLSConfig)),
		grpc.UnaryInterceptor(s.unaryAudit),
		grpc.StreamInterceptor(s.streamAudit),
	)
	cryptosv1.RegisterNodeServiceServer(s.grpcSrv, s)
	return s, nil
}

// NewLocal constructs a Server for the on-box UNIX socket: plaintext (no
// TLS), no client authentication. It is root-only and never exposed
// beyond the node's own filesystem; it exists so on-box cryptosctl can
// drive the ceremony as a break-glass surface.
//
// The same NodeService handlers and audit interceptors are wired as for
// the mTLS Server; actor_subject is simply empty for local calls.
func NewLocal(cfg ServerConfig) (*Server, error) {
	if cfg.Auditor == nil {
		return nil, errors.New("grpc: NewLocal: Auditor is required")
	}
	s := &Server{cfg: cfg}
	s.grpcSrv = grpc.NewServer(
		grpc.UnaryInterceptor(s.unaryAudit),
		grpc.StreamInterceptor(s.streamAudit),
	)
	cryptosv1.RegisterNodeServiceServer(s.grpcSrv, s)
	return s, nil
}

// Serve blocks serving on lis until Stop is called.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpcSrv.Serve(lis)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.grpcSrv.GracefulStop()
	s.closed = true
}

// ApplyConfig handles cryptos.v1.NodeService/ApplyConfig.
//
// Running node (ConfigStore != nil): persist config via the store (Sub-spec 2).
// Maintenance mode (ConfigStore == nil, Installer != nil): install to disk and
// signal a reboot (Sub-spec 3, Task 4).
// Maintenance mode with no Installer: not available yet.
func (s *Server) ApplyConfig(ctx context.Context, req *cryptosv1.ApplyConfigRequest) (*cryptosv1.ApplyConfigResponse, error) {
	if s.cfg.ConfigStore != nil {
		if req == nil || req.Config == nil {
			return nil, status.Error(codes.InvalidArgument, "ApplyConfig: config is required")
		}
		return s.cfg.ConfigStore.Apply(ctx, req.Config)
	}
	if s.cfg.Installer != nil {
		if req == nil || req.Config == nil {
			return nil, status.Error(codes.InvalidArgument, "ApplyConfig: config is required")
		}
		return s.cfg.Installer.Install(ctx, req.Config)
	}
	return nil, status.Error(codes.Unavailable, "not available in maintenance mode")
}

// Reset handles cryptos.v1.NodeService/Reset. It is available only on the
// local console socket: when Resetter is nil (the mTLS and maintenance
// servers) it returns Unimplemented. The Resetter owns the confirm-CN
// check and the destructive wipe; this handler only maps errors. A
// confirm-CN mismatch (reset.ErrConfirmMismatch) maps to PermissionDenied;
// any other failure maps to Internal.
func (s *Server) Reset(ctx context.Context, req *cryptosv1.ResetRequest) (*cryptosv1.ResetResponse, error) {
	if s.cfg.Resetter == nil {
		return nil, status.Error(codes.Unimplemented, "reset is only available on the local console socket")
	}
	if err := s.cfg.Resetter.Reset(ctx, req.GetConfirmCommonName()); err != nil {
		if errors.Is(err, reset.ErrConfirmMismatch) {
			return nil, status.Error(codes.PermissionDenied, "reset: confirmation CN does not match the Root CA CN")
		}
		return nil, status.Errorf(codes.Internal, "Reset: %v", err)
	}
	return &cryptosv1.ResetResponse{}, nil
}

// SignSubordinateCSR handles cryptos.v1.NodeService/SignSubordinateCSR: a
// parent CA signs a child CA CSR into a CA certificate and returns the chain.
// The maintenance servers leave SubordinateSigner nil, so the RPC returns
// Unimplemented there. On a running node the caller is authorized against the
// bootstrap admin trust before the CA key is touched. This handler is thin: the
// role/pathLen/CSR-verification rules live in the signer.
func (s *Server) SignSubordinateCSR(ctx context.Context, req *cryptosv1.SignSubordinateCSRRequest) (*cryptosv1.SignSubordinateCSRResponse, error) {
	if s.cfg.SubordinateSigner == nil {
		return nil, status.Error(codes.Unimplemented, "signing is not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if req == nil || len(req.GetCsrDer()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "SignSubordinateCSR: csr_der is required")
	}
	chainDER, chainPEM, err := s.cfg.SubordinateSigner.SignSubordinate(ctx, req.GetCsrDer(), req.GetProfileName())
	if err != nil {
		return nil, err
	}
	return &cryptosv1.SignSubordinateCSRResponse{ChainDer: chainDER, ChainPem: chainPEM}, nil
}

// IssueLeaf handles cryptos.v1.NodeService/IssueLeaf: a CA issues an end-entity
// certificate from a CSR. The maintenance servers leave LeafSigner nil, so the
// RPC returns Unimplemented there. On a running node the caller is authorized
// against the bootstrap admin trust before the CA key is touched. This handler
// is thin: the role/ack/CSR-verification rules live in the signer.
func (s *Server) IssueLeaf(ctx context.Context, req *cryptosv1.IssueLeafRequest) (*cryptosv1.IssueLeafResponse, error) {
	if s.cfg.LeafSigner == nil {
		return nil, status.Error(codes.Unimplemented, "signing is not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if req == nil || len(req.GetCsrDer()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "IssueLeaf: csr_der is required")
	}
	certDER, err := s.cfg.LeafSigner.IssueLeaf(ctx, req.GetCsrDer(), req.GetProfileName())
	if err != nil {
		return nil, err
	}
	return &cryptosv1.IssueLeafResponse{CertDer: certDER}, nil
}

// GetSubordinateCSR handles cryptos.v1.NodeService/GetSubordinateCSR: a
// subordinate node returns the CSR it staged on first boot so an operator can
// ferry it to the parent CA. A Root and the maintenance servers leave
// SubordinateEnroller nil, so the RPC returns Unimplemented there. This handler
// is thin: the enroller owns the phase check (the CSR is only available while
// the node is awaiting its certificate).
func (s *Server) GetSubordinateCSR(ctx context.Context, _ *cryptosv1.GetSubordinateCSRRequest) (*cryptosv1.GetSubordinateCSRResponse, error) {
	if s.cfg.SubordinateEnroller == nil {
		return nil, status.Error(codes.Unimplemented, "subordinate enrollment is not available on this node")
	}
	csrDER, err := s.cfg.SubordinateEnroller.CSR(ctx)
	if err != nil {
		return nil, err
	}
	return &cryptosv1.GetSubordinateCSRResponse{CsrDer: csrDER}, nil
}

// SubmitSubordinateCertificate handles
// cryptos.v1.NodeService/SubmitSubordinateCertificate: an operator hands back
// the parent-signed certificate chain and the node establishes its identity. A
// Root and the maintenance servers leave SubordinateEnroller nil, so the RPC
// returns Unimplemented there. On a subordinate node the caller is authorized
// against the bootstrap admin trust before any state changes. This handler is
// thin: the security-critical chain verification (that the chain roots to the
// pinned parent anchor and that the leaf carries this node's staged key) and
// the atomic commit live in the enroller.
func (s *Server) SubmitSubordinateCertificate(ctx context.Context, req *cryptosv1.SubmitSubordinateCertificateRequest) (*cryptosv1.SubmitSubordinateCertificateResponse, error) {
	if s.cfg.SubordinateEnroller == nil {
		return nil, status.Error(codes.Unimplemented, "subordinate enrollment is not available on this node")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if req == nil || len(req.GetChainDer()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "SubmitSubordinateCertificate: chain_der is required")
	}
	id, err := s.cfg.SubordinateEnroller.AcceptCertificate(ctx, req.GetChainDer())
	if err != nil {
		return nil, err
	}
	return &cryptosv1.SubmitSubordinateCertificateResponse{Identity: id}, nil
}

// BeginKeyRotation handles cryptos.v1.NodeService/BeginKeyRotation: an
// established subordinate generates a new CA key and stages its CSR so an
// operator can ferry it to the parent CA, while the node keeps serving with its
// current key. A Root and the maintenance servers leave Rekeyer nil, so the RPC
// returns Unimplemented there. On a subordinate node the caller is authorized
// against the bootstrap admin trust before any key material is generated. A
// no-identity node surfaces as FailedPrecondition from the rekeyer. This handler
// is thin: the key generation and staging live in the rekeyer.
func (s *Server) BeginKeyRotation(ctx context.Context, _ *cryptosv1.BeginKeyRotationRequest) (*cryptosv1.BeginKeyRotationResponse, error) {
	if s.cfg.Rekeyer == nil {
		return nil, status.Error(codes.Unimplemented, "key rotation is not available on this node")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	csrDER, err := s.cfg.Rekeyer.BeginRotation(ctx)
	if err != nil {
		return nil, err
	}
	return &cryptosv1.BeginKeyRotationResponse{CsrDer: csrDER}, nil
}

// CompleteKeyRotation handles cryptos.v1.NodeService/CompleteKeyRotation: an
// operator hands back the parent-signed chain for the new key and the node
// atomically swaps to it. A Root and the maintenance servers leave Rekeyer nil,
// so the RPC returns Unimplemented there. On a subordinate node the caller is
// authorized against the bootstrap admin trust before any state changes. This
// handler is thin: the security-critical chain verification (that the chain
// roots to the pinned parent anchor and that the leaf carries the staged
// rotation key) and the atomic swap live in the rekeyer.
func (s *Server) CompleteKeyRotation(ctx context.Context, req *cryptosv1.CompleteKeyRotationRequest) (*cryptosv1.CompleteKeyRotationResponse, error) {
	if s.cfg.Rekeyer == nil {
		return nil, status.Error(codes.Unimplemented, "key rotation is not available on this node")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if req == nil || len(req.GetChainDer()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "CompleteKeyRotation: chain_der is required")
	}
	id, err := s.cfg.Rekeyer.CompleteRotation(ctx, req.GetChainDer())
	if err != nil {
		return nil, err
	}
	return &cryptosv1.CompleteKeyRotationResponse{Identity: id}, nil
}

// RevokeCertificate handles cryptos.v1.NodeService/RevokeCertificate: it marks
// a certificate this node issued (identified by its hex serial) as revoked and
// refreshes the published CRL. The maintenance servers leave Revoker nil, so the
// RPC returns Unimplemented there. On a running node the caller is authorized
// against the bootstrap admin trust before any state changes. A serial this node
// never issued surfaces as NotFound (revocation.ErrNotIssued); the revoke is
// idempotent, so re-revoking a serial returns the original record.
func (s *Server) RevokeCertificate(ctx context.Context, req *cryptosv1.RevokeCertificateRequest) (*cryptosv1.RevokeCertificateResponse, error) {
	if s.cfg.Revoker == nil {
		return nil, status.Error(codes.Unimplemented, "revocation is not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if req == nil || req.GetSerialHex() == "" {
		return nil, status.Error(codes.InvalidArgument, "RevokeCertificate: serial_hex is required")
	}
	rev, err := s.cfg.Revoker.Revoke(ctx, req.GetSerialHex(), int(req.GetReasonCode()))
	if err != nil {
		if errors.Is(err, revocation.ErrNotIssued) {
			return nil, status.Errorf(codes.NotFound, "RevokeCertificate: serial %q was not issued by this node", req.GetSerialHex())
		}
		return nil, err
	}
	return &cryptosv1.RevokeCertificateResponse{Revocation: rev}, nil
}

// ListIssued handles cryptos.v1.NodeService/ListIssued: it returns this node's
// issued-certificate inventory. The maintenance servers leave Revoker nil, so
// the RPC returns Unimplemented there. The caller is authorized against the
// bootstrap admin trust.
func (s *Server) ListIssued(ctx context.Context, _ *cryptosv1.ListIssuedRequest) (*cryptosv1.ListIssuedResponse, error) {
	if s.cfg.Revoker == nil {
		return nil, status.Error(codes.Unimplemented, "revocation is not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	issued, err := s.cfg.Revoker.ListIssued(ctx)
	if err != nil {
		return nil, err
	}
	return &cryptosv1.ListIssuedResponse{Issued: issued}, nil
}

// ListRevocations handles cryptos.v1.NodeService/ListRevocations: it returns
// this node's revoked-certificate inventory. The maintenance servers leave
// Revoker nil, so the RPC returns Unimplemented there. The caller is authorized
// against the bootstrap admin trust.
func (s *Server) ListRevocations(ctx context.Context, _ *cryptosv1.ListRevocationsRequest) (*cryptosv1.ListRevocationsResponse, error) {
	if s.cfg.Revoker == nil {
		return nil, status.Error(codes.Unimplemented, "revocation is not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	revs, err := s.cfg.Revoker.ListRevocations(ctx)
	if err != nil {
		return nil, err
	}
	return &cryptosv1.ListRevocationsResponse{Revocations: revs}, nil
}

// ExportCAKey handles cryptos.v1.NodeService/ExportCAKey: it seals this node's
// software CA key + identity chain under the operator passphrase and returns
// the encrypted backup envelope. The maintenance servers leave Exporter nil, so
// the RPC returns Unimplemented there. On a running node the caller is
// authorized against the bootstrap admin trust before the CA key is touched. A
// TPM node refuses (ErrNotExportable -> FailedPrecondition) because a TPM-sealed
// key is non-exportable by design. The plaintext key never leaves the node; only
// the encrypted envelope crosses the wire.
func (s *Server) ExportCAKey(ctx context.Context, req *cryptosv1.ExportCAKeyRequest) (*cryptosv1.ExportCAKeyResponse, error) {
	if s.cfg.Exporter == nil {
		return nil, status.Error(codes.Unimplemented, "CA key export is not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if req == nil || len(req.GetPassphrase()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ExportCAKey: passphrase is required")
	}
	envelope, err := s.cfg.Exporter.ExportCAKey(ctx, req.GetPassphrase())
	if err != nil {
		if errors.Is(err, ErrNotExportable) {
			return nil, status.Error(codes.FailedPrecondition, "ExportCAKey: this node's CA key is non-exportable (TPM-backed)")
		}
		return nil, status.Errorf(codes.Internal, "ExportCAKey: %v", err)
	}
	return &cryptosv1.ExportCAKeyResponse{Envelope: envelope}, nil
}

// ImportCAKey handles cryptos.v1.NodeService/ImportCAKey: it restores a CA
// identity from an encrypted backup envelope onto a node that has none, the
// recovery sibling of StartCeremony. The maintenance servers leave Importer nil,
// so the RPC returns Unimplemented there. On a running node the caller is
// authorized against the bootstrap admin trust before any state changes. A
// node that already has an identity refuses (node.ErrIdentityExists ->
// FailedPrecondition); a wrong passphrase or corrupt envelope
// (backup.ErrBadPassphrase) maps to InvalidArgument. The security-critical
// key/chain match and the atomic commit live in the importer; this handler only
// maps errors.
func (s *Server) ImportCAKey(ctx context.Context, req *cryptosv1.ImportCAKeyRequest) (*cryptosv1.ImportCAKeyResponse, error) {
	if s.cfg.Importer == nil {
		return nil, status.Error(codes.Unimplemented, "CA key import is not available in maintenance mode")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}
	if req == nil || len(req.GetEnvelope()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ImportCAKey: envelope is required")
	}
	if len(req.GetPassphrase()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ImportCAKey: passphrase is required")
	}
	id, err := s.cfg.Importer.ImportCAKey(ctx, req.GetEnvelope(), req.GetPassphrase())
	if err != nil {
		switch {
		case errors.Is(err, backup.ErrBadPassphrase):
			return nil, status.Error(codes.InvalidArgument, "ImportCAKey: bad passphrase or corrupt backup")
		case errors.Is(err, ErrIdentityExists):
			return nil, status.Error(codes.FailedPrecondition, "ImportCAKey: this node already has an identity")
		}
		return nil, status.Errorf(codes.Internal, "ImportCAKey: %v", err)
	}
	return &cryptosv1.ImportCAKeyResponse{Identity: id}, nil
}

// GetStatus handles cryptos.v1.NodeService/GetStatus.
func (s *Server) GetStatus(ctx context.Context, _ *cryptosv1.GetStatusRequest) (*cryptosv1.GetStatusResponse, error) {
	st, err := s.cfg.Status.Status(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "GetStatus: %v", err)
	}
	return &cryptosv1.GetStatusResponse{Status: st}, nil
}

// GetIdentity handles cryptos.v1.NodeService/GetIdentity.
func (s *Server) GetIdentity(ctx context.Context, _ *cryptosv1.GetIdentityRequest) (*cryptosv1.GetIdentityResponse, error) {
	if s.cfg.Identity == nil {
		return nil, status.Error(codes.Unavailable, "not available in maintenance mode")
	}
	id, err := s.cfg.Identity.Get(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "GetIdentity: %v", err)
	}
	return &cryptosv1.GetIdentityResponse{Identity: id}, nil
}

// StartCeremony handles cryptos.v1.NodeService/StartCeremony.
func (s *Server) StartCeremony(req *cryptosv1.StartCeremonyRequest, stream grpc.ServerStreamingServer[cryptosv1.StartCeremonyResponse]) error {
	if s.cfg.Ceremony == nil {
		return status.Error(codes.Unavailable, "not available in maintenance mode")
	}
	if req == nil {
		return status.Error(codes.InvalidArgument, "StartCeremony: request is required")
	}
	send := func(resp *cryptosv1.StartCeremonyResponse) error {
		return stream.Send(resp)
	}
	if err := s.cfg.Ceremony.Start(stream.Context(), req, send); err != nil {
		// Preserve a status code the ceremony chose (e.g.
		// FAILED_PRECONDITION when an identity already exists); wrap
		// anything else as Internal.
		if _, ok := status.FromError(err); ok {
			return err
		}
		return status.Errorf(codes.Internal, "StartCeremony: %v", err)
	}
	return nil
}

// actorSubject extracts the verified client certificate's Subject DN
// from the request context, or returns an empty string if no mTLS info
// is attached (which shouldn't happen given the server's TLS config).
func actorSubject(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return ""
	}
	return tlsInfo.State.VerifiedChains[0][0].Subject.String()
}

// unaryAudit is the interceptor that records every unary RPC. It runs
// BEFORE the handler (to capture the request digest) and again AFTER
// (to record the outcome).
func (s *Server) unaryAudit(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	digest := digestRequest(req)
	resp, err := handler(ctx, req)
	s.recordAudit(ctx, info.FullMethod, digest, err)
	return resp, err
}

// streamAudit is the interceptor that records every server-streaming
// RPC. Streamed responses are not individually recorded; the audit
// entry captures the start + final outcome.
func (s *Server) streamAudit(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	// The streaming request struct lives in the stream metadata, not as
	// an interceptor parameter. Just record the call start; concrete
	// request digesting can be added if a specific RPC demands it.
	err := handler(srv, ss)
	s.recordAudit(ss.Context(), info.FullMethod, nil, err)
	return err
}

// recordAudit appends an entry to the audit log. Errors are intentionally
// swallowed — failing to audit must not change the RPC outcome the
// client sees; PID 1's supervisor surfaces audit subsystem health
// separately via GetStatus.
func (s *Server) recordAudit(ctx context.Context, method string, requestDigest []byte, rpcErr error) {
	outcome := cryptosv1.Outcome_OUTCOME_OK
	if rpcErr != nil {
		if st, ok := status.FromError(rpcErr); ok && st.Code() == codes.PermissionDenied {
			outcome = cryptosv1.Outcome_OUTCOME_DENIED
		} else {
			outcome = cryptosv1.Outcome_OUTCOME_ERROR
		}
	}
	_ = s.cfg.Auditor.Append(&cryptosv1.AuditEvent{
		ActorSubject:        actorSubject(ctx),
		RpcMethod:           method,
		RequestDigestSha256: requestDigest,
		Outcome:             outcome,
	})
}

// digestRequest returns the SHA-256 of req's canonical-proto encoding
// for proto messages, or nil for non-proto requests (which Phase 1
// shouldn't have).
func digestRequest(req interface{}) []byte {
	msg, ok := req.(proto.Message)
	if !ok {
		return nil
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(canonical)
	return sum[:]
}
