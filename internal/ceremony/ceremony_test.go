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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// Engine satisfies the gRPC Ceremony interface.
var _ cgrpc.Ceremony = (*Engine)(nil)

// tpmTestBackend adapts *tpm.TPM to RootKeyBackend for the tests: LoadKey
// returns the *tpm.Key (already a RootSigner) as the interface.
type tpmTestBackend struct{ t *tpm.TPM }

func (b tpmTestBackend) ProvisionSRK() error { return b.t.ProvisionSRK() }

func (b tpmTestBackend) CreateKey(alg tpm.KeyAlgorithm) (*tpm.CreatedKey, error) {
	return b.t.CreateKey(alg)
}

func (b tpmTestBackend) LoadKey(private, public []byte) (RootSigner, error) {
	return b.t.LoadKey(private, public)
}

type harness struct {
	engine    *Engine
	store     *node.Store
	cli       *clientv3.Client
	adminCert *x509.Certificate
	adminPEM  string
	adminFP   [32]byte
}

func newHarness(t *testing.T) (*harness, context.Context) {
	t.Helper()

	tp, err := tpm.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })

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
	store, err := node.New(cli)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}

	adminCert, adminPEM := testAdminCert(t)
	trust, err := bootstrap.LoadTrust(adminPEM, "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}

	seed := make([]byte, SeedLength)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	eng, err := New(Config{RootKey: tpmTestBackend{tp}, Store: store, ConfigStore: config.NewFileStore(t.TempDir()), Trust: trust, Seed: seed})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return &harness{
		engine:    eng,
		store:     store,
		cli:       cli,
		adminCert: adminCert,
		adminPEM:  adminPEM,
		adminFP:   sha256.Sum256(adminCert.Raw),
	}, ctx
}

func testAdminCert(t *testing.T) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "bootstrap-admin", Organization: []string{"Acme"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return cert, pemStr
}

func machineYAML(adminFP [32]byte) []byte {
	return machineYAMLRole(adminFP, "root")
}

// machineYAMLRole builds the same otherwise-valid MachineConfig as
// machineYAML but with the given role.kind, so tests can drive the
// ceremony with a non-root role.
func machineYAMLRole(adminFP [32]byte, role string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: root-ca-test
role:
  kind: %s
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_sha256: "%s"
pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "CryptOS Root CA - Test"
    organization: "Test Org"
    country: "US"
  root_validity_years: 20
  path_len_constraint: 2
`, role, hex.EncodeToString(adminFP[:])))
}

// collector accumulates streamed event kinds.
type collector struct {
	kinds  []cryptosv1.CeremonyEventKind
	events []*cryptosv1.CeremonyEvent
}

func (c *collector) send(resp *cryptosv1.StartCeremonyResponse) error {
	c.kinds = append(c.kinds, resp.Event.Kind)
	c.events = append(c.events, resp.Event)
	return nil
}

func mtlsContext(parent context.Context, cert *x509.Certificate) context.Context {
	return peer.NewContext(parent, &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}},
	})
}

func wantOrder() []cryptosv1.CeremonyEventKind {
	return []cryptosv1.CeremonyEventKind{
		cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_KEY_CREATED,
		cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_CERT_SIGNED,
		cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_MANIFEST_WRITTEN,
		cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_ADMIN_ROTATED,
		cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
	}
}

func assertOrder(t *testing.T, got, want []cryptosv1.CeremonyEventKind) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("event count = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event[%d] = %v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestStart_HappyPath_LocalSocket(t *testing.T) {
	h, ctx := newHarness(t)
	c := &collector{}
	req := &cryptosv1.StartCeremonyRequest{
		Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: machineYAML(h.adminFP),
	}
	if err := h.engine.Start(ctx, req, c.send); err != nil {
		t.Fatalf("Start: %v", err)
	}
	assertOrder(t, c.kinds, wantOrder())

	// Identity established and the Root cert is a valid self-signed CA.
	id, err := h.store.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	root, err := x509.ParseCertificate(id.ChainDer[0])
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	if !root.IsCA {
		t.Error("root cert IsCA = false")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := root.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("root cert does not self-verify: %v", err)
	}
	if root.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("root key alg = %v, want ECDSA", root.PublicKeyAlgorithm)
	}
	if root.Subject.CommonName != "CryptOS Root CA - Test" {
		t.Errorf("root CN = %q", root.Subject.CommonName)
	}

	// The stored manifest verifies against the engine's public key and
	// records the bootstrap admin as the operator.
	manifestBytes := readManifest(t, ctx, h.cli)
	if err := VerifyManifest(manifestBytes, h.engine.PublicKey()); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}
	checkManifestContents(t, manifestBytes, h.adminFP, sha256.Sum256(id.ChainDer[0]))

	// The bootstrap admin was promoted into the admin registry.
	if n := countAdmins(t, ctx, h.cli); n != 1 {
		t.Errorf("admin registry has %d entries, want 1", n)
	}
}

func TestStart_MTLS_Authorized(t *testing.T) {
	h, baseCtx := newHarness(t)
	ctx := mtlsContext(baseCtx, h.adminCert)
	c := &collector{}
	req := &cryptosv1.StartCeremonyRequest{
		Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: machineYAML(h.adminFP),
	}
	if err := h.engine.Start(ctx, req, c.send); err != nil {
		t.Fatalf("Start (mTLS authorized): %v", err)
	}
	assertOrder(t, c.kinds, wantOrder())
}

func TestStart_MTLS_WrongCert(t *testing.T) {
	h, baseCtx := newHarness(t)
	intruder, _ := testAdminCert(t)
	ctx := mtlsContext(baseCtx, intruder)
	c := &collector{}
	req := &cryptosv1.StartCeremonyRequest{
		Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: machineYAML(h.adminFP),
	}
	err := h.engine.Start(ctx, req, c.send)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Start with wrong cert: code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if len(c.kinds) != 0 {
		t.Errorf("events emitted on rejected ceremony: %v", c.kinds)
	}
	if ok, _ := h.store.HasIdentity(baseCtx); ok {
		t.Error("identity established despite authorization failure")
	}
}

func TestStart_IdentityExists(t *testing.T) {
	h, ctx := newHarness(t)
	req := &cryptosv1.StartCeremonyRequest{
		Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: machineYAML(h.adminFP),
	}
	if err := h.engine.Start(ctx, req, (&collector{}).send); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	err := h.engine.Start(ctx, req, (&collector{}).send)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second Start: code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
}

func TestStart_BadConfig(t *testing.T) {
	h, ctx := newHarness(t)
	tests := map[string][]byte{
		"empty":   nil,
		"garbage": []byte("not: valid: yaml: : :"),
		"unknown-role": []byte(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
role:
  kind: bogus
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
bootstrap: {admin_cert_sha256: "` + hex.EncodeToString(h.adminFP[:]) + `"}
pki: {root_key_alg: ECDSA-P384, root_subject: {common_name: x}, root_validity_years: 1, path_len_constraint: 0}
`),
	}
	for name, yaml := range tests {
		t.Run(name, func(t *testing.T) {
			err := h.engine.Start(ctx, &cryptosv1.StartCeremonyRequest{
				Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
				MachineConfigYaml: yaml,
			}, (&collector{}).send)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
			}
		})
	}
}

func TestStart_NonRootRole_Refused(t *testing.T) {
	h, ctx := newHarness(t)
	c := &collector{}
	req := &cryptosv1.StartCeremonyRequest{
		Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: machineYAMLRole(h.adminFP, "intermediate"),
	}
	err := h.engine.Start(ctx, req, c.send)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("non-root role: code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if len(c.kinds) != 0 {
		t.Errorf("events emitted on refused ceremony: %v", c.kinds)
	}
	if ok, _ := h.store.HasIdentity(ctx); ok {
		t.Error("identity established despite a non-root role")
	}
}

func TestVerifyManifest_Tamper(t *testing.T) {
	h, ctx := newHarness(t)
	if err := h.engine.Start(ctx, &cryptosv1.StartCeremonyRequest{
		Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: machineYAML(h.adminFP),
	}, (&collector{}).send); err != nil {
		t.Fatalf("Start: %v", err)
	}
	manifestBytes := readManifest(t, ctx, h.cli)

	// A different key must not verify.
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := VerifyManifest(manifestBytes, wrongPub); err == nil {
		t.Error("VerifyManifest accepted a wrong public key")
	}

	// A flipped byte must not verify.
	tampered := append([]byte(nil), manifestBytes...)
	tampered[len(tampered)/2] ^= 0xff
	if err := VerifyManifest(tampered, h.engine.PublicKey()); err == nil {
		t.Error("VerifyManifest accepted tampered bytes")
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New(empty) = nil error, want error")
	}
	if _, err := deriveCeremonySigner(make([]byte, 16)); err == nil {
		t.Error("deriveCeremonySigner(short seed) = nil error, want error")
	}
}

func readManifest(t *testing.T, ctx context.Context, cli *clientv3.Client) []byte {
	t.Helper()
	resp, err := cli.Get(ctx, etcd.PrefixCeremonyManifests, clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("get manifests: %v", err)
	}
	if len(resp.Kvs) != 1 {
		t.Fatalf("manifest count = %d, want 1", len(resp.Kvs))
	}
	return resp.Kvs[0].Value
}

func countAdmins(t *testing.T, ctx context.Context, cli *clientv3.Client) int {
	t.Helper()
	resp, err := cli.Get(ctx, etcd.PrefixAdmins, clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("get admins: %v", err)
	}
	return len(resp.Kvs)
}

func checkManifestContents(t *testing.T, manifestBytes []byte, wantSigner [32]byte, wantCertSHA [32]byte) {
	t.Helper()
	var m cryptosv1.CeremonyManifest
	if err := proto.Unmarshal(manifestBytes, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if m.ManifestVersion != manifestVersion {
		t.Errorf("manifest_version = %d, want %d", m.ManifestVersion, manifestVersion)
	}
	if m.CeremonyKind != ceremonyKindRootFirstBoot {
		t.Errorf("ceremony_kind = %q, want %q", m.CeremonyKind, ceremonyKindRootFirstBoot)
	}
	if m.CeremonyId == "" {
		t.Error("ceremony_id is empty")
	}
	if len(m.PrevManifestSha256) != 0 {
		t.Errorf("prev_manifest_sha256 = %x, want empty for first ceremony", m.PrevManifestSha256)
	}
	if string(m.ResultingCertSha256) != string(wantCertSHA[:]) {
		t.Error("resulting_cert_sha256 mismatch")
	}
	if m.KeyCreationAttestation == nil || len(m.KeyCreationAttestation.TpmPublic) == 0 {
		t.Error("key_creation_attestation missing tpm_public")
	}
	if len(m.OperatorSignatures) != 1 {
		t.Fatalf("operator_signatures count = %d, want 1", len(m.OperatorSignatures))
	}
	if got, want := m.OperatorSignatures[0].SignerId, hex.EncodeToString(wantSigner[:]); got != want {
		t.Errorf("signer_id = %q, want %q", got, want)
	}
}

func TestStart_RejectsConcurrentCeremony(t *testing.T) {
	h, ctx := newHarness(t)
	req := &cryptosv1.StartCeremonyRequest{
		Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
		MachineConfigYaml: machineYAML(h.adminFP),
	}

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)

	// First ceremony blocks on its first emitted event, holding the lock.
	first := true
	go func() {
		done <- h.engine.Start(ctx, req, func(*cryptosv1.StartCeremonyResponse) error {
			if first {
				first = false
				close(started)
				<-release
			}
			return nil
		})
	}()

	<-started // the first ceremony now holds e.running

	// A second concurrent ceremony must be rejected, not queued.
	if err := h.engine.Start(ctx, req, (&collector{}).send); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("concurrent ceremony: code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}

	close(release) // let the first ceremony finish
	if err := <-done; err != nil {
		t.Fatalf("first ceremony: %v", err)
	}
}
