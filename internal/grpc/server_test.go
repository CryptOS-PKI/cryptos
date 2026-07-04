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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	stdgrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

// ---- mocks ----

type mockAuditor struct {
	mu     sync.Mutex
	events []*cryptosv1.AuditEvent
}

func (m *mockAuditor) Append(e *cryptosv1.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *mockAuditor) snapshot() []*cryptosv1.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*cryptosv1.AuditEvent, len(m.events))
	copy(out, m.events)
	return out
}

type mockIdentity struct {
	resp *cryptosv1.Identity
	err  error
}

func (m *mockIdentity) Get(_ context.Context) (*cryptosv1.Identity, error) {
	return m.resp, m.err
}

type mockStatus struct {
	resp *cryptosv1.NodeStatus
	err  error
}

func (m *mockStatus) Status(_ context.Context) (*cryptosv1.NodeStatus, error) {
	return m.resp, m.err
}

type mockCeremony struct {
	events []*cryptosv1.StartCeremonyResponse
	err    error
}

func (m *mockCeremony) Start(_ context.Context, _ *cryptosv1.StartCeremonyRequest, send func(*cryptosv1.StartCeremonyResponse) error) error {
	for _, e := range m.events {
		if err := send(e); err != nil {
			return err
		}
	}
	return m.err
}

type mockConfigStore struct {
	last *cryptosv1.MachineConfig
	resp *cryptosv1.ApplyConfigResponse
	err  error
}

func (m *mockConfigStore) Apply(_ context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	m.last = cfg
	return m.resp, m.err
}

// ---- test fixtures: in-memory CA + server + client certs ----

type fixtures struct {
	serverConf *tls.Config
	clientConf *tls.Config
	caPool     *x509.CertPool
}

func newFixtures(t *testing.T) *fixtures {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	makeLeaf := func(cn string, isServer bool) tls.Certificate {
		t.Helper()
		leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("leaf key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		if isServer {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			tmpl.DNSNames = []string{"localhost"}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("leaf cert: %v", err)
		}
		return tls.Certificate{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafKey,
		}
	}

	server := makeLeaf("server.test", true)
	client := makeLeaf("CN=test-operator", false)

	return &fixtures{
		serverConf: &tls.Config{
			Certificates: []tls.Certificate{server},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		},
		clientConf: &tls.Config{
			Certificates: []tls.Certificate{client},
			RootCAs:      pool,
			ServerName:   "localhost",
			MinVersion:   tls.VersionTLS13,
		},
		caPool: pool,
	}
}

// startTestServer brings up a Server on 127.0.0.1:0 and returns the
// listener address + cleanup hook + observable mocks.
func startTestServer(t *testing.T, cfg ServerConfig, fx *fixtures) (string, *Server) {
	t.Helper()
	cfg.TLSConfig = fx.serverConf
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := lis.Addr().String()
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return addr, srv
}

func dial(t *testing.T, addr string, fx *fixtures) (cryptosv1.NodeServiceClient, func()) {
	t.Helper()
	conn, err := stdgrpc.NewClient(addr, stdgrpc.WithTransportCredentials(credentials.NewTLS(fx.clientConf)))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return cryptosv1.NewNodeServiceClient(conn), func() { _ = conn.Close() }
}

// ---- tests ----

func TestNew_RejectsBadConfig(t *testing.T) {
	if _, err := New(ServerConfig{}); err == nil {
		t.Fatalf("New with nil TLSConfig should fail")
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.NoClientCert, // wrong
	}
	if _, err := New(ServerConfig{TLSConfig: tlsCfg}); err == nil {
		t.Fatalf("New with NoClientCert should fail")
	}
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	if _, err := New(ServerConfig{TLSConfig: tlsCfg}); err == nil {
		t.Fatalf("New without Auditor should fail")
	}
}

func TestGetStatus_RoutesAndAudits(t *testing.T) {
	fx := newFixtures(t)
	auditor := &mockAuditor{}
	stat := &mockStatus{resp: &cryptosv1.NodeStatus{
		Role:          cryptosv1.NodeRole_NODE_ROLE_ROOT,
		IdentityState: cryptosv1.IdentityState_IDENTITY_STATE_NONE,
	}}
	addr, _ := startTestServer(t, ServerConfig{
		Auditor:     auditor,
		Identity:    &mockIdentity{},
		Status:      stat,
		Ceremony:    &mockCeremony{},
		ConfigStore: &mockConfigStore{},
	}, fx)

	client, closeConn := dial(t, addr, fx)
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.GetStatus(ctx, &cryptosv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.GetStatus().GetRole() != cryptosv1.NodeRole_NODE_ROLE_ROOT {
		t.Fatalf("role = %v", resp.GetStatus().GetRole())
	}

	// Audit interceptor recorded the call.
	for i := 0; i < 20; i++ {
		if len(auditor.snapshot()) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	events := auditor.snapshot()
	if len(events) == 0 {
		t.Fatalf("audit interceptor did not record GetStatus")
	}
	last := events[len(events)-1]
	if last.RpcMethod == "" {
		t.Fatalf("audit event has empty RpcMethod")
	}
	if last.ActorSubject == "" {
		t.Fatalf("audit event has empty ActorSubject (mTLS should populate it)")
	}
	if last.Outcome != cryptosv1.Outcome_OUTCOME_OK {
		t.Fatalf("Outcome = %v, want OK", last.Outcome)
	}
}

func TestGetIdentity_RoutesUnderlyingError(t *testing.T) {
	fx := newFixtures(t)
	addr, _ := startTestServer(t, ServerConfig{
		Auditor:     &mockAuditor{},
		Identity:    &mockIdentity{err: errors.New("no identity yet")},
		Status:      &mockStatus{},
		Ceremony:    &mockCeremony{},
		ConfigStore: &mockConfigStore{},
	}, fx)
	client, closeConn := dial(t, addr, fx)
	defer closeConn()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.GetIdentity(ctx, &cryptosv1.GetIdentityRequest{})
	if err == nil {
		t.Fatalf("GetIdentity should have failed")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", st.Code())
	}
}

func TestApplyConfig_Routes(t *testing.T) {
	fx := newFixtures(t)
	store := &mockConfigStore{resp: &cryptosv1.ApplyConfigResponse{Generation: 7}}
	addr, _ := startTestServer(t, ServerConfig{
		Auditor:     &mockAuditor{},
		Identity:    &mockIdentity{},
		Status:      &mockStatus{},
		Ceremony:    &mockCeremony{},
		ConfigStore: store,
	}, fx)
	client, closeConn := dial(t, addr, fx)
	defer closeConn()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.ApplyConfig(ctx, &cryptosv1.ApplyConfigRequest{
		Config: &cryptosv1.MachineConfig{ApiVersion: "cryptos.dev/v1alpha1"},
	})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if resp.GetGeneration() != 7 {
		t.Fatalf("generation = %d, want 7", resp.GetGeneration())
	}
	if store.last == nil || store.last.ApiVersion != "cryptos.dev/v1alpha1" {
		t.Fatalf("ConfigStore did not receive the config: %v", store.last)
	}
}

func TestApplyConfig_RejectsMissingConfig(t *testing.T) {
	fx := newFixtures(t)
	addr, _ := startTestServer(t, ServerConfig{
		Auditor:     &mockAuditor{},
		Identity:    &mockIdentity{},
		Status:      &mockStatus{},
		Ceremony:    &mockCeremony{},
		ConfigStore: &mockConfigStore{},
	}, fx)
	client, closeConn := dial(t, addr, fx)
	defer closeConn()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.ApplyConfig(ctx, &cryptosv1.ApplyConfigRequest{})
	if err == nil {
		t.Fatalf("ApplyConfig(no config) should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", st.Code())
	}
}

func TestStartCeremony_Streams(t *testing.T) {
	fx := newFixtures(t)
	cer := &mockCeremony{
		events: []*cryptosv1.StartCeremonyResponse{
			{Event: &cryptosv1.CeremonyEvent{Kind: cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_KEY_CREATED}},
			{Event: &cryptosv1.CeremonyEvent{Kind: cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_CERT_SIGNED}},
			{Event: &cryptosv1.CeremonyEvent{Kind: cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE}},
		},
	}
	addr, _ := startTestServer(t, ServerConfig{
		Auditor:     &mockAuditor{},
		Identity:    &mockIdentity{},
		Status:      &mockStatus{},
		Ceremony:    cer,
		ConfigStore: &mockConfigStore{},
	}, fx)
	client, closeConn := dial(t, addr, fx)
	defer closeConn()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.StartCeremony(ctx, &cryptosv1.StartCeremonyRequest{
		Kind: cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
	})
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}
	var got []cryptosv1.CeremonyEventKind
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		got = append(got, resp.GetEvent().GetKind())
	}
	want := []cryptosv1.CeremonyEventKind{
		cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_KEY_CREATED,
		cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_CERT_SIGNED,
		cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestMTLS_RejectsUntrustedClient(t *testing.T) {
	fx := newFixtures(t)
	addr, _ := startTestServer(t, ServerConfig{
		Auditor:     &mockAuditor{},
		Identity:    &mockIdentity{},
		Status:      &mockStatus{},
		Ceremony:    &mockCeremony{},
		ConfigStore: &mockConfigStore{},
	}, fx)

	// Build a client with no cert at all (or an unrelated CA-signed cert):
	// the server's RequireAndVerifyClientCert should reject the handshake.
	wrongConf := &tls.Config{
		RootCAs:    fx.caPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		// No Certificates -> client presents nothing
	}
	conn, err := stdgrpc.NewClient(addr, stdgrpc.WithTransportCredentials(credentials.NewTLS(wrongConf)))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := cryptosv1.NewNodeServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.GetStatus(ctx, &cryptosv1.GetStatusRequest{}); err == nil {
		t.Fatalf("GetStatus over unauthenticated TLS should fail")
	}
}

func TestNewMaintenance(t *testing.T) {
	// nil TLSConfig -> error
	if _, err := NewMaintenance(ServerConfig{}); err == nil {
		t.Error("want error for nil TLSConfig")
	}
	// mTLS-style ClientAuth is rejected: maintenance must be client-unauthenticated
	mtls := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}
	if _, err := NewMaintenance(ServerConfig{TLSConfig: mtls, Auditor: &mockAuditor{}}); err == nil {
		t.Error("want error when ClientAuth != NoClientCert")
	}
	// NoClientCert but nil Auditor -> error (interceptors need it)
	ok := &tls.Config{ClientAuth: tls.NoClientCert}
	if _, err := NewMaintenance(ServerConfig{TLSConfig: ok}); err == nil {
		t.Error("want error for nil Auditor")
	}
	// valid maintenance config -> non-nil server
	srv, err := NewMaintenance(ServerConfig{TLSConfig: ok, Auditor: &mockAuditor{}})
	if err != nil {
		t.Fatalf("NewMaintenance: %v", err)
	}
	if srv == nil {
		t.Fatal("nil server")
	}
}

func TestMaintenanceHandlers_Unavailable(t *testing.T) {
	srv, err := NewMaintenance(ServerConfig{
		TLSConfig: &tls.Config{ClientAuth: tls.NoClientCert},
		Auditor:   &mockAuditor{},
	})
	if err != nil {
		t.Fatalf("NewMaintenance: %v", err)
	}
	if _, err := srv.GetIdentity(context.Background(), &cryptosv1.GetIdentityRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("GetIdentity code = %v, want Unavailable", status.Code(err))
	}
	if _, err := srv.ApplyConfig(context.Background(), &cryptosv1.ApplyConfigRequest{Config: &cryptosv1.MachineConfig{}}); status.Code(err) != codes.Unavailable {
		t.Errorf("ApplyConfig code = %v, want Unavailable", status.Code(err))
	}
	// StartCeremony is the ceremony trigger on the unauthenticated maintenance
	// surface; its guard returns before the stream is used, so a nil stream is
	// safe here.
	if err := srv.StartCeremony(&cryptosv1.StartCeremonyRequest{}, nil); status.Code(err) != codes.Unavailable {
		t.Errorf("StartCeremony code = %v, want Unavailable", status.Code(err))
	}
}

// mockInstaller is a fake Installer for testing the maintenance ApplyConfig path.
type mockInstaller struct {
	called bool
	last   *cryptosv1.MachineConfig
	resp   *cryptosv1.ApplyConfigResponse
	err    error
}

func (m *mockInstaller) Install(_ context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	m.called = true
	m.last = cfg
	return m.resp, m.err
}

// TestApplyConfig_MaintenanceInstaller verifies that when ConfigStore is nil but
// an Installer is wired, ApplyConfig delegates to the Installer and returns its
// response (not Unavailable).
func TestApplyConfig_MaintenanceInstaller(t *testing.T) {
	inst := &mockInstaller{resp: &cryptosv1.ApplyConfigResponse{RequiresReboot: true}}
	srv, err := NewMaintenance(ServerConfig{
		TLSConfig: &tls.Config{ClientAuth: tls.NoClientCert},
		Auditor:   &mockAuditor{},
		Installer: inst,
	})
	if err != nil {
		t.Fatalf("NewMaintenance: %v", err)
	}
	cfg := &cryptosv1.MachineConfig{ApiVersion: "cryptos.dev/v1alpha1"}
	resp, err := srv.ApplyConfig(context.Background(), &cryptosv1.ApplyConfigRequest{Config: cfg})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if !resp.GetRequiresReboot() {
		t.Fatalf("RequiresReboot = false, want true")
	}
	if !inst.called {
		t.Fatalf("Installer.Install was not called")
	}
	if inst.last == nil || inst.last.ApiVersion != "cryptos.dev/v1alpha1" {
		t.Fatalf("Installer did not receive config: %v", inst.last)
	}
}

// TestApplyConfig_NeitherStoreNorInstaller verifies that when both ConfigStore
// and Installer are nil, ApplyConfig returns Unavailable.
func TestApplyConfig_NeitherStoreNorInstaller(t *testing.T) {
	srv, err := NewMaintenance(ServerConfig{
		TLSConfig: &tls.Config{ClientAuth: tls.NoClientCert},
		Auditor:   &mockAuditor{},
		// No ConfigStore, no Installer
	})
	if err != nil {
		t.Fatalf("NewMaintenance: %v", err)
	}
	_, err = srv.ApplyConfig(context.Background(), &cryptosv1.ApplyConfigRequest{
		Config: &cryptosv1.MachineConfig{ApiVersion: "cryptos.dev/v1alpha1"},
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

// TestApplyConfig_InstallerNilConfig verifies that a nil Config with an Installer
// wired returns InvalidArgument (not a panic or Unavailable).
func TestApplyConfig_InstallerNilConfig(t *testing.T) {
	inst := &mockInstaller{resp: &cryptosv1.ApplyConfigResponse{RequiresReboot: true}}
	srv, err := NewMaintenance(ServerConfig{
		TLSConfig: &tls.Config{ClientAuth: tls.NoClientCert},
		Auditor:   &mockAuditor{},
		Installer: inst,
	})
	if err != nil {
		t.Fatalf("NewMaintenance: %v", err)
	}
	_, err = srv.ApplyConfig(context.Background(), &cryptosv1.ApplyConfigRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// mockResetter is a fake Resetter for testing the local-socket Reset handler.
type mockResetter struct {
	called bool
	lastCN string
	err    error
}

func (m *mockResetter) Reset(_ context.Context, confirmCommonName string) error {
	m.called = true
	m.lastCN = confirmCommonName
	return m.err
}

// TestReset_UnimplementedWhenNoResetter verifies that a server with no Resetter
// wired (the mTLS and maintenance servers) refuses Reset with Unimplemented.
func TestReset_UnimplementedWhenNoResetter(t *testing.T) {
	srv, err := NewLocal(ServerConfig{Auditor: &mockAuditor{}})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	_, err = srv.Reset(context.Background(), &cryptosv1.ResetRequest{ConfirmCommonName: "anything"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}

// TestReset_MismatchIsPermissionDenied verifies that a confirm-CN mismatch
// (surfaced by the resetter as reset.ErrConfirmMismatch) maps to PermissionDenied.
func TestReset_MismatchIsPermissionDenied(t *testing.T) {
	rst := &mockResetter{err: reset.ErrConfirmMismatch}
	srv, err := NewLocal(ServerConfig{Auditor: &mockAuditor{}, Resetter: rst})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	_, err = srv.Reset(context.Background(), &cryptosv1.ResetRequest{ConfirmCommonName: "WRONG"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if !rst.called || rst.lastCN != "WRONG" {
		t.Fatalf("resetter not called with confirm CN: called=%v cn=%q", rst.called, rst.lastCN)
	}
}

// TestReset_SuccessReturnsResponse verifies that a successful reset returns a
// ResetResponse and the resetter saw the supplied confirm_common_name.
func TestReset_SuccessReturnsResponse(t *testing.T) {
	rst := &mockResetter{}
	srv, err := NewLocal(ServerConfig{Auditor: &mockAuditor{}, Resetter: rst})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	resp, err := srv.Reset(context.Background(), &cryptosv1.ResetRequest{ConfirmCommonName: "Root CA G1"})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if resp == nil {
		t.Fatalf("nil ResetResponse")
	}
	if !rst.called || rst.lastCN != "Root CA G1" {
		t.Fatalf("resetter not called with confirm CN: called=%v cn=%q", rst.called, rst.lastCN)
	}
}

func TestSignCSR_StubReturnsUnimplemented(t *testing.T) {
	fx := newFixtures(t)
	addr, _ := startTestServer(t, ServerConfig{
		Auditor:     &mockAuditor{},
		Identity:    &mockIdentity{},
		Status:      &mockStatus{},
		Ceremony:    &mockCeremony{},
		ConfigStore: &mockConfigStore{},
	}, fx)
	client, closeConn := dial(t, addr, fx)
	defer closeConn()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.SignCSR(ctx, &cryptosv1.SignCSRRequest{CsrDer: []byte("anything"), Profile: "test"})
	if err == nil {
		t.Fatalf("SignCSR should be UNIMPLEMENTED in prod build")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", st.Code())
	}
}
