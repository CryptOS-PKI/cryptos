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
	"crypto/tls"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

// mtlsTLSConfig returns a minimal server TLS config that satisfies New's
// mTLS minima (TLS 1.3, RequireAndVerifyClientCert). The handler tests
// invoke the RPC directly with a synthetic peer context, so no handshake
// runs and no certificate material is needed here.
func mtlsTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
}

// maintenanceTLSConfig returns a server TLS config that satisfies
// NewMaintenance (TLS 1.3, NoClientCert).
func maintenanceTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.NoClientCert,
	}
}

// mtlsServerWithRemoteReset builds an mTLS Server carrying the supplied
// RemoteResetter and a Trust pinned to admin, mirroring how the mTLS
// listener is wired in internal/init. The Resetter field is intentionally
// left nil, so the local-only Reset stays refused on this server.
func mtlsServerWithRemoteReset(t *testing.T, rr Resetter) *Server {
	t.Helper()
	admin := authzTestCert(t)
	srv, err := New(ServerConfig{
		TLSConfig:      mtlsTLSConfig(t),
		Auditor:        &mockAuditor{},
		RemoteResetter: rr,
		Trust:          trustForCert(t, admin),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// TestRemoteReset_UnimplementedWhenNoResetter verifies that a server with no
// RemoteResetter wired (the local console socket and the maintenance servers)
// refuses RemoteReset with Unimplemented, before any auth is considered.
func TestRemoteReset_UnimplementedWhenNoResetter(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig: mtlsTLSConfig(t),
		Auditor:   &mockAuditor{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = srv.RemoteReset(context.Background(), &cryptosv1.RemoteResetRequest{ConfirmCommonName: "anything"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}

// TestRemoteReset_NonAdminIsPermissionDenied verifies that a caller whose
// client certificate is not the pinned bootstrap admin is denied and the
// destructive resetter is never invoked.
func TestRemoteReset_NonAdminIsPermissionDenied(t *testing.T) {
	rst := &mockResetter{}
	srv := mtlsServerWithRemoteReset(t, rst)

	other := authzTestCert(t)
	_, err := srv.RemoteReset(authzMTLSContext(other), &cryptosv1.RemoteResetRequest{ConfirmCommonName: "Root CA G1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if rst.called {
		t.Fatalf("resetter must not be invoked for a non-admin caller")
	}
}

// TestRemoteReset_AdminWrongCNIsPermissionDenied verifies that an authorized
// admin who echoes the wrong Root CA CN is denied (reset.ErrConfirmMismatch
// mapped to PermissionDenied) and no wipe committed. The resetter is consulted
// (it owns the constant-time CN compare) but takes no destructive action.
func TestRemoteReset_AdminWrongCNIsPermissionDenied(t *testing.T) {
	rst := &mockResetter{err: reset.ErrConfirmMismatch}
	admin := authzTestCert(t)
	srv, err := New(ServerConfig{
		TLSConfig:      mtlsTLSConfig(t),
		Auditor:        &mockAuditor{},
		RemoteResetter: rst,
		Trust:          trustForCert(t, admin),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = srv.RemoteReset(authzMTLSContext(admin), &cryptosv1.RemoteResetRequest{ConfirmCommonName: "WRONG"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if !rst.called || rst.lastCN != "WRONG" {
		t.Fatalf("resetter not consulted with confirm CN: called=%v cn=%q", rst.called, rst.lastCN)
	}
}

// TestRemoteReset_AdminCorrectCNInvokesResetter verifies that an authorized
// admin who echoes the correct Root CA CN drives the destructive path and
// receives a rebooting response.
func TestRemoteReset_AdminCorrectCNInvokesResetter(t *testing.T) {
	rst := &mockResetter{}
	admin := authzTestCert(t)
	srv, err := New(ServerConfig{
		TLSConfig:      mtlsTLSConfig(t),
		Auditor:        &mockAuditor{},
		RemoteResetter: rst,
		Trust:          trustForCert(t, admin),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := srv.RemoteReset(authzMTLSContext(admin), &cryptosv1.RemoteResetRequest{ConfirmCommonName: "Root CA G1"})
	if err != nil {
		t.Fatalf("RemoteReset: %v", err)
	}
	if resp == nil || !resp.GetRebooting() {
		t.Fatalf("want rebooting response, got %+v", resp)
	}
	if !rst.called || rst.lastCN != "Root CA G1" {
		t.Fatalf("resetter not invoked with confirm CN: called=%v cn=%q", rst.called, rst.lastCN)
	}
}

// TestRemoteReset_UnavailableInMaintenance verifies that the maintenance
// server (built with NewMaintenance and no RemoteResetter) refuses RemoteReset
// with Unimplemented, so remote decommission is never reachable there.
func TestRemoteReset_UnavailableInMaintenance(t *testing.T) {
	srv, err := NewMaintenance(ServerConfig{
		TLSConfig: maintenanceTLSConfig(t),
		Auditor:   &mockAuditor{},
	})
	if err != nil {
		t.Fatalf("NewMaintenance: %v", err)
	}
	_, err = srv.RemoteReset(context.Background(), &cryptosv1.RemoteResetRequest{ConfirmCommonName: "anything"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}

// TestReset_UnimplementedOnMTLS is the companion guarantee: even when the mTLS
// server carries a RemoteResetter, the local-only Reset RPC stays refused there
// (its Resetter field is nil), so the boundary relaxation does not leak the
// unauthenticated local semantics onto the network.
func TestReset_UnimplementedOnMTLS(t *testing.T) {
	srv := mtlsServerWithRemoteReset(t, &mockResetter{})
	_, err := srv.Reset(context.Background(), &cryptosv1.ResetRequest{ConfirmCommonName: "anything"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Reset on mTLS: code = %v, want Unimplemented", status.Code(err))
	}
}
