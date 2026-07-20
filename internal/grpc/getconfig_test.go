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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// TestGetConfig_ReturnsCurrentConfig verifies that GetConfig returns the
// node's currently persisted machine config unchanged, so a caller can fetch
// the full config before editing a subset of it.
func TestGetConfig_ReturnsCurrentConfig(t *testing.T) {
	cur := setManagementFixtureConfig()
	cur.Pki.RevocationBaseUrl = "http://ca.example/crl"
	store := &mockConfigStore{current: cur}
	srv, err := New(ServerConfig{
		TLSConfig:   newFixtures(t).serverConf,
		Auditor:     &mockAuditor{},
		ConfigStore: store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp, err := srv.GetConfig(context.Background(), &cryptosv1.GetConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !proto.Equal(resp.GetConfig(), cur) {
		t.Errorf("GetConfig returned %v, want %v", resp.GetConfig(), cur)
	}
	// Spot-check the key fields the fleet/web flow round-trips.
	if got := resp.GetConfig().GetRole().GetKind(); got != "root" {
		t.Errorf("role = %q, want root", got)
	}
	if got := resp.GetConfig().GetManagement().GetManagerCn(); got != "old-fm" {
		t.Errorf("management.manager_cn = %q, want old-fm", got)
	}
	if got := resp.GetConfig().GetPki().GetRevocationBaseUrl(); got != "http://ca.example/crl" {
		t.Errorf("pki.revocation_base_url = %q, want http://ca.example/crl", got)
	}
}

// TestGetConfig_UnimplementedWhenNoConfigStore verifies that with a nil
// ConfigStore (the maintenance servers) the RPC refuses with Unimplemented,
// mirroring SetManagement and the other running-node-only RPCs.
func TestGetConfig_UnimplementedWhenNoConfigStore(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
		// ConfigStore intentionally nil.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = srv.GetConfig(context.Background(), &cryptosv1.GetConfigRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("GetConfig code = %v, want Unimplemented", status.Code(err))
	}
}

// TestGetConfig_ErrorFromStoreIsInternal verifies that a read failure from the
// config store surfaces as Internal rather than a nil response.
func TestGetConfig_ErrorFromStoreIsInternal(t *testing.T) {
	store := &mockConfigStore{currentErr: context.DeadlineExceeded}
	srv, err := New(ServerConfig{
		TLSConfig:   newFixtures(t).serverConf,
		Auditor:     &mockAuditor{},
		ConfigStore: store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = srv.GetConfig(context.Background(), &cryptosv1.GetConfigRequest{})
	if status.Code(err) != codes.Internal {
		t.Errorf("GetConfig code = %v, want Internal", status.Code(err))
	}
}
