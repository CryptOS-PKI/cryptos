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

// setManagementFixtureConfig returns a fully-populated MachineConfig
// standing in for "the node's currently persisted config", so the
// no-clobber assertions have real role/network/bootstrap/pki content to
// check for preservation.
func setManagementFixtureConfig() *cryptosv1.MachineConfig {
	return &cryptosv1.MachineConfig{
		ApiVersion: "cryptos.dev/v1alpha1",
		Kind:       "MachineConfig",
		Metadata:   &cryptosv1.Metadata{Name: "node-1"},
		Role:       &cryptosv1.Role{Kind: "root"},
		Network:    &cryptosv1.Network{Interface: "eth0", Address: "10.0.0.10/24", Gateway: "10.0.0.1"},
		Bootstrap:  &cryptosv1.Bootstrap{AdminCertPem: "admin-cert-pem", AdminCertSha256: "admin-cert-sha256"},
		Pki:        &cryptosv1.Pki{RootKeyAlg: "ECDSA-P384", RootValidityYears: 20},
		Management: &cryptosv1.Management{ManagerCn: "old-fm"},
	}
}

// TestSetManagement_MergesWithoutClobbering verifies that SetManagement
// reads the node's current config, replaces only the Management field, and
// hands that merged config to Apply -- proving the RPC is a
// read-modify-write over the node's own config rather than a whole-config
// replace that would drop role/network/bootstrap/pki.
func TestSetManagement_MergesWithoutClobbering(t *testing.T) {
	cur := setManagementFixtureConfig()
	store := &mockConfigStore{
		current: cur,
		resp:    &cryptosv1.ApplyConfigResponse{Generation: 3, RequiresReboot: true},
	}
	srv, err := New(ServerConfig{
		TLSConfig:   newFixtures(t).serverConf,
		Auditor:     &mockAuditor{},
		ConfigStore: store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	newManagement := &cryptosv1.Management{ManagerCn: "new-fm", TrustPem: "trust-pem"}
	resp, err := srv.SetManagement(context.Background(), &cryptosv1.SetManagementRequest{Management: newManagement})
	if err != nil {
		t.Fatalf("SetManagement: %v", err)
	}

	if store.last == nil {
		t.Fatalf("Apply was not called")
	}
	if !proto.Equal(store.last.GetManagement(), newManagement) {
		t.Errorf("Apply got Management = %v, want %v", store.last.GetManagement(), newManagement)
	}

	// Everything else must be byte-for-byte what Current returned: build the
	// expected config as a copy of cur with only Management swapped, and
	// compare the whole message so no field can silently regress.
	want := proto.Clone(cur).(*cryptosv1.MachineConfig)
	want.Management = newManagement
	if !proto.Equal(store.last, want) {
		t.Errorf("Apply got config = %v, want %v (no-clobber merge)", store.last, want)
	}

	if resp.GetGeneration() != 3 || !resp.GetRequiresReboot() {
		t.Errorf("SetManagement response = %v, want Generation=3 RequiresReboot=true", resp)
	}
}

// TestSetManagement_NilManagementUnlinks verifies that SetManagement with a
// nil Management clears the field on the merged config (unlink from the
// Fleet Manager) rather than leaving the old value or refusing the call.
func TestSetManagement_NilManagementUnlinks(t *testing.T) {
	cur := setManagementFixtureConfig() // Management is set on the fixture
	store := &mockConfigStore{
		current: cur,
		resp:    &cryptosv1.ApplyConfigResponse{Generation: 4},
	}
	srv, err := New(ServerConfig{
		TLSConfig:   newFixtures(t).serverConf,
		Auditor:     &mockAuditor{},
		ConfigStore: store,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := srv.SetManagement(context.Background(), &cryptosv1.SetManagementRequest{Management: nil}); err != nil {
		t.Fatalf("SetManagement: %v", err)
	}

	if store.last == nil {
		t.Fatalf("Apply was not called")
	}
	if store.last.GetManagement() != nil {
		t.Errorf("Apply got Management = %v, want nil (unlink)", store.last.GetManagement())
	}
	want := proto.Clone(cur).(*cryptosv1.MachineConfig)
	want.Management = nil
	if !proto.Equal(store.last, want) {
		t.Errorf("Apply got config = %v, want %v (unlink, no-clobber)", store.last, want)
	}
}

// TestSetManagement_UnimplementedWhenNoConfigStore verifies that with a nil
// ConfigStore (the maintenance servers) the RPC refuses with Unimplemented,
// mirroring the other running-node-only RPCs.
func TestSetManagement_UnimplementedWhenNoConfigStore(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
		// ConfigStore intentionally nil.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = srv.SetManagement(context.Background(), &cryptosv1.SetManagementRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("SetManagement code = %v, want Unimplemented", status.Code(err))
	}
}

// TestSetManagement_UnauthorizedIsDenied verifies that a caller who fails
// AuthorizeAdmin is denied before Current/Apply are ever consulted.
func TestSetManagement_UnauthorizedIsDenied(t *testing.T) {
	trust := trustForCert(t, authzTestCert(t))
	store := &mockConfigStore{current: setManagementFixtureConfig()}
	srv, err := New(ServerConfig{
		TLSConfig:   newFixtures(t).serverConf,
		Auditor:     &mockAuditor{},
		ConfigStore: store,
		Trust:       trust,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := authzMTLSContext(authzTestCert(t)) // a different cert than the trust
	_, err = srv.SetManagement(ctx, &cryptosv1.SetManagementRequest{Management: &cryptosv1.Management{ManagerCn: "new-fm"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("SetManagement code = %v, want PermissionDenied", status.Code(err))
	}
	if store.last != nil {
		t.Fatalf("Apply was consulted despite a denied caller")
	}
}
