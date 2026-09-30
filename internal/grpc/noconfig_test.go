package grpc

/*
Apache License 2.0

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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

// emptyConfigStore is the real node config store over a directory that has
// never had a config written to it.
func emptyConfigStore(t *testing.T) *node.ConfigStore {
	t.Helper()
	return node.NewConfigStore(config.NewFileStore(t.TempDir()))
}

// A node with no persisted config is not ready, not broken: the caller has to
// apply a config first, so the code must say so instead of Internal.
func TestGetConfig_NoPersistedConfigIsFailedPrecondition(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig:   newFixtures(t).serverConf,
		Auditor:     &mockAuditor{},
		ConfigStore: emptyConfigStore(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = srv.GetConfig(context.Background(), &cryptosv1.GetConfigRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("GetConfig code = %v (%v), want FailedPrecondition", status.Code(err), err)
	}
}

func TestSetManagement_NoPersistedConfigIsFailedPrecondition(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig:   newFixtures(t).serverConf,
		Auditor:     &mockAuditor{},
		ConfigStore: emptyConfigStore(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = srv.SetManagement(context.Background(), &cryptosv1.SetManagementRequest{Management: &cryptosv1.Management{ManagerCn: "fm"}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("SetManagement code = %v (%v), want FailedPrecondition", status.Code(err), err)
	}
}
