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
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// TestApplyConfig_StatusCodes verifies the running-node ApplyConfig handler
// keeps a status error from the store (InvalidArgument for a config that
// fails validation) and reports any other store error as Internal, never
// Unknown.
func TestApplyConfig_StatusCodes(t *testing.T) {
	tests := []struct {
		name     string
		storeErr error
		want     codes.Code
	}{
		{"invalid config passes through", status.Error(codes.InvalidArgument, "validate: bad"), codes.InvalidArgument},
		{"plain store error is internal", errors.New("disk full"), codes.Internal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(ServerConfig{
				TLSConfig:   newFixtures(t).serverConf,
				Auditor:     &mockAuditor{},
				ConfigStore: &mockConfigStore{err: tc.storeErr},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = srv.ApplyConfig(context.Background(), &cryptosv1.ApplyConfigRequest{Config: setManagementFixtureConfig()})
			if got := status.Code(err); got != tc.want {
				t.Errorf("ApplyConfig code = %v, want %v (err: %v)", got, tc.want, err)
			}
		})
	}
}

// TestSetManagement_InvalidConfigIsInvalidArgument verifies that when the
// merged config fails validation in the store, SetManagement reports
// InvalidArgument rather than Internal.
func TestSetManagement_InvalidConfigIsInvalidArgument(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
		ConfigStore: &mockConfigStore{
			current: setManagementFixtureConfig(),
			err:     status.Error(codes.InvalidArgument, "validate: management.trust_pem: required"),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = srv.SetManagement(context.Background(), &cryptosv1.SetManagementRequest{Management: &cryptosv1.Management{ManagerCn: "fm"}})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("SetManagement code = %v, want InvalidArgument (err: %v)", got, err)
	}
}
