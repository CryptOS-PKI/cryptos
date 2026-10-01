package grpc

/*
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

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// TestUnservedRPCs_ReturnUnimplemented pins the answer for the NodeService
// RPCs in the node API contract that this build does not serve yet: Unimplemented,
// never a panic or a silent empty success.
func TestUnservedRPCs_ReturnUnimplemented(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	calls := map[string]func() error{
		"ListTsaCertificates": func() error {
			_, err := srv.ListTsaCertificates(ctx, &nodev1.ListTsaCertificatesRequest{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			if got := status.Code(call()); got != codes.Unimplemented {
				t.Errorf("%s code = %v, want Unimplemented", name, got)
			}
		})
	}
}
