package node

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
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// A running node's state volume is sealed in one mode, and init reads the mode
// from the volume on every boot. Apply refuses a config that asks for another
// mode rather than persisting a setting the node would ignore.
func TestConfigStoreApply_RefusesStateKeyModeChange(t *testing.T) {
	seed, err := config.Parse([]byte(applyValidateSeed))
	if err != nil {
		t.Fatalf("config.Parse(seed): %v", err)
	}
	cases := []struct {
		mode string
		want codes.Code
	}{
		{config.StateKeyModeNodeID, codes.FailedPrecondition},
		{config.StateKeyModeKMS, codes.FailedPrecondition},
		{config.StateKeyModeTPM, codes.OK},
		{"", codes.OK},
	}
	for _, tc := range cases {
		t.Run("mode "+tc.mode, func(t *testing.T) {
			fs := config.NewFileStore(t.TempDir())
			if _, err := fs.Write([]byte(applyValidateSeed)); err != nil {
				t.Fatalf("FileStore.Write (seed): %v", err)
			}
			beforeRaw, _, _, _ := fs.Read()

			pb := seed.ToProto()
			pb.StateKey = &cryptosv1.StateKey{Mode: tc.mode}
			if tc.mode == config.StateKeyModeKMS {
				pb.StateKey.Kms = &cryptosv1.KmsStateKey{Endpoint: "https://kms.example"}
			}
			_, err := NewConfigStore(fs).WithSealedStateKeyMode(config.StateKeyModeTPM).Apply(context.Background(), pb)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("Apply code = %v, want %v (err: %v)", got, tc.want, err)
			}
			if tc.want != codes.OK {
				afterRaw, _, _, _ := fs.Read()
				if !bytes.Equal(afterRaw, beforeRaw) {
					t.Error("persisted config changed after a refused Apply")
				}
			}
		})
	}
}
