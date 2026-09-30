package config

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
	"strings"
	"testing"
)

// The state-key mode is fixed when the volume is sealed at install. A config
// may repeat it or leave it empty, but may not name another mode.
func TestStateKeyCheckSealed(t *testing.T) {
	cases := []struct {
		name, configured, sealed string
		wantErr                  bool
	}{
		{"empty keeps the sealed mode", "", StateKeyModeTPM, false},
		{"same mode", StateKeyModeNodeID, StateKeyModeNodeID, false},
		{"tpm on a nodeid volume", StateKeyModeTPM, StateKeyModeNodeID, true},
		{"nodeid on a tpm volume", StateKeyModeNodeID, StateKeyModeTPM, true},
		{"kms on a tpm volume", StateKeyModeKMS, StateKeyModeTPM, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := StateKey{Mode: tc.configured}.CheckSealed(tc.sealed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckSealed = %v, want error %v", err, tc.wantErr)
			}
			if err != nil && (!strings.Contains(err.Error(), tc.configured) || !strings.Contains(err.Error(), tc.sealed)) {
				t.Errorf("error %q should name both modes", err)
			}
		})
	}
}
