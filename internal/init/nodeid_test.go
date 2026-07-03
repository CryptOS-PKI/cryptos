package init

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
)

func fixedUUID(s string) func() (string, error) {
	return func() (string, error) { return s, nil }
}

func TestNodeIDProtector_Deterministic(t *testing.T) {
	p := newNodeIDProtector(fixedUUID("564d1234-0000-0000-0000-abcdef012345"), "cryptos-state")
	k1, tok, err := p.ProvisionKey(context.Background())
	if err != nil {
		t.Fatalf("ProvisionKey: %v", err)
	}
	if tok != nil {
		t.Errorf("nodeID must not persist a token, got %d bytes", len(tok))
	}
	if len(k1) != stateKeyBytes {
		t.Fatalf("key len = %d, want %d", len(k1), stateKeyBytes)
	}
	k2, err := p.RecoverKey(context.Background(), nil)
	if err != nil {
		t.Fatalf("RecoverKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("ProvisionKey and RecoverKey derived different keys")
	}
	if p.PersistsToken() {
		t.Error("PersistsToken must be false")
	}
	if p.Name() != "nodeid" {
		t.Errorf("Name = %q", p.Name())
	}
}

func TestNodeIDProtector_UUIDSensitive(t *testing.T) {
	a, _, _ := newNodeIDProtector(fixedUUID("aaaaaaaa-0000-0000-0000-000000000001"), "cryptos-state").ProvisionKey(context.Background())
	b, _, _ := newNodeIDProtector(fixedUUID("bbbbbbbb-0000-0000-0000-000000000002"), "cryptos-state").ProvisionKey(context.Background())
	if bytes.Equal(a, b) {
		t.Error("different UUIDs produced the same key")
	}
}

func TestNodeIDProtector_RejectsEmptyAndZero(t *testing.T) {
	for _, u := range []string{"", "00000000-0000-0000-0000-000000000000"} {
		p := newNodeIDProtector(fixedUUID(u), "cryptos-state")
		if _, _, err := p.ProvisionKey(context.Background()); err == nil {
			t.Errorf("UUID %q: want error, got nil", u)
		}
	}
}

// TestReadProductUUID_SmokeTest verifies readProductUUID returns either a
// non-empty string or an error; it must never panic. The sysfs path may not
// be readable in all test environments (CI, containers), so errors are
// acceptable.
func TestReadProductUUID_SmokeTest(t *testing.T) {
	uuid, err := readProductUUID()
	if err == nil && uuid == "" {
		t.Error("readProductUUID returned empty string without error")
	}
}
