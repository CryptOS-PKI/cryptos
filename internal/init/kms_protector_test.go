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

	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/kms"
)

// fakeProvider seals by XORing with a fixed pad and unseals by XORing again
// (its own inverse), standing in for a KEK without any network.
type fakeProvider struct{ pad byte }

func (f fakeProvider) transform(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ f.pad
	}
	return out
}

func (f fakeProvider) Seal(_ context.Context, plaintext []byte) ([]byte, error) {
	return f.transform(plaintext), nil
}

func (f fakeProvider) Unseal(_ context.Context, blob []byte) ([]byte, error) {
	return f.transform(blob), nil
}

func newTestKMSProtector() *kmsProtector {
	p, _ := newKMSProtector(&config.KmsStateKey{Endpoint: "https://kms.example"})
	p.newProvider = func(_ string, _ []byte) (kms.Provider, error) {
		return fakeProvider{pad: 0x5a}, nil
	}
	return p
}

func TestKMSProtector_NameAndPersists(t *testing.T) {
	p := newTestKMSProtector()
	if p.Name() != "kms" {
		t.Errorf("Name() = %q, want kms", p.Name())
	}
	if !p.PersistsToken() {
		t.Error("PersistsToken() = false, want true")
	}
}

func TestKMSProtector_ProvisionRecoverRoundTrip(t *testing.T) {
	p := newTestKMSProtector()

	key, token, err := p.ProvisionKey(context.Background())
	if err != nil {
		t.Fatalf("ProvisionKey: %v", err)
	}
	if len(key) != stateKeyBytes {
		t.Fatalf("key length = %d, want %d", len(key), stateKeyBytes)
	}
	if len(token) == 0 {
		t.Fatal("ProvisionKey returned an empty token")
	}
	if bytes.Contains(token, key) {
		t.Fatal("the DEK plaintext must not appear in the persisted token")
	}

	got, err := p.RecoverKey(context.Background(), token)
	if err != nil {
		t.Fatalf("RecoverKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("RecoverKey returned a different DEK: got %x, want %x", got, key)
	}
}

func TestKMSProtector_RecoverMalformedTokenErrors(t *testing.T) {
	p := newTestKMSProtector()
	if _, err := p.RecoverKey(context.Background(), []byte("{not json")); err == nil {
		t.Fatal("a malformed token must error")
	}
	if _, err := p.RecoverKey(context.Background(), []byte(`{"sealed":"AAAA"}`)); err == nil {
		t.Fatal("a token with no endpoint must error")
	}
}

func TestNewKMSProtector_RequiresEndpoint(t *testing.T) {
	if _, err := newKMSProtector(nil); err == nil {
		t.Fatal("nil kms config must error")
	}
	if _, err := newKMSProtector(&config.KmsStateKey{}); err == nil {
		t.Fatal("an empty endpoint must error")
	}
}
