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
	"crypto/x509"
	"errors"
	"testing"
)

// The caIssuers endpoint serves the node's own CA certificate exactly as it
// sits in the identity chain, and fails while the node has none.
func TestCACertFnServesIssuerDER(t *testing.T) {
	want := &x509.Certificate{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
	r := &nodeRevoker{issuer: func(context.Context) (*x509.Certificate, error) { return want, nil }}
	got, err := r.caCertFn()(context.Background())
	if err != nil {
		t.Fatalf("caCertFn: %v", err)
	}
	if !bytes.Equal(got, want.Raw) {
		t.Fatalf("caCertFn = %x, want %x", got, want.Raw)
	}

	r = &nodeRevoker{issuer: func(context.Context) (*x509.Certificate, error) { return nil, errors.New("no chain") }}
	if _, err := r.caCertFn()(context.Background()); err == nil {
		t.Fatal("caCertFn with no issuer certificate returned nil error")
	}
}
