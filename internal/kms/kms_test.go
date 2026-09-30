package kms

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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// xorPad is the fixed pad the fake KMS XORs plaintext with to "seal" it; the
// same XOR reverses it on unseal. It stands in for a KEK.
var xorPad = []byte{0x5a, 0xa5, 0x3c, 0xc3}

func xorWith(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ xorPad[i%len(xorPad)]
	}
	return out
}

// fakeKMS is an httptest server that seals by XORing with a fixed pad and
// unseals by XORing again (its own inverse), through the same base64 JSON
// envelope the adapter speaks.
func fakeKMS(t *testing.T) *httptest.Server {
	t.Helper()
	transform := func(w http.ResponseWriter, r *http.Request) {
		var in sealUnsealBody
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(in.Data)
		if err != nil {
			http.Error(w, "bad base64", http.StatusBadRequest)
			return
		}
		resp := sealUnsealBody{Data: base64.StdEncoding.EncodeToString(xorWith(payload))}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/seal", transform)
	mux.HandleFunc("/unseal", transform)
	return httptest.NewServer(mux)
}

func TestHTTPProvider_SealUnsealRoundTrip(t *testing.T) {
	srv := fakeKMS(t)
	defer srv.Close()

	prov, err := NewHTTPProvider(srv.URL, nil)
	if err != nil {
		t.Fatalf("NewHTTPProvider: %v", err)
	}

	want := []byte("this-is-a-32-byte-example-dek!!!")
	sealed, err := prov.Seal(context.Background(), want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(sealed, want) {
		t.Fatal("sealed blob must differ from the plaintext")
	}
	got, err := prov.Unseal(context.Background(), sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Unseal(Seal(x)) = %q, want %q", got, want)
	}
}

func TestNewHTTPProvider_RejectsEmptyEndpoint(t *testing.T) {
	if _, err := NewHTTPProvider("  ", nil); err == nil {
		t.Fatal("empty endpoint must be rejected")
	}
}

func TestNewHTTPProvider_RejectsBadTrustBundle(t *testing.T) {
	if _, err := NewHTTPProvider("https://kms.example", []byte("not a pem")); err == nil {
		t.Fatal("a trust bundle with no valid certificates must be rejected")
	}
}

func TestHTTPProvider_NonOKStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	prov, err := NewHTTPProvider(srv.URL, nil)
	if err != nil {
		t.Fatalf("NewHTTPProvider: %v", err)
	}
	if _, err := prov.Seal(context.Background(), []byte("x")); err == nil {
		t.Fatal("a non-200 KMS response must surface as an error")
	}
}
