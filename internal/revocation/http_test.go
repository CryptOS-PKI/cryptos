package revocation

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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCRLEndpointServesDER(t *testing.T) {
	want := []byte{0x30, 0x01} // stand-in DER
	h := NewHandler(func(context.Context) ([]byte, error) { return want, nil }, nil)
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/crl")
	if err != nil {
		t.Fatalf("GET /crl: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/pkix-crl" {
		t.Fatalf("status=%d ctype=%s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, want) {
		t.Fatalf("body=%x, want %x", body, want)
	}
}

func TestOCSPEndpointUnwiredReturns501(t *testing.T) {
	h := NewHandler(func(context.Context) ([]byte, error) { return nil, nil }, nil)
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/ocsp")
	if err != nil {
		t.Fatalf("GET /ocsp: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status=%d, want 501", resp.StatusCode)
	}
}
