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
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// freePort binds an ephemeral port, closes it, and returns the address, giving
// a very-likely-free host:port for a Serve reachability test.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestServeIsListeningWhenItReturns(t *testing.T) {
	addr := freePort(t)
	h := NewHandler(func(context.Context) ([]byte, error) { return []byte{0x30, 0x01}, nil }, nil, nil)
	stop, err := Serve(context.Background(), addr, h)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer func() { _ = stop(context.Background()) }()
	// No sleep: a synchronous bind means the endpoint answers the instant Serve
	// returns. The node's startup preflight relies on exactly this.
	resp, err := http.Get("http://" + addr + "/crl")
	if err != nil {
		t.Fatalf("immediate GET /crl failed (listener not up on return): %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
}

func TestServeSurfacesBindError(t *testing.T) {
	// Occupy a port, then Serve on it must fail synchronously (the prior
	// goroutine-bind returned nil and swallowed the error).
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	h := NewHandler(func(context.Context) ([]byte, error) { return nil, nil }, nil, nil)
	stop, err := Serve(context.Background(), occupied.Addr().String(), h)
	if err == nil {
		if stop != nil {
			_ = stop(context.Background())
		}
		t.Fatal("Serve on an occupied port returned nil error, want a bind failure")
	}
}

func TestCRLEndpointServesDER(t *testing.T) {
	want := []byte{0x30, 0x01} // stand-in DER
	h := NewHandler(func(context.Context) ([]byte, error) { return want, nil }, nil, nil)
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
	h := NewHandler(func(context.Context) ([]byte, error) { return nil, nil }, nil, nil)
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

func TestOCSPEndpointPOSTServesResponse(t *testing.T) {
	want := []byte{0x30, 0x03} // stand-in OCSP response DER
	var gotReq []byte
	h := NewHandler(
		func(context.Context) ([]byte, error) { return nil, nil },
		func(_ context.Context, reqDER []byte) ([]byte, error) {
			gotReq = reqDER
			return want, nil
		},
		nil,
	)
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()
	reqBody := []byte{0x30, 0x01}
	resp, err := http.Post(srv.URL+"/ocsp", "application/ocsp-request", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /ocsp: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/ocsp-response" {
		t.Fatalf("status=%d ctype=%s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !bytes.Equal(gotReq, reqBody) {
		t.Fatalf("handler received %x, want %x", gotReq, reqBody)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, want) {
		t.Fatalf("body=%x, want %x", body, want)
	}
}

func TestCACertEndpointServesDER(t *testing.T) {
	want := []byte{0x30, 0x02} // stand-in certificate DER
	noCRL := func(context.Context) ([]byte, error) { return nil, nil }
	h := NewHandler(noCRL, nil, func(context.Context) ([]byte, error) { return want, nil })
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + CACertPath)
	if err != nil {
		t.Fatalf("GET %s: %v", CACertPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/pkix-cert" {
		t.Fatalf("status=%d ctype=%s, want 200 application/pkix-cert", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, want) {
		t.Fatalf("body=%x, want %x", body, want)
	}
}

func TestCACertEndpointFailures(t *testing.T) {
	noCRL := func(context.Context) ([]byte, error) { return nil, nil }
	serve := func(context.Context) ([]byte, error) { return []byte{0x30, 0x00}, nil }
	for _, tc := range []struct {
		name   string
		caCert func(context.Context) ([]byte, error)
		method string
		want   int
	}{
		// A non-GET is refused, as on /crl.
		{"post", serve, http.MethodPost, http.StatusMethodNotAllowed},
		// No certificate yet (a subordinate still awaiting its chain) must answer
		// 5xx so the preflight fails closed rather than passing on an empty body.
		{"no certificate", func(context.Context) ([]byte, error) { return nil, errors.New("no chain") }, http.MethodGet, http.StatusInternalServerError},
		{"empty certificate", func(context.Context) ([]byte, error) { return nil, nil }, http.MethodGet, http.StatusInternalServerError},
		{"unwired", nil, http.MethodGet, http.StatusNotImplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(NewHandler(noCRL, nil, tc.caCert).Routes())
			defer srv.Close()
			req, err := http.NewRequest(tc.method, srv.URL+CACertPath, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", tc.method, CACertPath, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Fatalf("status=%d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}
