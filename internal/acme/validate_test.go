package acme

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
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// validateAgainst runs the real validation body against an httptest server.
// Production always dials port 80, which a test cannot bind, so the port is
// passed explicitly here; everything else is the code path that runs live.
func validateAgainst(t *testing.T, handler http.HandlerFunc, token, keyAuth string) error {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxChallengeRedirects {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return errors.New("unsupported scheme")
			}
			return nil
		},
	}
	host, port := splitAddr(t, srv.Listener.Addr().String())
	return validateHTTP01(context.Background(), client, host, port, token, keyAuth)
}

// splitAddr breaks a listener address into the host and port the validator
// takes separately.
func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}
	return host, port
}

func TestHTTP01Accepts(t *testing.T) {
	const token, keyAuth = "tok123", "tok123.thumbprint"
	err := validateAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ChallengePathPrefix+token {
			t.Errorf("validator fetched %q, want %q", r.URL.Path, ChallengePathPrefix+token)
		}
		_, _ = w.Write([]byte(keyAuth))
	}, token, keyAuth)
	if err != nil {
		t.Fatalf("validateHTTP01: %v", err)
	}
}

// A key authorization written with a shell redirect picks up a newline, which
// RFC 8555 section 8.3 tells servers to tolerate.
func TestHTTP01ToleratesTrailingWhitespace(t *testing.T) {
	const token, keyAuth = "tok", "tok.thumb"
	err := validateAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(keyAuth + "\n"))
	}, token, keyAuth)
	if err != nil {
		t.Fatalf("validateHTTP01: %v", err)
	}
}

func TestHTTP01Rejects(t *testing.T) {
	const token, keyAuth = "tok", "tok.thumb"

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		problem string
	}{
		{
			name:    "wrong body",
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("tok.someone-else")) },
			problem: ErrIncorrectResponse,
		},
		{
			name:    "empty body",
			handler: func(http.ResponseWriter, *http.Request) {},
			problem: ErrIncorrectResponse,
		},
		{
			name:    "not found",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) },
			problem: ErrUnauthorized,
		},
		{
			name: "oversized body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("A", maxChallengeBody+1)))
			},
			problem: ErrIncorrectResponse,
		},
		{
			// A prefix of the key authorization must not pass: the comparison
			// is on the whole value, not a prefix.
			name:    "truncated key authorization",
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(keyAuth[:len(keyAuth)-1])) },
			problem: ErrIncorrectResponse,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAgainst(t, tc.handler, token, keyAuth)
			var prob *Problem
			if !errors.As(err, &prob) {
				t.Fatalf("err = %v, want a Problem", err)
			}
			if prob.Type != tc.problem {
				t.Fatalf("problem = %q, want %q", prob.Type, tc.problem)
			}
		})
	}
}

func TestHTTP01StopsRedirectLoop(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxChallengeRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	host, port := splitAddr(t, srv.Listener.Addr().String())
	err := validateHTTP01(context.Background(), client, host, port, "tok", "tok.thumb")
	var prob *Problem
	if !errors.As(err, &prob) || prob.Type != ErrConnection {
		t.Fatalf("err = %v, want a connection problem", err)
	}
}

func TestHTTP01UnreachableHost(t *testing.T) {
	v := HTTP01Validator(500 * time.Millisecond)
	// RFC 6761 reserves .invalid to never resolve.
	err := v(context.Background(), "nothing.invalid", "tok", "tok.thumb")
	var prob *Problem
	if !errors.As(err, &prob) || prob.Type != ErrConnection {
		t.Fatalf("err = %v, want a connection problem", err)
	}
}
