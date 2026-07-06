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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrPreflightFailed wraps every revocation preflight failure so callers can
// match it with errors.Is regardless of the underlying resolver or probe error.
var ErrPreflightFailed = errors.New("revocation: preflight failed")

// Preflight verifies that a configured revocation base URL is actually usable
// before issuance stamps a CDP/AIA pointer at it: the host must resolve and the
// local /crl and /ocsp endpoints must answer. It caches the last-good result so
// the signer can consult OK() cheaply on the hot path; a background caller
// re-runs Check to refresh it.
type Preflight struct {
	baseURL  string
	resolver func(host string) error
	probe    func(url string) error

	mu sync.Mutex
	ok bool
}

// NewPreflight constructs a Preflight for baseURL. resolver reports whether the
// URL host resolves (production: DefaultResolver); probe reports whether an
// endpoint URL answers (production: an HTTP GET). Both are injectable so the
// check is hermetic under test.
func NewPreflight(baseURL string, resolver func(host string) error, probe func(url string) error) *Preflight {
	return &Preflight{baseURL: baseURL, resolver: resolver, probe: probe}
}

// Check resolves the base-URL host and probes <base>/crl and <base>/ocsp. On
// success it caches ok=true and returns nil; on any failure it caches ok=false
// and returns an error wrapping ErrPreflightFailed. The cached result is read
// via OK.
func (p *Preflight) Check(_ context.Context) error {
	err := p.run()
	p.mu.Lock()
	p.ok = err == nil
	p.mu.Unlock()
	return err
}

// run performs the resolution and probes without touching cached state, so the
// mutation in Check is a single guarded assignment.
func (p *Preflight) run() error {
	u, err := url.Parse(p.baseURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: parse base URL %q: %v", ErrPreflightFailed, p.baseURL, err)
	}
	if err := p.resolver(u.Hostname()); err != nil {
		return fmt.Errorf("%w: resolve %q: %v", ErrPreflightFailed, u.Hostname(), err)
	}
	base := strings.TrimSuffix(p.baseURL, "/")
	for _, path := range []string{"/crl", "/ocsp"} {
		if err := p.probe(base + path); err != nil {
			return fmt.Errorf("%w: probe %s: %v", ErrPreflightFailed, base+path, err)
		}
	}
	return nil
}

// OK reports the result of the most recent Check. It is false until Check has
// run and succeeded.
func (p *Preflight) OK() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ok
}

// Ensure returns the current OK state, running one fresh Check first when the
// cached result is not OK. It lets an issuance path self-heal: a subordinate
// runs its first preflight while still in AWAITING_CERT (no cert, so /crl
// answers 5xx and the check fails), and without a re-check issuance would stay
// blocked until the next periodic tick. Ensure re-checks on demand so the first
// issuance after establishment succeeds. The fresh Check is skipped when the
// cached result is already OK, so the common path stays cheap.
func (p *Preflight) Ensure(ctx context.Context) bool {
	if p.OK() {
		return true
	}
	_ = p.Check(ctx)
	return p.OK()
}

// DefaultResolver resolves host via net.DefaultResolver. It is the production
// resolver passed to NewPreflight.
func DefaultResolver(host string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses for %q", host)
	}
	return nil
}

// DefaultProbe issues an HTTP GET against endpoint and treats any non-5xx
// response as reachable (a 404 still proves the listener is up). It is the
// production probe passed to NewPreflight.
func DefaultProbe(endpoint string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(endpoint) //nolint:noctx // short fixed-timeout preflight probe
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("endpoint %s returned %d", endpoint, resp.StatusCode)
	}
	return nil
}
