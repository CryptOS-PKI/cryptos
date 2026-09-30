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
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ChallengePathPrefix is the well-known path an http-01 response is served
// from (RFC 8555 section 8.3).
const ChallengePathPrefix = "/.well-known/acme-challenge/"

// http01Port is the only port an http-01 validation connects to. RFC 8555
// section 8.3 fixes it at 80 precisely so that control of a high port, which
// an unprivileged process on a shared host can bind, does not amount to
// control of the name.
const http01Port = 80

// maxChallengeBody caps the response body read from the client's server. A
// key authorization is under 128 bytes; anything approaching this cap is a
// misconfigured server or a hostile one.
const maxChallengeBody = 4 << 10

// maxChallengeRedirects bounds redirect following. RFC 8555 section 8.3
// permits redirects (a common deployment terminates HTTP on a redirector),
// but an unbounded chain is a denial-of-service vector.
const maxChallengeRedirects = 5

// defaultValidationTimeout bounds one whole validation attempt, including
// DNS, connect, and body read. Validation runs inline on the challenge POST,
// so this is also the worst-case latency of that request.
const defaultValidationTimeout = 10 * time.Second

// Validator proves that the requester controls identifier. It returns nil on
// success and a *Problem describing the failure otherwise; the problem is
// stored on the authorization and returned to the client, so its detail is
// the operator's only diagnostic for a failed enrolment.
type Validator func(ctx context.Context, identifier, token, keyAuth string) error

// HTTP01Validator returns a Validator that performs the RFC 8555 section 8.3
// http-01 check: GET http://<identifier>/.well-known/acme-challenge/<token>
// and require the body to equal the key authorization.
//
// A note on what this does and does not prove. It proves that whoever answers
// port 80 for the name, as this node resolves it, holds the key authorization.
// It does not constrain what address that resolves to: an internal CA will
// happily validate an RFC 1918 name, which is the point. It does mean the node
// makes an outbound GET to a client-influenced host, so the request is fixed
// to one path, one port, one method, and a small bounded body.
func HTTP01Validator(timeout time.Duration) Validator {
	if timeout <= 0 {
		timeout = defaultValidationTimeout
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxChallengeRedirects {
				return fmt.Errorf("stopped after %d redirects", maxChallengeRedirects)
			}
			// A redirect to a non-HTTP scheme (file, gopher, ...) would turn
			// the fetch into something other than a web request.
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
			}
			return nil
		},
	}
	return func(ctx context.Context, identifier, token, keyAuth string) error {
		return validateHTTP01(ctx, client, identifier, http01Port, token, keyAuth)
	}
}

// validateHTTP01 is the body of the check. port is a parameter only so a test
// can point it at a listener it is allowed to bind; production always passes
// http01Port, which RFC 8555 section 8.3 fixes at 80.
func validateHTTP01(ctx context.Context, client *http.Client, identifier string, port int, token, keyAuth string) error {
	target := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(identifier, strconv.Itoa(port)),
		Path:   ChallengePathPrefix + token,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return problemf(ErrConnection, http.StatusBadRequest,
			"could not build a validation request for %s: %v", identifier, err)
	}
	// RFC 8555 section 6.1 asks servers to send a descriptive User-Agent so an
	// operator reading their own access log can tell what hit them.
	req.Header.Set("User-Agent", "cryptos-acme/1")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return problemf(ErrConnection, http.StatusBadRequest,
			"fetching %s failed: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return problemf(ErrUnauthorized, http.StatusForbidden,
			"%s returned HTTP %d, expected 200", target, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChallengeBody+1))
	if err != nil {
		return problemf(ErrConnection, http.StatusBadRequest,
			"reading the response from %s failed: %v", target, err)
	}
	if len(body) > maxChallengeBody {
		return problemf(ErrIncorrectResponse, http.StatusForbidden,
			"the response from %s exceeds %d bytes", target, maxChallengeBody)
	}

	// RFC 8555 section 8.3 allows trailing whitespace, which every client
	// that writes the file with a shell redirect produces.
	got := strings.TrimSpace(string(body))
	if subtle.ConstantTimeCompare([]byte(got), []byte(keyAuth)) != 1 {
		return problemf(ErrIncorrectResponse, http.StatusForbidden,
			"the key authorization at %s does not match the expected value", target)
	}
	return nil
}
