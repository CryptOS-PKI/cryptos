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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider seals and unseals the state-partition DEK with an external KMS. The
// node never persists the DEK plaintext; it holds only the sealed blob (in the
// LUKS2 header token) and asks the KMS to reverse the operation at boot.
type Provider interface {
	// Seal wraps plaintext with the KMS key, returning the sealed blob.
	Seal(ctx context.Context, plaintext []byte) ([]byte, error)
	// Unseal reverses Seal, returning the plaintext.
	Unseal(ctx context.Context, blob []byte) ([]byte, error)
}

// httpRequestTimeout bounds a single seal/unseal round-trip so a wedged KMS
// cannot hang boot indefinitely; boot fails closed on the resulting error.
const httpRequestTimeout = 30 * time.Second

// sealUnsealBody is the JSON envelope for both the seal/unseal request and the
// response: the payload is base64 so arbitrary binary survives JSON transport.
type sealUnsealBody struct {
	Data string `json:"data"`
}

// httpProvider is the generic seal/unseal KMS adapter. It POSTs the base64
// payload to <endpoint>/seal and <endpoint>/unseal (the Talos KMS model). When
// a trust bundle is configured it pins the KMS TLS server to that bundle.
type httpProvider struct {
	endpoint string
	client   *http.Client
}

// NewHTTPProvider builds an httpProvider for endpoint. When trustPEM is
// non-empty the returned client verifies the KMS TLS server against exactly
// that CA bundle; an empty bundle uses the system roots.
func NewHTTPProvider(endpoint string, trustPEM []byte) (Provider, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, errors.New("kms: endpoint is required")
	}
	transport := &http.Transport{}
	if len(bytes.TrimSpace(trustPEM)) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(trustPEM) {
			return nil, errors.New("kms: trust bundle contains no valid certificates")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &httpProvider{
		endpoint: strings.TrimRight(endpoint, "/"),
		client:   &http.Client{Transport: transport, Timeout: httpRequestTimeout},
	}, nil
}

func (p *httpProvider) Seal(ctx context.Context, plaintext []byte) ([]byte, error) {
	return p.post(ctx, "/seal", plaintext)
}

func (p *httpProvider) Unseal(ctx context.Context, blob []byte) ([]byte, error) {
	return p.post(ctx, "/unseal", blob)
}

// post sends payload to <endpoint><path> as a base64 JSON envelope and returns
// the decoded response payload.
func (p *httpProvider) post(ctx context.Context, path string, payload []byte) ([]byte, error) {
	reqBody, err := json.Marshal(sealUnsealBody{Data: base64.StdEncoding.EncodeToString(payload)})
	if err != nil {
		return nil, fmt.Errorf("kms: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+path, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("kms: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kms: POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("kms: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kms: POST %s: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out sealUnsealBody
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("kms: parse response: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(out.Data)
	if err != nil {
		return nil, fmt.Errorf("kms: decode response payload: %w", err)
	}
	return decoded, nil
}
