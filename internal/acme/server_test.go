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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

const (
	testEABKeyID = "ops-team"
)

var testEABMACKey = []byte("0123456789abcdef0123456789abcdef")

// fixture is a running ACME server with an embedded etcd behind it.
type fixture struct {
	t        *testing.T
	srv      *httptest.Server
	handler  *Handler
	store    *Store
	baseURL  string
	caCert   *x509.Certificate
	caKey    crypto.Signer
	issued   []string
	revoked  map[string]int
	validate func(ctx context.Context, identifier, token, keyAuth string) error
	now      time.Time
}

// newFixture builds a server. mutate can adjust the Options before the
// handler is constructed.
func newFixture(t *testing.T, mutate func(*Options)) *fixture {
	t.Helper()

	srv, err := etcd.Open(t.TempDir())
	if err != nil {
		t.Fatalf("etcd.Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("etcd.Client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}

	f := &fixture{
		t:       t,
		store:   NewStore(cli),
		caCert:  caCert,
		caKey:   caKey,
		revoked: map[string]int{},
		now:     time.Now().UTC().Truncate(time.Second),
	}
	// The default validator succeeds; a test that cares swaps it out.
	f.validate = func(context.Context, string, string, string) error { return nil }

	// The handler must know the URL clients will dial, and httptest only
	// picks a port when the listener is created, so the server is built
	// unstarted, its address read, and its handler installed afterwards.
	f.srv = httptest.NewUnstartedServer(nil)
	f.baseURL = "http://" + f.srv.Listener.Addr().String() + "/acme"

	opts := Options{
		BaseURL:                 f.baseURL,
		ExternalAccountRequired: true,
		EABKey:                  StaticEABKeys(map[string][]byte{testEABKeyID: testEABMACKey}),
		Now:                     func() time.Time { return f.now },
		Logf:                    t.Logf,
	}
	if mutate != nil {
		mutate(&opts)
	}

	h, err := NewHandler(f.store, f.issueFunc(), f.revokeFunc(), f.validateFunc(), opts)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	f.handler = h
	f.srv.Config.Handler = h.Routes()
	f.srv.Start()
	t.Cleanup(f.srv.Close)
	return f
}

// issueFunc mints a real certificate so the test can assert on the SANs that
// actually came out, not on what the handler intended.
func (f *fixture) issueFunc() IssueFunc {
	return func(_ context.Context, csrDER []byte, dnsNames []string) (string, string, error) {
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return "", "", err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return "", "", err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			DNSNames:     dnsNames,
			NotBefore:    f.now.Add(-time.Minute),
			NotAfter:     f.now.Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
		if err != nil {
			return "", "", err
		}
		var sb strings.Builder
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw}))
		hexSerial := serial.Text(16)
		f.issued = append(f.issued, hexSerial)
		return sb.String(), hexSerial, nil
	}
}

func (f *fixture) revokeFunc() RevokeFunc {
	return func(_ context.Context, serialHex string, reason int) error {
		if _, ok := f.revoked[serialHex]; ok {
			return ErrCertificateAlreadyRevoked
		}
		f.revoked[serialHex] = reason
		return nil
	}
}

func (f *fixture) validateFunc() Validator {
	return func(ctx context.Context, identifier, token, keyAuth string) error {
		return f.validate(ctx, identifier, token, keyAuth)
	}
}

// client drives the fixture the way an ACME client would.
type client struct {
	t   *testing.T
	f   *fixture
	key *testKey
	kid string

	nonce string
	dir   Directory
}

func (f *fixture) newClient(key *testKey) *client {
	c := &client{t: f.t, f: f, key: key}
	c.fetchDirectory()
	return c
}

func (c *client) fetchDirectory() {
	c.t.Helper()
	resp, err := http.Get(c.f.baseURL + pathDirectory)
	if err != nil {
		c.t.Fatalf("GET directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("GET directory: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&c.dir); err != nil {
		c.t.Fatalf("decode directory: %v", err)
	}
	// The directory deliberately does not mint a nonce, so the client gets
	// its first one the way a real client does.
	if got := resp.Header.Get("Replay-Nonce"); got != "" {
		c.t.Fatalf("the directory minted a Replay-Nonce (%q); it should not", got)
	}
	c.fetchNonce()
}

func (c *client) fetchNonce() {
	c.t.Helper()
	resp, err := http.Head(c.f.baseURL + pathNewNonce)
	if err != nil {
		c.t.Fatalf("HEAD new-nonce: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	c.nonce = resp.Header.Get("Replay-Nonce")
	if c.nonce == "" {
		c.t.Fatal("new-nonce carried no Replay-Nonce")
	}
}

// post signs and sends an ACME POST. payload nil sends POST-as-GET. It
// returns the response, its body, and refreshes the stored nonce.
func (c *client) post(url string, payload any) (*http.Response, []byte) {
	c.t.Helper()
	var encoded []byte
	if payload != nil {
		var err error
		encoded, err = json.Marshal(payload)
		if err != nil {
			c.t.Fatalf("marshal payload: %v", err)
		}
	}
	hdr := map[string]any{"nonce": c.nonce, "url": url}
	if c.kid != "" {
		hdr["kid"] = c.kid
	} else {
		hdr["jwk"] = c.key.jwk
	}
	body := c.key.signJWS(c.t, hdr, encoded)

	resp, err := http.Post(url, contentTypeJOSE, bytes.NewReader(body))
	if err != nil {
		c.t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
	return resp, raw
}

// register performs new-account with a valid external account binding.
func (c *client) register() {
	c.t.Helper()
	eab := signEAB(c.t, testEABKeyID, testEABMACKey, "HS256", c.f.baseURL+pathNewAccount, c.key.jwk)
	resp, body := c.post(c.f.baseURL+pathNewAccount, map[string]any{
		"contact":                []string{"mailto:ops@example.org"},
		"externalAccountBinding": eab,
	})
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("new-account: status %d body %s", resp.StatusCode, body)
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		c.t.Fatal("new-account returned no Location header")
	}
}

// newOrder places an order and returns the order URL and its resource.
func (c *client) newOrder(names ...string) (string, OrderResource) {
	c.t.Helper()
	idents := make([]Identifier, 0, len(names))
	for _, n := range names {
		idents = append(idents, Identifier{Type: IdentifierTypeDNS, Value: n})
	}
	resp, body := c.post(c.f.baseURL+pathNewOrder, map[string]any{"identifiers": idents})
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("new-order: status %d body %s", resp.StatusCode, body)
	}
	var order OrderResource
	if err := json.Unmarshal(body, &order); err != nil {
		c.t.Fatalf("decode order: %v", err)
	}
	return resp.Header.Get("Location"), order
}

func (c *client) getAuthz(url string) AuthorizationResource {
	c.t.Helper()
	resp, body := c.post(url, nil)
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("authz: status %d body %s", resp.StatusCode, body)
	}
	var authz AuthorizationResource
	if err := json.Unmarshal(body, &authz); err != nil {
		c.t.Fatalf("decode authz: %v", err)
	}
	return authz
}

func (c *client) getOrder(url string) OrderResource {
	c.t.Helper()
	resp, body := c.post(url, nil)
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("order: status %d body %s", resp.StatusCode, body)
	}
	var order OrderResource
	if err := json.Unmarshal(body, &order); err != nil {
		c.t.Fatalf("decode order: %v", err)
	}
	return order
}

// solveAll triggers the http-01 challenge on every authorization of an order.
func (c *client) solveAll(order OrderResource) []ChallengeResource {
	c.t.Helper()
	out := make([]ChallengeResource, 0, len(order.Authorizations))
	for _, authzURL := range order.Authorizations {
		authz := c.getAuthz(authzURL)
		if len(authz.Challenges) != 1 {
			c.t.Fatalf("expected one challenge, got %d", len(authz.Challenges))
		}
		resp, body := c.post(authz.Challenges[0].URL, map[string]any{})
		if resp.StatusCode != http.StatusOK {
			c.t.Fatalf("challenge: status %d body %s", resp.StatusCode, body)
		}
		var ch ChallengeResource
		if err := json.Unmarshal(body, &ch); err != nil {
			c.t.Fatalf("decode challenge: %v", err)
		}
		out = append(out, ch)
	}
	return out
}

// makeCSR builds a PKCS#10 request over a fresh key for the given names.
func makeCSR(t *testing.T, commonName string, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("csr key: %v", err)
	}
	tmpl := &x509.CertificateRequest{DNSNames: names}
	if commonName != "" {
		tmpl.Subject = pkix.Name{CommonName: commonName}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

func decodeProblem(t *testing.T, body []byte) Problem {
	t.Helper()
	var p Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode problem from %s: %v", body, err)
	}
	return p
}

// TestFullEnrolmentFlow walks the whole RFC 8555 sequence a real client walks:
// directory, account, order, authorization, challenge, finalize, download,
// revoke. It asserts on the issued certificate, not just on the status codes,
// so a server that answered "valid" without issuing the right names would
// fail here.
func TestFullEnrolmentFlow(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))

	if c.dir.NewOrder != f.baseURL+pathNewOrder {
		t.Fatalf("directory newOrder = %q", c.dir.NewOrder)
	}
	if c.dir.Meta == nil || !c.dir.Meta.ExternalAccountRequired {
		t.Fatal("directory did not advertise externalAccountRequired")
	}

	c.register()

	const nameA, nameB = "web.example.org", "api.example.org"
	orderURL, order := c.newOrder(nameA, nameB)
	if order.Status != StatusPending {
		t.Fatalf("new order status = %q, want pending", order.Status)
	}
	if len(order.Authorizations) != 2 {
		t.Fatalf("got %d authorizations, want 2", len(order.Authorizations))
	}

	// The key authorization the server expects must be derivable by the
	// client from its own key, which is the whole point of the thumbprint.
	wantThumb, err := c.key.jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	var seenKeyAuth []string
	f.validate = func(_ context.Context, _, token, keyAuth string) error {
		seenKeyAuth = append(seenKeyAuth, keyAuth)
		if keyAuth != token+"."+wantThumb {
			t.Errorf("key authorization = %q, want %s.%s", keyAuth, token, wantThumb)
		}
		return nil
	}

	for _, ch := range c.solveAll(order) {
		if ch.Status != StatusValid {
			t.Fatalf("challenge status = %q, want valid", ch.Status)
		}
	}
	if len(seenKeyAuth) != 2 {
		t.Fatalf("validator ran %d times, want 2", len(seenKeyAuth))
	}

	order = c.getOrder(orderURL)
	if order.Status != StatusReady {
		t.Fatalf("order status after validation = %q, want ready", order.Status)
	}

	csrDER := makeCSR(t, nameA, nameA, nameB)
	resp, body := c.post(order.Finalize, map[string]any{"csr": b64.EncodeToString(csrDER)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize: status %d body %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &order); err != nil {
		t.Fatalf("decode finalized order: %v", err)
	}
	if order.Status != StatusValid {
		t.Fatalf("finalized order status = %q, want valid", order.Status)
	}
	if order.Certificate == "" {
		t.Fatal("finalized order carries no certificate URL")
	}

	resp, chainPEM := c.post(order.Certificate, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("certificate: status %d body %s", resp.StatusCode, chainPEM)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Fatalf("certificate content type = %q", ct)
	}

	block, rest := pem.Decode(chainPEM)
	if block == nil {
		t.Fatalf("certificate response is not PEM: %s", chainPEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := leaf.DNSNames; len(got) != 2 || got[0] != nameA || got[1] != nameB {
		t.Fatalf("leaf SANs = %v, want [%s %s]", got, nameA, nameB)
	}
	if issuerBlock, _ := pem.Decode(rest); issuerBlock == nil {
		t.Fatal("certificate response carried no issuer certificate")
	}

	// The chain must actually verify, which catches a server that returned
	// the right names on a certificate signed by the wrong key.
	pool := x509.NewCertPool()
	pool.AddCert(f.caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: f.now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("issued chain does not verify: %v", err)
	}

	// Revoke through ACME and confirm the serial the CA knows is the one that
	// gets revoked.
	resp, body = c.post(c.dir.RevokeCert, map[string]any{
		"certificate": b64.EncodeToString(leaf.Raw),
		"reason":      4,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke-cert: status %d body %s", resp.StatusCode, body)
	}
	if got, ok := f.revoked[leaf.SerialNumber.Text(16)]; !ok || got != 4 {
		t.Fatalf("revoked map = %v, want the leaf serial with reason 4", f.revoked)
	}

	// A second revocation of the same certificate is alreadyRevoked, not a
	// silent success.
	resp, body = c.post(c.dir.RevokeCert, map[string]any{"certificate": b64.EncodeToString(leaf.Raw)})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("second revoke: status %d body %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != ErrAlreadyRevoked {
		t.Fatalf("second revoke problem = %q, want alreadyRevoked", p.Type)
	}
}

// TestNonceIsSingleUse is the anti-replay property. Capturing a signed request
// and sending it twice must fail the second time.
func TestNonceIsSingleUse(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	url := f.baseURL + pathNewOrder
	payload, err := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: IdentifierTypeDNS, Value: "replay.example.org"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := c.key.signJWS(t, map[string]any{"nonce": c.nonce, "url": url, "kid": c.kid}, payload)

	send := func() (int, []byte) {
		resp, perr := http.Post(url, contentTypeJOSE, bytes.NewReader(body))
		if perr != nil {
			t.Fatalf("POST: %v", perr)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, rerr := io.ReadAll(resp.Body)
		if rerr != nil {
			t.Fatalf("read: %v", rerr)
		}
		return resp.StatusCode, raw
	}

	if status, raw := send(); status != http.StatusCreated {
		t.Fatalf("first send: status %d body %s", status, raw)
	}
	status, raw := send()
	if status != http.StatusBadRequest {
		t.Fatalf("replayed send: status %d body %s", status, raw)
	}
	if p := decodeProblem(t, raw); p.Type != ErrBadNonce {
		t.Fatalf("replayed send problem = %q, want badNonce", p.Type)
	}
}

// TestProtectedURLBinding: a request signed for one endpoint must not be
// accepted at another.
func TestProtectedURLBinding(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	payload, err := json.Marshal(map[string]any{
		"identifiers": []Identifier{{Type: IdentifierTypeDNS, Value: "moved.example.org"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Signed for new-order, sent to new-account.
	body := c.key.signJWS(t, map[string]any{
		"nonce": c.nonce, "url": f.baseURL + pathNewOrder, "kid": c.kid,
	}, payload)
	resp, err := http.Post(f.baseURL+pathNewAccount, contentTypeJOSE, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d body %s", resp.StatusCode, raw)
	}
	if p := decodeProblem(t, raw); p.Type != ErrMalformed {
		t.Fatalf("problem = %q, want malformed", p.Type)
	}
}

func TestNewAccountRequiresExternalBinding(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))

	resp, body := c.post(f.baseURL+pathNewAccount, map[string]any{"contact": []string{"mailto:x@example.org"}})
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("an account registered without an external account binding")
	}
	if p := decodeProblem(t, body); p.Type != ErrExternalAccountRequired {
		t.Fatalf("problem = %q, want externalAccountRequired", p.Type)
	}
}

func TestNewAccountAnonymousWhenAllowed(t *testing.T) {
	f := newFixture(t, func(o *Options) {
		o.ExternalAccountRequired = false
		o.EABKey = nil
	})
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))

	resp, body := c.post(f.baseURL+pathNewAccount, map[string]any{"contact": []string{"mailto:x@example.org"}})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if c.dir.Meta != nil && c.dir.Meta.ExternalAccountRequired {
		t.Fatal("directory advertised externalAccountRequired with anonymous accounts allowed")
	}
}

// TestNewAccountIsIdempotent: a client that re-registers the same key gets the
// same account back rather than a second one, which is what makes it safe to
// call new-account on every run.
func TestNewAccountIsIdempotent(t *testing.T) {
	f := newFixture(t, nil)
	key := newECTestKey(t, elliptic.P256(), "ES256")
	c := f.newClient(key)
	c.register()
	first := c.kid

	c.kid = "" // sign with the embedded jwk again, as a fresh client would
	eab := signEAB(t, testEABKeyID, testEABMACKey, "HS256", f.baseURL+pathNewAccount, key.jwk)
	resp, body := c.post(f.baseURL+pathNewAccount, map[string]any{"externalAccountBinding": eab})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-register: status %d body %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != first {
		t.Fatalf("re-register returned account %q, want %q", got, first)
	}
}

func TestOnlyReturnExistingForUnknownKey(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	resp, body := c.post(f.baseURL+pathNewAccount, map[string]any{"onlyReturnExisting": true})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != ErrAccountDoesNotExist {
		t.Fatalf("problem = %q, want accountDoesNotExist", p.Type)
	}
}

func TestOrderIdentifierRules(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.AllowedSuffixes = []string{"example.org"} })
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	for _, tc := range []struct {
		name    string
		idents  []Identifier
		problem string
	}{
		{"wildcard", []Identifier{{Type: IdentifierTypeDNS, Value: "*.example.org"}}, ErrRejectedIdentifier},
		{"outside the allowlist", []Identifier{{Type: IdentifierTypeDNS, Value: "web.evil.test"}}, ErrRejectedIdentifier},
		{"non-dns type", []Identifier{{Type: "ip", Value: "10.0.0.1"}}, ErrUnsupportedIdentifier},
		{"empty list", nil, ErrMalformed},
		{"not a fqdn", []Identifier{{Type: IdentifierTypeDNS, Value: "localhost"}}, ErrMalformed},
		{"bad characters", []Identifier{{Type: IdentifierTypeDNS, Value: "we b.example.org"}}, ErrMalformed},
		// A suffix match must be on a label boundary, not a string suffix.
		{"suffix is not a label boundary", []Identifier{{Type: IdentifierTypeDNS, Value: "notexample.org"}}, ErrRejectedIdentifier},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := c.post(f.baseURL+pathNewOrder, map[string]any{"identifiers": tc.idents})
			if resp.StatusCode == http.StatusCreated {
				t.Fatalf("order accepted %v", tc.idents)
			}
			if p := decodeProblem(t, body); p.Type != tc.problem {
				t.Fatalf("problem = %q, want %q (body %s)", p.Type, tc.problem, body)
			}
		})
	}

	t.Run("accepts the apex and a subdomain", func(t *testing.T) {
		if _, order := c.newOrder("example.org", "deep.web.example.org"); len(order.Identifiers) != 2 {
			t.Fatalf("identifiers = %v", order.Identifiers)
		}
	})

	t.Run("normalises case and deduplicates", func(t *testing.T) {
		_, order := c.newOrder("WEB.Example.ORG", "web.example.org.")
		if len(order.Identifiers) != 1 || order.Identifiers[0].Value != "web.example.org" {
			t.Fatalf("identifiers = %v, want one normalised entry", order.Identifiers)
		}
	})
}

func TestFinalizeRejectsMismatchedCSR(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	orderURL, order := c.newOrder("web.example.org")
	c.solveAll(order)
	order = c.getOrder(orderURL)

	for _, tc := range []struct {
		name string
		csr  []byte
	}{
		{"extra name", makeCSR(t, "web.example.org", "web.example.org", "extra.example.org")},
		{"missing name", makeCSR(t, "", "other.example.org")},
		{"common name outside the order", makeCSR(t, "sneaky.example.org", "web.example.org")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := c.post(order.Finalize, map[string]any{"csr": b64.EncodeToString(tc.csr)})
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("finalize accepted a mismatched CSR: %s", body)
			}
			if p := decodeProblem(t, body); p.Type != ErrBadCSR {
				t.Fatalf("problem = %q, want badCSR", p.Type)
			}
		})
	}

	// A CSR whose common name merely duplicates a SAN is fine.
	t.Run("common name duplicating a san", func(t *testing.T) {
		resp, body := c.post(order.Finalize, map[string]any{
			"csr": b64.EncodeToString(makeCSR(t, "web.example.org", "web.example.org")),
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d body %s", resp.StatusCode, body)
		}
	})
}

func TestFinalizeBeforeReady(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	_, order := c.newOrder("web.example.org")
	resp, body := c.post(order.Finalize, map[string]any{
		"csr": b64.EncodeToString(makeCSR(t, "", "web.example.org")),
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("finalize succeeded on a pending order")
	}
	if p := decodeProblem(t, body); p.Type != ErrOrderNotReady {
		t.Fatalf("problem = %q, want orderNotReady", p.Type)
	}
	if len(f.issued) != 0 {
		t.Fatalf("the CA issued %d certificates for an unvalidated order", len(f.issued))
	}
}

// TestFailedValidationInvalidatesOrder: a challenge the client cannot answer
// must leave the authorization and its order invalid, and must not be
// retryable into a success.
func TestFailedValidationInvalidatesOrder(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	f.validate = func(context.Context, string, string, string) error {
		return problemf(ErrIncorrectResponse, http.StatusForbidden, "nothing answered on port 80")
	}

	orderURL, order := c.newOrder("web.example.org")
	chs := c.solveAll(order)
	if chs[0].Status != StatusInvalid {
		t.Fatalf("challenge status = %q, want invalid", chs[0].Status)
	}
	if chs[0].Error == nil || chs[0].Error.Type != ErrIncorrectResponse {
		t.Fatalf("challenge error = %+v, want an incorrectResponse problem", chs[0].Error)
	}
	if chs[0].Error.Identifier == nil || chs[0].Error.Identifier.Value != "web.example.org" {
		t.Fatalf("challenge error carries no identifier: %+v", chs[0].Error)
	}

	if got := c.getOrder(orderURL); got.Status != StatusInvalid {
		t.Fatalf("order status = %q, want invalid", got.Status)
	}

	// Retrying the challenge with a validator that now succeeds must not
	// resurrect the authorization.
	f.validate = func(context.Context, string, string, string) error { return nil }
	authz := c.getAuthz(order.Authorizations[0])
	resp, body := c.post(authz.Challenges[0].URL, map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge retry: status %d body %s", resp.StatusCode, body)
	}
	var ch ChallengeResource
	if err := json.Unmarshal(body, &ch); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ch.Status != StatusInvalid {
		t.Fatalf("retried challenge status = %q, want it to stay invalid", ch.Status)
	}
}

// TestAccountIsolation: one account must not be able to read, finalize, or
// revoke another account's resources.
func TestAccountIsolation(t *testing.T) {
	f := newFixture(t, nil)
	owner := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	owner.register()
	intruder := f.newClient(newECTestKey(t, elliptic.P384(), "ES384"))
	intruder.register()

	orderURL, order := owner.newOrder("web.example.org")
	owner.solveAll(order)
	order = owner.getOrder(orderURL)
	resp, body := owner.post(order.Finalize, map[string]any{
		"csr": b64.EncodeToString(makeCSR(t, "", "web.example.org")),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize: status %d body %s", resp.StatusCode, body)
	}
	var finalized OrderResource
	if err := json.Unmarshal(body, &finalized); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, tc := range []struct {
		name    string
		url     string
		payload any
	}{
		{"read the order", orderURL, nil},
		{"read the authorization", order.Authorizations[0], nil},
		{"download the certificate", finalized.Certificate, nil},
		{"finalize the order", order.Finalize, map[string]any{"csr": b64.EncodeToString(makeCSR(t, "", "web.example.org"))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := intruder.post(tc.url, tc.payload)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("the intruder could %s: %s", tc.name, body)
			}
			if p := decodeProblem(t, body); p.Type != ErrUnauthorized {
				t.Fatalf("problem = %q, want unauthorized", p.Type)
			}
		})
	}
}

// TestRevokeByCertificateKey: RFC 8555 section 7.6 allows the holder of the
// certificate key to revoke it even without the ordering account.
func TestRevokeByCertificateKey(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	orderURL, order := c.newOrder("web.example.org")
	c.solveAll(order)
	order = c.getOrder(orderURL)

	// Build the CSR from a key the test keeps, so it can sign the revocation
	// with the certificate key afterwards.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cert key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{DNSNames: []string{"web.example.org"}}, certKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	resp, body := c.post(order.Finalize, map[string]any{"csr": b64.EncodeToString(csrDER)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize: status %d body %s", resp.StatusCode, body)
	}
	var finalized OrderResource
	if err := json.Unmarshal(body, &finalized); err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, chainPEM := c.post(finalized.Certificate, nil)
	block, _ := pem.Decode(chainPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	certJWK, err := JWKFromPublic(&certKey.PublicKey)
	if err != nil {
		t.Fatalf("JWKFromPublic: %v", err)
	}
	holder := f.newClient(&testKey{signer: certKey, alg: "ES256", jwk: certJWK})
	resp, body = holder.post(holder.dir.RevokeCert, map[string]any{
		"certificate": b64.EncodeToString(leaf.Raw),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke by certificate key: status %d body %s", resp.StatusCode, body)
	}
	if _, ok := f.revoked[leaf.SerialNumber.Text(16)]; !ok {
		t.Fatal("the certificate was not revoked")
	}

	// An unrelated key must not be able to revoke it.
	stranger := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	resp, body = stranger.post(stranger.dir.RevokeCert, map[string]any{
		"certificate": b64.EncodeToString(leaf.Raw),
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("an unrelated key revoked the certificate: %s", body)
	}
}

func TestRevokeRejectsUnacceptableReason(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()
	resp, body := c.post(c.dir.RevokeCert, map[string]any{
		"certificate": b64.EncodeToString(f.caCert.Raw),
		"reason":      6, // certificateHold
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a certificateHold revocation was accepted")
	}
	if p := decodeProblem(t, body); p.Type != ErrBadRevocationReason {
		t.Fatalf("problem = %q, want badRevocationReason", p.Type)
	}
}

func TestRevokeRejectsForeignCertificate(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()
	// The CA's own certificate was never issued through ACME.
	resp, body := c.post(c.dir.RevokeCert, map[string]any{"certificate": b64.EncodeToString(f.caCert.Raw)})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a certificate this server never issued through ACME was revoked")
	}
	if p := decodeProblem(t, body); p.Type != ErrUnauthorized {
		t.Fatalf("problem = %q, want unauthorized", p.Type)
	}
}

func TestNewNonceStatuses(t *testing.T) {
	f := newFixture(t, nil)

	resp, err := http.Get(f.baseURL + pathNewNonce)
	if err != nil {
		t.Fatalf("GET new-nonce: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("GET new-nonce status = %d, want 204", resp.StatusCode)
	}
	if resp.Header.Get("Replay-Nonce") == "" {
		t.Fatal("GET new-nonce carried no Replay-Nonce")
	}

	headResp, err := http.Head(f.baseURL + pathNewNonce)
	if err != nil {
		t.Fatalf("HEAD new-nonce: %v", err)
	}
	defer func() { _ = headResp.Body.Close() }()
	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD new-nonce status = %d, want 200", headResp.StatusCode)
	}
}

func TestRejectsWrongContentType(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	body := c.key.signJWS(t, map[string]any{
		"nonce": c.nonce, "url": f.baseURL + pathNewAccount, "jwk": c.key.jwk,
	}, []byte(`{}`))
	resp, err := http.Post(f.baseURL+pathNewAccount, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAccountContactAndOrdersList(t *testing.T) {
	f := newFixture(t, nil)
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	// The account resource points at its own orders list.
	resp, body := c.post(c.kid, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("account: status %d body %s", resp.StatusCode, body)
	}
	var acct AccountResource
	if err := json.Unmarshal(body, &acct); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	if acct.Orders == "" {
		t.Fatal("account carries no orders URL")
	}

	orderURL, _ := c.newOrder("web.example.org")
	resp, body = c.post(acct.Orders, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("orders: status %d body %s", resp.StatusCode, body)
	}
	var list OrdersList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode orders: %v", err)
	}
	if len(list.Orders) != 1 || list.Orders[0] != orderURL {
		t.Fatalf("orders list = %v, want [%s]", list.Orders, orderURL)
	}

	// A non-mailto contact is refused rather than silently stored.
	resp, body = c.post(c.kid, map[string]any{"contact": []string{"https://example.org/hook"}})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a non-mailto contact was accepted")
	}
	if p := decodeProblem(t, body); p.Type != ErrInvalidContact {
		t.Fatalf("problem = %q, want invalidContact", p.Type)
	}

	resp, body = c.post(c.kid, map[string]any{"contact": []string{"mailto:new@example.org"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("contact update: status %d body %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &acct); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(acct.Contact) != 1 || acct.Contact[0] != "mailto:new@example.org" {
		t.Fatalf("contact = %v", acct.Contact)
	}
}

// TestExpiredOrderCannotFinalize: an order past its expiry becomes invalid
// rather than remaining finalizable forever.
func TestExpiredOrderCannotFinalize(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.OrderTTL = time.Hour })
	c := f.newClient(newECTestKey(t, elliptic.P256(), "ES256"))
	c.register()

	orderURL, order := c.newOrder("web.example.org")
	c.solveAll(order)
	if got := c.getOrder(orderURL); got.Status != StatusReady {
		t.Fatalf("order status = %q, want ready", got.Status)
	}

	f.now = f.now.Add(2 * time.Hour)
	if got := c.getOrder(orderURL); got.Status != StatusInvalid {
		t.Fatalf("expired order status = %q, want invalid", got.Status)
	}
	resp, body := c.post(order.Finalize, map[string]any{
		"csr": b64.EncodeToString(makeCSR(t, "", "web.example.org")),
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("an expired order was finalized: %s", body)
	}
	if len(f.issued) != 0 {
		t.Fatalf("the CA issued %d certificates for an expired order", len(f.issued))
	}
}

func TestNewHandlerValidatesOptions(t *testing.T) {
	store := &Store{}
	issue := IssueFunc(func(context.Context, []byte, []string) (string, string, error) { return "", "", nil })
	validate := Validator(func(context.Context, string, string, string) error { return nil })

	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"no base url", Options{}},
		{"relative base url", Options{BaseURL: "/acme"}},
		{"base url with no host", Options{BaseURL: "https:///acme"}},
		{"non-http scheme", Options{BaseURL: "ftp://ca.example/acme"}},
		{"binding required with no resolver", Options{BaseURL: "https://ca.example/acme", ExternalAccountRequired: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHandler(store, issue, nil, validate, tc.opts); err == nil {
				t.Fatal("NewHandler accepted invalid options")
			}
		})
	}
}
