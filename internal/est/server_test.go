package est

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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testEnrollUser = "switch-fleet"

// newTestPassword generates the fixture simpleenroll password. It is
// generated rather than written down so the test never carries a literal that
// looks like a credential, and because a real deployment has to generate one
// too: the config stores only the digest, which is only safe for a
// high-entropy value.
func newTestPassword(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("password: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// fixture is a running EST server over TLS, with a real issuing CA behind it.
type fixture struct {
	t       *testing.T
	srv     *httptest.Server
	ca      *testCA
	issued  [][]byte
	revoked map[string]bool
	now     time.Time

	// password is the simpleenroll credential this fixture accepts.
	password string

	// issueErr, when set, makes the issuance closure fail.
	issueErr error
}

func newFixture(t *testing.T, mutate func(*Options)) *fixture {
	t.Helper()
	ca := newTestCA(t)
	f := &fixture{t: t, ca: ca, revoked: map[string]bool{}, now: time.Now().UTC()}
	f.password = newTestPassword(t)

	digest := sha256.Sum256([]byte(f.password))
	opts := Options{
		AllowedSuffixes: []string{"example.org"},
		EnrollAuth:      StaticEnrollCredentials(map[string][]byte{testEnrollUser: digest[:]}),
		Now:             func() time.Time { return f.now },
		Logf:            t.Logf,
	}
	if mutate != nil {
		mutate(&opts)
	}

	h, err := NewHandler(f.caChainFunc(), f.issueFunc(), f.revokedFunc(), opts)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	f.srv = httptest.NewUnstartedServer(h.Routes())
	// A real TLS listener that asks for, but does not demand, a client
	// certificate: /cacerts must serve a client that has nothing yet, while
	// simplereenroll needs the certificate to reach the handler.
	f.srv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) caChainFunc() CAChainFunc {
	return func(context.Context) ([][]byte, error) {
		return [][]byte{f.ca.certDER}, nil
	}
}

// issueFunc signs a real certificate with the test CA so assertions are about
// what actually came out.
func (f *fixture) issueFunc() IssueFunc {
	return func(_ context.Context, csrDER []byte, dnsNames []string) ([][]byte, error) {
		if f.issueErr != nil {
			return nil, f.issueErr
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			DNSNames:     dnsNames,
			NotBefore:    f.now.Add(-time.Minute),
			NotAfter:     f.now.Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.cert, csr.PublicKey, f.ca.key)
		if err != nil {
			return nil, err
		}
		f.issued = append(f.issued, der)
		return [][]byte{der, f.ca.certDER}, nil
	}
}

func (f *fixture) revokedFunc() RevokedFunc {
	return func(_ context.Context, serialHex string) (bool, error) {
		return f.revoked[serialHex], nil
	}
}

// client returns an HTTP client trusting the test server, optionally
// presenting a TLS client certificate.
func (f *fixture) client(clientCert *tls.Certificate) *http.Client {
	f.t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   10 * time.Second,
	}
}

func (f *fixture) url(op string) string { return f.srv.URL + WellKnownPrefix + op }

// makeCSR builds a PKCS#10 request over a fresh key.
func makeCSR(t *testing.T, commonName string, names ...string) ([]byte, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	return der, key
}

// postCSR sends a base64 PKCS#10 body, as RFC 7030 specifies.
func (f *fixture) postCSR(c *http.Client, url string, csrDER []byte, user, pass string) (*http.Response, []byte) {
	f.t.Helper()
	body := base64.StdEncoding.EncodeToString(csrDER)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		f.t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", contentTypePKCS10)
	req.Header.Set("Content-Transfer-Encoding", "base64")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := c.Do(req)
	if err != nil {
		f.t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatalf("read body: %v", err)
	}
	return resp, raw
}

// decodeCertsOnly turns a base64 certs-only response body into certificates.
func decodeCertsOnly(t *testing.T, body []byte) []*x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("response body is not base64: %v", err)
	}
	raws, err := ParseCertsOnlyPKCS7(der)
	if err != nil {
		t.Fatalf("ParseCertsOnlyPKCS7: %v", err)
	}
	out := make([]*x509.Certificate, 0, len(raws))
	for i, raw := range raws {
		cert, perr := x509.ParseCertificate(raw)
		if perr != nil {
			t.Fatalf("certificate %d: %v", i, perr)
		}
		out = append(out, cert)
	}
	return out
}

func TestCACerts(t *testing.T) {
	f := newFixture(t, nil)
	resp, err := f.client(nil).Get(f.url(opCACerts))
	if err != nil {
		t.Fatalf("GET cacerts: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != contentTypePKCS7 {
		t.Fatalf("Content-Type = %q, want %q", ct, contentTypePKCS7)
	}
	if cte := resp.Header.Get("Content-Transfer-Encoding"); cte != "base64" {
		t.Fatalf("Content-Transfer-Encoding = %q, want base64", cte)
	}
	certs := decodeCertsOnly(t, body)
	if len(certs) != 1 || certs[0].Subject.CommonName != testCACommonName {
		t.Fatalf("cacerts returned %d certificates, first CN %q", len(certs), certs[0].Subject.CommonName)
	}
}

func TestCSRAttrsIsEmpty(t *testing.T) {
	f := newFixture(t, nil)
	resp, err := f.client(nil).Get(f.url(opCSRAttrs))
	if err != nil {
		t.Fatalf("GET csrattrs: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

func TestSimpleEnroll(t *testing.T) {
	f := newFixture(t, nil)
	csrDER, _ := makeCSR(t, "web.example.org", "web.example.org", "api.example.org")

	resp, body := f.postCSR(f.client(nil), f.url(opSimpleEnroll), csrDER, testEnrollUser, f.password)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	certs := decodeCertsOnly(t, body)
	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want the leaf and the CA", len(certs))
	}
	leaf := certs[0]
	want := map[string]bool{"web.example.org": true, "api.example.org": true}
	if len(leaf.DNSNames) != 2 {
		t.Fatalf("leaf SANs = %v", leaf.DNSNames)
	}
	for _, n := range leaf.DNSNames {
		if !want[n] {
			t.Fatalf("leaf carries an unrequested name %q", n)
		}
	}
	// The issued certificate must actually chain to the CA.
	pool := x509.NewCertPool()
	pool.AddCert(f.ca.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: f.now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("the issued certificate does not chain to the CA: %v", err)
	}
}

// A DER body is accepted alongside the base64 the RFC specifies, because
// clients in the field send it.
func TestSimpleEnrollAcceptsRawDER(t *testing.T) {
	f := newFixture(t, nil)
	csrDER, _ := makeCSR(t, "", "web.example.org")

	req, err := http.NewRequest(http.MethodPost, f.url(opSimpleEnroll), bytes.NewReader(csrDER))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", contentTypePKCS10)
	req.SetBasicAuth(testEnrollUser, f.password)
	resp, err := f.client(nil).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func TestSimpleEnrollAuthentication(t *testing.T) {
	f := newFixture(t, nil)
	csrDER, _ := makeCSR(t, "", "web.example.org")

	for _, tc := range []struct {
		name   string
		user   string
		pass   string
		status int
	}{
		{"no credential", "", "", http.StatusUnauthorized},
		{"wrong password", testEnrollUser, "wrong", http.StatusUnauthorized},
		{"unknown user", "nobody", f.password, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := f.postCSR(f.client(nil), f.url(opSimpleEnroll), csrDER, tc.user, tc.pass)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d body %s", resp.StatusCode, body)
			}
			if resp.Header.Get("WWW-Authenticate") == "" {
				t.Fatal("a 401 must offer a WWW-Authenticate challenge")
			}
			if len(f.issued) != 0 {
				t.Fatal("the CA issued a certificate to an unauthenticated caller")
			}
		})
	}
}

func TestSimpleEnrollDisabledWithoutCredentials(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.EnrollAuth = nil })
	csrDER, _ := makeCSR(t, "", "web.example.org")
	resp, body := f.postCSR(f.client(nil), f.url(opSimpleEnroll), csrDER, testEnrollUser, f.password)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func TestSimpleEnrollNamePolicy(t *testing.T) {
	f := newFixture(t, nil)
	for _, tc := range []struct {
		name   string
		csr    func() []byte
		status int
	}{
		{
			name:   "outside the allowlist",
			csr:    func() []byte { der, _ := makeCSR(t, "", "web.evil.test"); return der },
			status: http.StatusForbidden,
		},
		{
			// A label-boundary check, not a string suffix.
			name:   "suffix is not a label boundary",
			csr:    func() []byte { der, _ := makeCSR(t, "", "notexample.org"); return der },
			status: http.StatusForbidden,
		},
		{
			name:   "wildcard",
			csr:    func() []byte { der, _ := makeCSR(t, "", "*.example.org"); return der },
			status: http.StatusForbidden,
		},
		{
			name:   "not a fqdn",
			csr:    func() []byte { der, _ := makeCSR(t, "", "localhost"); return der },
			status: http.StatusBadRequest,
		},
		{
			name:   "no name at all",
			csr:    func() []byte { der, _ := makeCSR(t, ""); return der },
			status: http.StatusBadRequest,
		},
		{
			// A common name outside the allowlist must not slip past a
			// compliant SAN.
			name:   "common name outside the allowlist",
			csr:    func() []byte { der, _ := makeCSR(t, "sneaky.evil.test", "web.example.org"); return der },
			status: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := f.postCSR(f.client(nil), f.url(opSimpleEnroll), tc.csr(), testEnrollUser, f.password)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, tc.status, body)
			}
		})
	}
	if len(f.issued) != 0 {
		t.Fatalf("the CA issued %d certificates for rejected requests", len(f.issued))
	}
}

func TestSimpleEnrollRejectsBadRequests(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client(nil)

	t.Run("wrong content type", func(t *testing.T) {
		csrDER, _ := makeCSR(t, "", "web.example.org")
		req, err := http.NewRequest(http.MethodPost, f.url(opSimpleEnroll),
			strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(testEnrollUser, f.password)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415", resp.StatusCode)
		}
	})

	t.Run("not a csr", func(t *testing.T) {
		resp, _ := f.postCSR(c, f.url(opSimpleEnroll), []byte("nonsense"), testEnrollUser, f.password)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("non-dns san", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			DNSNames:       []string{"web.example.org"},
			EmailAddresses: []string{"ops@example.org"},
		}, key)
		if err != nil {
			t.Fatalf("CreateCertificateRequest: %v", err)
		}
		resp, _ := f.postCSR(c, f.url(opSimpleEnroll), der, testEnrollUser, f.password)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})
}

// newClientCredential issues a certificate from the test CA and returns it as
// a TLS client credential.
func (f *fixture) newClientCredential(t *testing.T, names ...string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	der, cert := f.ca.issueLeafForKey(t, key, names...)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// TestSimpleReenroll is the capability EST exists for: renewal authenticated
// by the certificate already held, with no shared secret anywhere.
func TestSimpleReenroll(t *testing.T) {
	f := newFixture(t, nil)
	cred := f.newClientCredential(t, "switch01.example.org")
	csrDER, _ := makeCSR(t, "switch01.example.org", "switch01.example.org")

	resp, body := f.postCSR(f.client(cred), f.url(opSimpleReenroll), csrDER, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	certs := decodeCertsOnly(t, body)
	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want the leaf and the CA", len(certs))
	}
	if got := certs[0].DNSNames; len(got) != 1 || got[0] != "switch01.example.org" {
		t.Fatalf("renewed SANs = %v", got)
	}
	// The renewal is a new certificate, not the old one handed back.
	if bytes.Equal(certs[0].Raw, cred.Certificate[0]) {
		t.Fatal("re-enrolment returned the certificate the client already had")
	}
}

// A re-enrolment is allowed to keep the names it holds even where those names
// are outside the simpleenroll allowlist: the existing certificate, not the
// policy, is the authority on what a renewal may carry.
func TestSimpleReenrollIgnoresEnrollAllowlist(t *testing.T) {
	f := newFixture(t, nil)
	cred := f.newClientCredential(t, "legacy.internal.test")
	csrDER, _ := makeCSR(t, "", "legacy.internal.test")

	resp, body := f.postCSR(f.client(cred), f.url(opSimpleReenroll), csrDER, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

// TestSimpleReenrollCannotChangeNames is the escalation guard: holding one
// certificate must not mint another for a different name.
func TestSimpleReenrollCannotChangeNames(t *testing.T) {
	f := newFixture(t, nil)
	cred := f.newClientCredential(t, "switch01.example.org")

	for _, tc := range []struct {
		name string
		csr  func() []byte
	}{
		{"a different name", func() []byte { der, _ := makeCSR(t, "", "switch99.example.org"); return der }},
		{"an extra name", func() []byte {
			der, _ := makeCSR(t, "", "switch01.example.org", "switch99.example.org")
			return der
		}},
		{"a common name it does not hold", func() []byte {
			der, _ := makeCSR(t, "admin.example.org", "switch01.example.org")
			return der
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := f.postCSR(f.client(cred), f.url(opSimpleReenroll), tc.csr(), "", "")
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body %s)", resp.StatusCode, body)
			}
		})
	}
	if len(f.issued) != 0 {
		t.Fatalf("the CA issued %d certificates for a name change", len(f.issued))
	}
}

func TestSimpleReenrollRequiresOurCertificate(t *testing.T) {
	f := newFixture(t, nil)
	csrDER, _ := makeCSR(t, "", "switch01.example.org")

	t.Run("no client certificate", func(t *testing.T) {
		resp, body := f.postCSR(f.client(nil), f.url(opSimpleReenroll), csrDER, "", "")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %s)", resp.StatusCode, body)
		}
	})

	t.Run("a certificate from another CA", func(t *testing.T) {
		other := newTestCA(t)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		der, cert := other.issueLeafForKey(t, key, "switch01.example.org")
		cred := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
		resp, body := f.postCSR(f.client(cred), f.url(opSimpleReenroll), csrDER, "", "")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body %s)", resp.StatusCode, body)
		}
	})

	if len(f.issued) != 0 {
		t.Fatalf("the CA issued %d certificates to an unauthenticated client", len(f.issued))
	}
}

// A revoked certificate must not be able to renew itself. A TLS handshake
// that only checked the signature would let it, which is why the check is in
// the handler.
func TestSimpleReenrollRefusesRevokedCertificate(t *testing.T) {
	f := newFixture(t, nil)
	cred := f.newClientCredential(t, "switch01.example.org")
	f.revoked[cred.Leaf.SerialNumber.Text(16)] = true

	csrDER, _ := makeCSR(t, "", "switch01.example.org")
	resp, body := f.postCSR(f.client(cred), f.url(opSimpleReenroll), csrDER, "", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "revoked") {
		t.Fatalf("body does not say why: %s", body)
	}
	if len(f.issued) != 0 {
		t.Fatal("a revoked certificate renewed itself")
	}
}

// An expired certificate must not renew itself either: the point of an expiry
// is that it ends.
func TestSimpleReenrollRefusesExpiredCertificate(t *testing.T) {
	f := newFixture(t, nil)
	cred := f.newClientCredential(t, "switch01.example.org")
	f.now = cred.Leaf.NotAfter.Add(time.Hour)

	csrDER, _ := makeCSR(t, "", "switch01.example.org")
	resp, body := f.postCSR(f.client(cred), f.url(opSimpleReenroll), csrDER, "", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", resp.StatusCode, body)
	}
}

func TestIssuanceFailureIsReported(t *testing.T) {
	f := newFixture(t, nil)
	f.issueErr = errors.New("profile refused the subject key")
	csrDER, _ := makeCSR(t, "", "web.example.org")

	resp, body := f.postCSR(f.client(nil), f.url(opSimpleEnroll), csrDER, testEnrollUser, f.password)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "profile refused") {
		t.Fatalf("body does not carry the reason: %s", body)
	}
}

func TestLabelledPaths(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Label = "issuing" })
	c := f.client(nil)

	resp, err := c.Get(f.srv.URL + WellKnownPrefix + "/issuing" + opCACerts)
	if err != nil {
		t.Fatalf("GET labelled cacerts: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("labelled cacerts status = %d", resp.StatusCode)
	}

	// The unlabelled path must not also answer, or the label would be
	// decoration rather than routing.
	plain, err := c.Get(f.url(opCACerts))
	if err != nil {
		t.Fatalf("GET unlabelled cacerts: %v", err)
	}
	defer func() { _ = plain.Body.Close() }()
	if plain.StatusCode != http.StatusNotFound {
		t.Fatalf("unlabelled cacerts status = %d, want 404", plain.StatusCode)
	}
}

func TestNewHandlerValidatesOptions(t *testing.T) {
	chain := CAChainFunc(func(context.Context) ([][]byte, error) { return nil, nil })
	issue := IssueFunc(func(context.Context, []byte, []string) ([][]byte, error) { return nil, nil })
	auth := EnrollAuthFunc(func(string, string) bool { return true })

	t.Run("no chain", func(t *testing.T) {
		if _, err := NewHandler(nil, issue, nil, Options{}); err == nil {
			t.Fatal("accepted a nil caChain")
		}
	})
	t.Run("no issue", func(t *testing.T) {
		if _, err := NewHandler(chain, nil, nil, Options{}); err == nil {
			t.Fatal("accepted a nil issue")
		}
	})
	t.Run("enrol with no allowlist", func(t *testing.T) {
		if _, err := NewHandler(chain, issue, nil, Options{EnrollAuth: auth}); err == nil {
			t.Fatal("accepted simpleenroll with neither an allowlist nor the explicit override")
		}
	})
	t.Run("enrol with the explicit override", func(t *testing.T) {
		if _, err := NewHandler(chain, issue, nil, Options{EnrollAuth: auth, AllowAnyIdentifier: true}); err != nil {
			t.Fatalf("rejected the deliberate override: %v", err)
		}
	})
	t.Run("label with a slash", func(t *testing.T) {
		if _, err := NewHandler(chain, issue, nil, Options{Label: "a/b"}); err == nil {
			t.Fatal("accepted a multi-segment label")
		}
	})
}

func TestServeRequiresClientCertRequest(t *testing.T) {
	chain := CAChainFunc(func(context.Context) ([][]byte, error) { return nil, nil })
	issue := IssueFunc(func(context.Context, []byte, []string) ([][]byte, error) { return nil, nil })
	h, err := NewHandler(chain, issue, nil, Options{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if _, err := Serve(context.Background(), "127.0.0.1:0", nil, h); err == nil {
		t.Fatal("Serve accepted a nil TLS config")
	}
	cfg := &tls.Config{ClientAuth: tls.NoClientCert, MinVersion: tls.VersionTLS12}
	if _, err := Serve(context.Background(), "127.0.0.1:0", cfg, h); err == nil {
		t.Fatal("Serve accepted a config that never asks for a client certificate")
	}
}
