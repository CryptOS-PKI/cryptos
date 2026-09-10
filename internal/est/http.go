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
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// WellKnownPrefix is the fixed path EST lives under (RFC 7030 section 3.2.2).
// An optional arbitrary label may follow it, which is how one server offers
// several CAs; this server supports at most one label.
const WellKnownPrefix = "/.well-known/est"

// Media types (RFC 7030 sections 4.1.3 and 4.2).
const (
	contentTypePKCS10 = "application/pkcs10"
	contentTypePKCS7  = "application/pkcs7-mime; smime-type=certs-only"
)

// maxRequestBody caps a request body. The largest legitimate body is a
// base64 PKCS#10 request.
const maxRequestBody = 256 << 10

// maxIdentifiersPerRequest bounds the SAN count on one CSR.
const maxIdentifiersPerRequest = 100

// IssueFunc issues a certificate for csrDER with exactly the SAN set in
// dnsNames and returns the chain leaf-first in DER. In production this is
// backed by node.CASigner.IssueLeafForNames, so the configured profile decides
// every other extension and the certificate is recorded in the revocation
// issued set before it is returned.
type IssueFunc func(ctx context.Context, csrDER []byte, dnsNames []string) (chainDER [][]byte, err error)

// CAChainFunc returns this node's CA certificate and its issuers, leaf-first,
// in DER. It backs /cacerts and it is the trust anchor set a re-enrolling
// client's certificate is verified against.
type CAChainFunc func(ctx context.Context) (chainDER [][]byte, err error)

// RevokedFunc reports whether the certificate with the given lowercase hex
// serial has been revoked. A nil RevokedFunc means the check is skipped, which
// is only appropriate where no revocation store exists.
type RevokedFunc func(ctx context.Context, serialHex string) (bool, error)

// EnrollAuthFunc reports whether an HTTP Basic credential is valid for
// simpleenroll. A nil EnrollAuthFunc disables simpleenroll entirely: the
// endpoint answers 403 rather than enrolling anyone who asks.
type EnrollAuthFunc func(username, password string) bool

// StaticEnrollCredentials returns an EnrollAuthFunc over a fixed map of
// username to the SHA-256 of the password.
//
// The digest rather than the password is what an operator puts in the node
// config, so the running configuration never holds a live credential. That is
// only safe because the password is required to be a high-entropy generated
// value: a plain digest of an operator-chosen word would fall to a dictionary,
// which is why config validation demands 32 bytes of randomness.
func StaticEnrollCredentials(digests map[string][]byte) EnrollAuthFunc {
	return func(username, password string) bool {
		want, ok := digests[username]
		sum := sha256.Sum256([]byte(password))
		// The comparison runs even for an unknown username so that a valid
		// and an invalid username cost the same.
		match := subtle.ConstantTimeCompare(want, sum[:]) == 1
		return ok && match
	}
}

// Options configures a Handler.
type Options struct {
	// Label is the optional arbitrary path segment between /.well-known/est
	// and the operation (RFC 7030 section 3.2.2). Empty serves the
	// unlabelled paths.
	Label string

	// AllowedSuffixes restricts the DNS names simpleenroll will issue for: a
	// name must equal, or be a subdomain of, one of these. It does not apply
	// to simplereenroll, whose names are pinned to the client's existing
	// certificate.
	AllowedSuffixes []string

	// AllowAnyIdentifier drops the AllowedSuffixes requirement for
	// simpleenroll. It has to be set by name because simpleenroll has no
	// proof of control: without an allowlist, one leaked credential mints a
	// certificate for any name at all.
	AllowAnyIdentifier bool

	// EnrollAuth authenticates simpleenroll. Nil disables that endpoint.
	EnrollAuth EnrollAuthFunc

	// Realm is the HTTP Basic realm offered on a simpleenroll challenge.
	Realm string

	// Now supplies the current time; nil means time.Now. Tests set it.
	Now func() time.Time

	// Logf receives one line per rejected request and per internal error.
	// Nil discards.
	Logf func(format string, args ...any)
}

// Handler serves the EST endpoints. It holds no key: the CA chain, issuance
// and the revocation check all arrive as closures.
type Handler struct {
	caChain CAChainFunc
	issue   IssueFunc
	revoked RevokedFunc
	opts    Options
}

// NewHandler validates opts and returns a Handler. caChain and issue are
// required; revoked may be nil, in which case a re-enrolling client's
// revocation status is not consulted.
func NewHandler(caChain CAChainFunc, issue IssueFunc, revoked RevokedFunc, opts Options) (*Handler, error) {
	if caChain == nil {
		return nil, errors.New("est: NewHandler: caChain is required")
	}
	if issue == nil {
		return nil, errors.New("est: NewHandler: issue is required")
	}
	if opts.EnrollAuth != nil && len(opts.AllowedSuffixes) == 0 && !opts.AllowAnyIdentifier {
		return nil, errors.New("est: NewHandler: simpleenroll needs AllowedSuffixes, " +
			"or AllowAnyIdentifier set deliberately: the endpoint has no proof of control")
	}
	if strings.Contains(opts.Label, "/") {
		return nil, fmt.Errorf("est: NewHandler: Label must be a single path segment, got %q", opts.Label)
	}
	if opts.Realm == "" {
		opts.Realm = "cryptos est"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &Handler{caChain: caChain, issue: issue, revoked: revoked, opts: opts}, nil
}

// Operation path segments, relative to the well-known prefix and label.
const (
	opCACerts        = "/cacerts"
	opSimpleEnroll   = "/simpleenroll"
	opSimpleReenroll = "/simplereenroll"
	opCSRAttrs       = "/csrattrs"
)

// base returns the path prefix every operation hangs off.
func (h *Handler) base() string {
	if h.opts.Label == "" {
		return WellKnownPrefix
	}
	return WellKnownPrefix + "/" + h.opts.Label
}

// Routes returns the EST mux, ready to mount at the root of a TLS server.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	b := h.base()
	mux.HandleFunc("GET "+b+opCACerts, h.wrap(h.handleCACerts))
	mux.HandleFunc("GET "+b+opCSRAttrs, h.wrap(h.handleCSRAttrs))
	mux.HandleFunc("POST "+b+opSimpleEnroll, h.wrap(h.handleSimpleEnroll))
	mux.HandleFunc("POST "+b+opSimpleReenroll, h.wrap(h.handleSimpleReenroll))
	return mux
}

// httpError is an error carrying the status EST should answer with. RFC 7030
// section 4.2.3 asks for a status code and a human-readable body rather than
// a structured error document, so this is deliberately thinner than ACME's
// problem type.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func errorf(status int, format string, args ...any) *httpError {
	return &httpError{status: status, msg: fmt.Sprintf(format, args...)}
}

// handlerFunc is an endpoint that may fail with an *httpError.
type handlerFunc func(w http.ResponseWriter, r *http.Request) error

// wrap renders a returned error. A non-httpError is a bug: it is logged in
// full and reported as a bare 500 so nothing internal reaches the client.
func (h *Handler) wrap(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := fn(w, r)
		if err == nil {
			return
		}
		var he *httpError
		if !errors.As(err, &he) {
			h.opts.Logf("est: unexpected handler error: %v", err)
			he = errorf(http.StatusInternalServerError, "internal error")
		}
		if he.status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+h.opts.Realm+`"`)
		}
		http.Error(w, he.msg, he.status)
	}
}

// writeCertsOnly renders a certificate chain as the base64 certs-only PKCS#7
// body EST expects (RFC 7030 section 4.1.3: the message is base64-encoded and
// the response says so with Content-Transfer-Encoding).
func writeCertsOnly(w http.ResponseWriter, status int, chainDER [][]byte) error {
	p7, err := CertsOnlyPKCS7(chainDER)
	if err != nil {
		return err
	}
	body := base64.StdEncoding.EncodeToString(p7)
	w.Header().Set("Content-Type", contentTypePKCS7)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
	return nil
}

// Serve starts a TLS http.Server bound to addr serving h.Routes and returns a
// stop closure. It mirrors revocation.Serve and acme.Serve: the listen is
// synchronous so a bind failure reaches the caller instead of dying in a
// goroutine, and a ReadHeaderTimeout guards the listener.
//
// tlsCfg is required and must request a client certificate, because
// simplereenroll authenticates with one. It must not *require* one: /cacerts
// exists precisely for a client that has nothing yet.
func Serve(_ context.Context, addr string, tlsCfg *tls.Config, h *Handler) (func(context.Context) error, error) {
	if tlsCfg == nil {
		return nil, errors.New("est: Serve: a TLS config is required; EST does not run over plaintext")
	}
	switch tlsCfg.ClientAuth {
	case tls.RequestClientCert, tls.VerifyClientCertIfGiven,
		tls.RequireAnyClientCert, tls.RequireAndVerifyClientCert:
	default:
		return nil, errors.New("est: Serve: TLSConfig.ClientAuth must request a client certificate " +
			"so simplereenroll can authenticate with one")
	}
	lis, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("est: listen %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           h.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = srv.Serve(lis)
	}()
	return srv.Shutdown, nil
}

// clientCertificate returns the verified TLS client certificate, or an error
// when the connection presented none.
//
// It reads only r.TLS, so the transport decides how the certificate got here.
// The listener must be TLS with at least RequestClientCert; chain verification
// against this CA happens in verifyReenrollClient rather than being delegated
// to the TLS stack, because the anchor set is the live CA chain and the check
// includes revocation.
func clientCertificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil {
		return nil, errorf(http.StatusForbidden, "simplereenroll requires TLS")
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, errorf(http.StatusForbidden, "simplereenroll requires a TLS client certificate")
	}
	return r.TLS.PeerCertificates[0], nil
}
