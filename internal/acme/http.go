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
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// contentTypeJOSE is the media type RFC 8555 section 6.2 requires on every
// ACME POST.
const contentTypeJOSE = "application/jose+json"

// maxRequestBody caps a request body on this unauthenticated listener. The
// largest legitimate body is a finalize carrying a base64url CSR.
const maxRequestBody = 256 << 10

// maxIdentifiersPerOrder bounds one order. Each identifier costs an
// authorization record and an outbound validation fetch, so an unbounded list
// is an amplification vector.
const maxIdentifiersPerOrder = 100

// Default lifetimes. An order and its authorizations expire together: there is
// no authorization reuse across orders, so nothing outlives its order.
const (
	DefaultOrderTTL = 7 * 24 * time.Hour
	// DefaultNonceTTL is short on purpose. Every nonce is a row in etcd, and
	// every response that carries one writes it there, so the steady-state
	// footprint of an endpoint being hammered is the request rate times this
	// window. Clients fetch a nonce immediately before the POST that spends
	// it, so fifteen minutes is far more slack than any of them need.
	DefaultNonceTTL = 15 * time.Minute
)

// IssueFunc issues a certificate for csrDER with exactly the SAN set in
// dnsNames, returning the PEM chain leaf-first and the lowercase hex serial.
// In production this is backed by node.CASigner.IssueLeaf, so the configured
// profile decides every other extension and the certificate is recorded in
// the revocation issued set before it is returned.
type IssueFunc func(ctx context.Context, csrDER []byte, dnsNames []string) (chainPEM string, serialHex string, err error)

// RevokeFunc revokes the certificate with the given lowercase hex serial. It
// returns ErrCertificateAlreadyRevoked when the serial is already revoked, so
// the handler can answer with the RFC 8555 alreadyRevoked problem rather than
// reporting a success the client did not cause.
type RevokeFunc func(ctx context.Context, serialHex string, reason int) error

// EABKeyFunc returns the HMAC key provisioned for an external account binding
// key ID, or ErrUnknownEABKey when the ID is not provisioned.
type EABKeyFunc func(keyID string) ([]byte, error)

// ErrCertificateAlreadyRevoked is the sentinel a RevokeFunc returns for a
// serial that is already revoked.
var ErrCertificateAlreadyRevoked = errors.New("acme: certificate already revoked")

// ErrUnknownEABKey is the sentinel an EABKeyFunc returns for an unprovisioned
// key ID. The handler folds it into the same problem a bad MAC produces, so a
// caller cannot probe which key IDs exist.
var ErrUnknownEABKey = errUnknownEABKey

// StaticEABKeys returns an EABKeyFunc backed by a fixed map of key ID to HMAC
// key, which is how the operator provisions bindings in the node config.
func StaticEABKeys(keys map[string][]byte) EABKeyFunc {
	return func(keyID string) ([]byte, error) {
		k, ok := keys[keyID]
		if !ok || len(k) == 0 {
			return nil, ErrUnknownEABKey
		}
		return k, nil
	}
}

// Options configures a Handler. BaseURL is the only required field.
type Options struct {
	// BaseURL is the externally reachable base under which this server's ACME
	// endpoints live, for example https://ca.example.org/acme. Every URL the
	// server hands a client is built from it, and every request's protected
	// url header is checked against it, so it must be what clients actually
	// dial rather than what this process happens to bind.
	BaseURL string

	// TermsOfService, when set, is advertised in the directory meta and a new
	// account must agree to it.
	TermsOfService string

	// Website is advertised in the directory meta.
	Website string

	// ExternalAccountRequired demands an RFC 8555 section 7.3.4 external
	// account binding on every new account. EABKey must be set with it.
	ExternalAccountRequired bool

	// EABKey resolves an external account binding key ID to its HMAC key.
	EABKey EABKeyFunc

	// AllowedSuffixes, when non-empty, restricts the DNS identifiers this
	// server will order for: an identifier must equal, or be a subdomain of,
	// one of these. Empty means any name a client can prove control of.
	AllowedSuffixes []string

	// OrderTTL is how long an order and its authorizations remain valid.
	// Zero means DefaultOrderTTL.
	OrderTTL time.Duration

	// NonceTTL is how long an unused nonce remains usable. Zero means
	// DefaultNonceTTL.
	NonceTTL time.Duration

	// Now supplies the current time; nil means time.Now. Tests set it.
	Now func() time.Time

	// Logf receives one line per failed validation and per internal error.
	// Nil discards. Problem details returned to a client are deliberately
	// coarse, so this is where an operator sees what actually broke.
	Logf func(format string, args ...any)
}

// Handler serves the ACME endpoints. Like revocation.Handler it holds no key
// and no signer: issuance, revocation and identifier validation all arrive as
// closures, so the protocol layer can be exercised without a CA behind it.
type Handler struct {
	store    *Store
	issue    IssueFunc
	revoke   RevokeFunc
	validate Validator
	opts     Options

	// origin is the scheme://host of BaseURL, used to reconstruct the
	// absolute URL of an incoming request without trusting the Host header.
	origin string
	// prefix is the path component of BaseURL, so the returned mux can be
	// mounted at the root of a server and still produce matching URLs.
	prefix string
}

// NewHandler validates opts and returns a Handler. store, issue and validate
// are required; revoke may be nil, in which case revoke-cert answers 501 and
// is omitted from the directory.
func NewHandler(store *Store, issue IssueFunc, revoke RevokeFunc, validate Validator, opts Options) (*Handler, error) {
	if store == nil {
		return nil, errors.New("acme: NewHandler: store is required")
	}
	if issue == nil {
		return nil, errors.New("acme: NewHandler: issue is required")
	}
	if validate == nil {
		return nil, errors.New("acme: NewHandler: validate is required")
	}
	if opts.ExternalAccountRequired && opts.EABKey == nil {
		return nil, errors.New("acme: NewHandler: ExternalAccountRequired is set but no EABKey resolver was supplied")
	}
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("acme: NewHandler: parse BaseURL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("acme: NewHandler: BaseURL must be http or https, got %q", opts.BaseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("acme: NewHandler: BaseURL has no host: %q", opts.BaseURL)
	}
	if opts.OrderTTL <= 0 {
		opts.OrderTTL = DefaultOrderTTL
	}
	if opts.NonceTTL <= 0 {
		opts.NonceTTL = DefaultNonceTTL
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &Handler{
		store:    store,
		issue:    issue,
		revoke:   revoke,
		validate: validate,
		opts:     opts,
		origin:   u.Scheme + "://" + u.Host,
		prefix:   strings.TrimRight(u.Path, "/"),
	}, nil
}

// Endpoint path segments, relative to the BaseURL path prefix.
const (
	pathDirectory  = "/directory"
	pathNewNonce   = "/new-nonce"
	pathNewAccount = "/new-account"
	pathNewOrder   = "/new-order"
	pathAccount    = "/account/"
	pathOrders     = "/orders/"
	pathOrder      = "/order/"
	pathAuthz      = "/authz/"
	pathChallenge  = "/challenge/"
	pathCert       = "/cert/"
	pathRevokeCert = "/revoke-cert"
)

// Routes returns the ACME mux. Patterns carry their method and the BaseURL
// path prefix, so mounting the result at the root of an http.Server produces
// exactly the URLs the directory advertises.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	p := h.prefix

	// The directory is the one route that does not mint a nonce. It is an
	// unauthenticated GET with no body, so it is the cheapest request an
	// attacker can make; minting a stored nonce for each one would turn it
	// into a write amplifier against etcd. RFC 8555 only requires a
	// Replay-Nonce on new-nonce and on responses to POSTs.
	mux.HandleFunc("GET "+p+pathDirectory, h.wrapWithoutNonce(h.handleDirectory))
	mux.HandleFunc("GET "+p+pathNewNonce, h.wrap(h.handleNewNonce))
	mux.HandleFunc("HEAD "+p+pathNewNonce, h.wrap(h.handleNewNonce))
	mux.HandleFunc("POST "+p+pathNewAccount, h.wrap(h.handleNewAccount))
	mux.HandleFunc("POST "+p+pathNewOrder, h.wrap(h.handleNewOrder))
	mux.HandleFunc("POST "+p+pathAccount+"{id}", h.wrap(h.handleAccount))
	mux.HandleFunc("POST "+p+pathOrders+"{id}", h.wrap(h.handleOrdersList))
	mux.HandleFunc("POST "+p+pathOrder+"{id}", h.wrap(h.handleOrder))
	mux.HandleFunc("POST "+p+pathOrder+"{id}/finalize", h.wrap(h.handleFinalize))
	mux.HandleFunc("POST "+p+pathAuthz+"{id}", h.wrap(h.handleAuthz))
	mux.HandleFunc("POST "+p+pathChallenge+"{id}/{type}", h.wrap(h.handleChallenge))
	mux.HandleFunc("POST "+p+pathCert+"{id}", h.wrap(h.handleCert))
	mux.HandleFunc("POST "+p+pathRevokeCert, h.wrap(h.handleRevokeCert))

	return mux
}

// url builds an absolute URL for a path relative to the BaseURL prefix.
func (h *Handler) url(path string) string {
	return h.origin + h.prefix + path
}

// requestURL reconstructs the absolute URL of r from the configured origin
// rather than from r.Host. A client's protected url header is checked against
// this, and letting an attacker set the expected value via a Host header would
// void that check entirely.
func (h *Handler) requestURL(r *http.Request) string {
	return h.origin + r.URL.Path
}

// handlerFunc is an endpoint that may fail with a *Problem.
type handlerFunc func(w http.ResponseWriter, r *http.Request) error

// wrap adapts a handlerFunc to http.HandlerFunc: it stamps the headers every
// ACME response carries, renders a returned Problem as RFC 7807, and makes
// sure a fresh nonce accompanies even an error (RFC 8555 section 6.5 requires
// one on a badNonce, and a client that cannot get a nonce cannot retry).
func (h *Handler) wrap(fn handlerFunc) http.HandlerFunc {
	return h.serve(fn, true)
}

// wrapWithoutNonce is wrap for a route that must not mint a nonce.
func (h *Handler) wrapWithoutNonce(fn handlerFunc) http.HandlerFunc {
	return h.serve(fn, false)
}

func (h *Handler) serve(fn handlerFunc, mintNonce bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `<`+h.url(pathDirectory)+`>;rel="index"`)
		w.Header().Set("Cache-Control", "no-store")
		if mintNonce {
			if nonce, err := h.store.NewNonce(r.Context(), h.opts.NonceTTL); err == nil {
				w.Header().Set("Replay-Nonce", nonce)
			} else {
				h.opts.Logf("acme: minting a Replay-Nonce failed: %v", err)
			}
		}

		if err := fn(w, r); err != nil {
			h.writeProblem(w, err)
		}
	}
}

// writeProblem renders err as an RFC 7807 problem document. A non-Problem
// error is a bug in a handler: it is logged in full and reported as a bare
// serverInternal so nothing internal leaks to an anonymous caller.
func (h *Handler) writeProblem(w http.ResponseWriter, err error) {
	var prob *Problem
	if !errors.As(err, &prob) {
		h.opts.Logf("acme: unexpected handler error: %v", err)
		prob = serverInternal("the server encountered an internal error")
	}
	status := prob.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	body, merr := json.Marshal(prob)
	if merr != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeJSON renders v as an ACME JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return serverInternal("encoding the response failed")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
	return nil
}

// signedRequest is a verified ACME POST: the JWS signature has been checked,
// the protected url matched this endpoint, and the nonce has been consumed.
type signedRequest struct {
	hdr        *protectedHeader
	payload    []byte
	key        crypto.PublicKey
	jwk        *JWK
	thumbprint string

	// account is set when the request was signed with a kid, and nil when it
	// was signed with an embedded jwk.
	account *Account
}

// postAsGet reports whether the request is the RFC 8555 section 6.3
// POST-as-GET form: a signed request with an empty payload.
func (s *signedRequest) postAsGet() bool { return len(s.payload) == 0 }

// authKind selects which key-identification forms an endpoint accepts.
type authKind int

const (
	// authAccount requires a kid pointing at an existing account. Everything
	// except new-account and revoke-cert uses this.
	authAccount authKind = iota
	// authEmbeddedKey requires an embedded jwk: new-account, where no account
	// exists yet to point a kid at.
	authEmbeddedKey
	// authEither accepts both: revoke-cert, which may be signed by the
	// account that ordered the certificate or by the certificate key itself.
	authEither
)

// authenticate performs the checks every ACME POST shares: media type, body
// size, JWS structure, url binding, signature, and nonce.
//
// The signature is verified before the nonce is consumed. Both orderings are
// safe against replay, since a replayed request fails whichever check runs
// second, but this ordering does not burn a nonce on a client that merely got
// its signature wrong.
func (h *Handler) authenticate(r *http.Request, kind authKind) (*signedRequest, error) {
	if err := requireJOSEContentType(r); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil {
		return nil, malformed("reading the request body failed: %v", err)
	}
	if len(body) > maxRequestBody {
		return nil, malformed("request body exceeds %d bytes", maxRequestBody)
	}

	jws, hdr, payload, err := parseJWS(body)
	if err != nil {
		return nil, err
	}

	// RFC 8555 section 6.4: the protected url must name the endpoint the
	// request was sent to, so a signed request cannot be replayed against a
	// different resource.
	if want := h.requestURL(r); hdr.URL != want {
		return nil, malformed("JWS url header %q does not match the request url %q", hdr.URL, want)
	}

	req := &signedRequest{hdr: hdr, payload: payload}

	switch {
	case hdr.JWK != nil:
		if kind == authAccount {
			return nil, malformed("this endpoint requires a kid, not an embedded jwk")
		}
		key, kerr := hdr.JWK.PublicKey()
		if kerr != nil {
			return nil, kerr
		}
		thumb, terr := hdr.JWK.Thumbprint()
		if terr != nil {
			return nil, terr
		}
		req.key, req.jwk, req.thumbprint = key, hdr.JWK, thumb

	default:
		if kind == authEmbeddedKey {
			return nil, malformed("this endpoint requires an embedded jwk, not a kid")
		}
		acct, aerr := h.accountFromKID(r.Context(), hdr.KID)
		if aerr != nil {
			return nil, aerr
		}
		key, kerr := acct.Key.PublicKey()
		if kerr != nil {
			return nil, kerr
		}
		req.account, req.key, req.jwk, req.thumbprint = &acct, key, &acct.Key, acct.KeyThumbprint
	}

	if err := verifyJWS(jws, hdr.Alg, req.key); err != nil {
		return nil, err
	}

	if hdr.Nonce == "" {
		return nil, problemf(ErrBadNonce, http.StatusBadRequest, "the request carries no anti-replay nonce")
	}
	ok, err := h.store.ConsumeNonce(r.Context(), hdr.Nonce)
	if err != nil {
		h.opts.Logf("acme: consuming a nonce failed: %v", err)
		return nil, serverInternal("the server could not verify the request nonce")
	}
	if !ok {
		return nil, problemf(ErrBadNonce, http.StatusBadRequest,
			"the nonce %q is unknown, expired, or already used", hdr.Nonce)
	}

	if req.account != nil && req.account.Status != StatusValid {
		return nil, unauthorized("account %s is %s", req.account.ID, req.account.Status)
	}
	return req, nil
}

// accountFromKID resolves the kid, which RFC 8555 defines as the account URL,
// to the stored account.
func (h *Handler) accountFromKID(ctx context.Context, kid string) (Account, error) {
	want := h.url(pathAccount)
	if !strings.HasPrefix(kid, want) {
		return Account{}, malformed("kid %q is not an account URL issued by this server", kid)
	}
	id := strings.TrimPrefix(kid, want)
	if id == "" || strings.Contains(id, "/") {
		return Account{}, malformed("kid %q is not an account URL issued by this server", kid)
	}
	acct, err := h.store.GetAccount(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Account{}, problemf(ErrAccountDoesNotExist, http.StatusBadRequest, "no account %s", id)
	}
	if err != nil {
		h.opts.Logf("acme: loading account %s failed: %v", id, err)
		return Account{}, serverInternal("the server could not load the account")
	}
	return acct, nil
}

// requireJOSEContentType enforces the RFC 8555 section 6.2 media type,
// tolerating parameters such as a charset that some clients append.
func requireJOSEContentType(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return malformed("request has no Content-Type; ACME requires %s", contentTypeJOSE)
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return malformed("request Content-Type %q is not a valid media type", ct)
	}
	if !strings.EqualFold(mt, contentTypeJOSE) {
		return malformed("request Content-Type must be %s, got %s", contentTypeJOSE, mt)
	}
	return nil
}

// unmarshalPayload decodes a JWS payload into v, rejecting the POST-as-GET
// form for an endpoint that needs a body.
func unmarshalPayload(req *signedRequest, v any) error {
	if req.postAsGet() {
		return malformed("this endpoint requires a request payload")
	}
	if err := json.Unmarshal(req.payload, v); err != nil {
		return malformed("request payload is not valid JSON: %v", err)
	}
	return nil
}

// Serve starts an http.Server bound to addr serving h.Routes and returns a
// stop closure. It mirrors revocation.Serve: the listen is synchronous so a
// bind failure reaches the caller instead of dying in a goroutine, and a
// ReadHeaderTimeout guards the unauthenticated listener.
func Serve(_ context.Context, addr string, h *Handler) (func(context.Context) error, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("acme: listen %s: %w", addr, err)
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
