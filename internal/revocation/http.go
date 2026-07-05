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
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// errMethodNotAllowed marks an OCSP request that used neither GET nor POST.
var errMethodNotAllowed = errors.New("revocation: ocsp: method not allowed")

// maxOCSPRequestBytes caps the OCSP request body read on the unauthenticated
// listener. RFC 6960 requests are small; this bounds a hostile client.
const maxOCSPRequestBytes = 64 << 10

// Handler serves the anonymous revocation endpoints. It carries no key or
// store state: the node supplies a crl provider closure (and, once wired, an
// ocsp closure) that load the CA key and build the responses on demand.
type Handler struct {
	crl  func(ctx context.Context) ([]byte, error)
	ocsp func(ctx context.Context, reqDER []byte) ([]byte, error)
}

// NewHandler returns a Handler that serves the CRL from crl. The ocspFn closure
// backs the /ocsp endpoint; when it is nil, /ocsp reports 501 Not Implemented
// (the OCSP responder is wired in a later milestone).
func NewHandler(crl func(context.Context) ([]byte, error), ocspFn func(context.Context, []byte) ([]byte, error)) *Handler {
	return &Handler{crl: crl, ocsp: ocspFn}
}

// Routes returns the anonymous HTTP mux: GET /crl yields the DER CRL as
// application/pkix-crl; /ocsp yields an application/ocsp-response once the
// responder is wired, and 501 until then.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/crl", h.handleCRL)
	mux.HandleFunc("/ocsp", h.handleOCSP)
	return mux
}

func (h *Handler) handleCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	der, err := h.crl(r.Context())
	if err != nil {
		http.Error(w, "crl unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}

func (h *Handler) handleOCSP(w http.ResponseWriter, r *http.Request) {
	if h.ocsp == nil {
		// The responder closure is unset (a CRL-only boot). Advertise the
		// endpoint as not yet implemented.
		http.Error(w, "ocsp not implemented", http.StatusNotImplemented)
		return
	}

	reqDER, err := readOCSPRequest(r)
	if err != nil {
		// A request we cannot decode is malformed: reply with the fixed RFC
		// 6960 malformedRequest response rather than a transport error.
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
		return
	}

	respDER, err := h.ocsp(r.Context(), reqDER)
	if err != nil {
		// The responder could not parse the request into a well-formed query.
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(respDER)
}

// readOCSPRequest extracts the DER-encoded OCSP request from an RFC 6960 HTTP
// request: a POST carries the DER in the body; a GET carries it base64-encoded
// in the path segment after /ocsp/.
func readOCSPRequest(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodPost:
		return io.ReadAll(io.LimitReader(r.Body, maxOCSPRequestBytes))
	case http.MethodGet:
		encoded := strings.TrimPrefix(r.URL.Path, "/ocsp/")
		return base64.StdEncoding.DecodeString(encoded)
	default:
		return nil, errMethodNotAllowed
	}
}

// Serve starts an anonymous http.Server bound to addr serving h.Routes and
// returns a stop closure that gracefully shuts the server down. A
// ReadHeaderTimeout guards against slow-header clients on the unauthenticated
// listener.
func Serve(_ context.Context, addr string, h *Handler) (func(context.Context) error, error) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = srv.ListenAndServe()
	}()
	return srv.Shutdown, nil
}
