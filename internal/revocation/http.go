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
	"net/http"
	"time"
)

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

func (h *Handler) handleOCSP(w http.ResponseWriter, _ *http.Request) {
	// The OCSP responder is wired in a later milestone. Until h.ocsp is set,
	// advertise the endpoint as not yet implemented.
	http.Error(w, "ocsp not implemented", http.StatusNotImplemented)
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
