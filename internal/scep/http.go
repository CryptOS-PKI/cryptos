package scep

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
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/cms"
)

// The paths SCEP is served on. /cgi-bin/pkiclient.exe is what Cisco IOS and
// many other clients append by default; /scep is the short form.
const (
	PathPKIClient = "/cgi-bin/pkiclient.exe"
	PathSCEP      = "/scep"
)

// Media types (RFC 8894 sections 4.2 to 4.4).
const (
	contentTypeCACaps     = "text/plain"
	contentTypeCARACert   = "application/x-x509-ca-ra-cert"
	contentTypePKIMessage = "application/x-pki-message"
)

// Capabilities is the GetCACaps answer. It lists only what this server does:
// AES content encryption, SHA-256 and SHA-512 signatures, POST for
// PKIOperation, and RenewalReq. DES, 3DES, MD5 and SHA-1 are refused, and
// GetNextCACert is not offered.
var Capabilities = []string{"AES", "POSTPKIOperation", "Renewal", "SHA-256", "SHA-512"}

// maxMessageBytes caps a PKIOperation message. The largest legitimate one is
// an encrypted PKCS#10 request with its signer certificate.
const maxMessageBytes = 1 << 20

// Routes returns the SCEP mux: the operations on PathPKIClient and PathSCEP.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(PathPKIClient, s.handle)
	mux.HandleFunc(PathSCEP, s.handle)
	return mux
}

// Mount adds the SCEP paths to mux, for sharing the plain-HTTP CRL/OCSP
// listener when both use one port.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc(PathPKIClient, s.handle)
	mux.HandleFunc(PathSCEP, s.handle)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	op := r.URL.Query().Get("operation")
	remote := r.RemoteAddr
	s.opts.Logf("scep: %s %s operation=%q from %s", r.Method, r.URL.Path, op, remote)
	switch op {
	case "GetCACaps":
		s.handleCACaps(w, r)
	case "GetCACert":
		s.handleCACert(w, r)
	case "PKIOperation":
		s.handlePKIOperation(w, r)
	case "GetNextCACert":
		http.Error(w, "GetNextCACert is not offered by this server", http.StatusNotImplemented)
	case "":
		http.Error(w, "the operation parameter is required", http.StatusBadRequest)
	default:
		http.Error(w, fmt.Sprintf("unknown operation %q", op), http.StatusBadRequest)
	}
}

// handleCACaps answers GetCACaps (RFC 8894 section 3.5.2).
func (s *Server) handleCACaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GetCACaps takes GET", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", contentTypeCACaps)
	_, _ = io.WriteString(w, strings.Join(Capabilities, "\n")+"\n")
}

// handleCACert answers GetCACert with the CA certificate and the newest RA
// certificate in a degenerate SignedData (RFC 8894 section 4.2.1.2). It is
// unauthenticated on purpose: a device that does not yet trust this CA has to
// fetch it, and the operator checks its fingerprint out of band.
func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GetCACert takes GET", http.StatusMethodNotAllowed)
		return
	}
	body, err := s.caRACert(r.Context())
	if err != nil {
		s.opts.Logf("scep: GetCACert: %v", err)
		http.Error(w, "the CA certificate is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeCARACert)
	_, _ = w.Write(body)
}

func (s *Server) caRACert(ctx context.Context) ([]byte, error) {
	chain, err := s.deps.CAChain(ctx)
	if err != nil {
		return nil, fmt.Errorf("load the CA chain: %w", err)
	}
	if len(chain) == 0 {
		return nil, errors.New("this node has no CA certificate")
	}
	ra, ok := s.ras.Current()
	if !ok {
		return nil, errors.New("no RA certificate is available")
	}
	return cms.Degenerate([][]byte{chain[0].Raw, ra.Cert.Raw}, nil)
}

// handlePKIOperation reads the message from the POST body or the GET message
// parameter (RFC 8894 section 4.3).
func (s *Server) handlePKIOperation(w http.ResponseWriter, r *http.Request) {
	var der []byte
	switch r.Method {
	case http.MethodPost:
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxMessageBytes+1))
		if err != nil {
			http.Error(w, "reading the request body failed", http.StatusBadRequest)
			return
		}
		if len(raw) > maxMessageBytes {
			http.Error(w, "the message is too large", http.StatusRequestEntityTooLarge)
			return
		}
		der = raw
	case http.MethodGet:
		msg := r.URL.Query().Get("message")
		if msg == "" {
			http.Error(w, "PKIOperation over GET needs the message parameter", http.StatusBadRequest)
			return
		}
		decoded, err := decodeMessageParam(msg)
		if err != nil {
			http.Error(w, "the message parameter is not base64", http.StatusBadRequest)
			return
		}
		der = decoded
	default:
		http.Error(w, "PKIOperation takes GET or POST", http.StatusMethodNotAllowed)
		return
	}
	if len(der) == 0 {
		http.Error(w, "the message is empty", http.StatusBadRequest)
		return
	}

	resp, err := s.pkiOperation(r.Context(), der, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, errMalformed) {
			http.Error(w, "the message is not a SCEP pkiMessage this server can answer", http.StatusBadRequest)
			return
		}
		s.opts.Logf("scep: PKIOperation: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypePKIMessage)
	_, _ = w.Write(resp)
}

// decodeMessageParam decodes the GET message parameter. RFC 8894 says base64;
// clients differ on padding, line breaks and whether "+" survived URL
// decoding as a space, so each of those is tolerated.
func decodeMessageParam(msg string) ([]byte, error) {
	msg = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t':
			return -1
		case ' ':
			return '+'
		}
		return r
	}, msg)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(msg); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// Serve starts a plain-HTTP server for h on addr and returns a stop closure.
// The listen is synchronous, so a bind failure reaches the caller. SCEP is
// plain HTTP by design: the CMS envelope carries confidentiality and
// integrity.
func Serve(_ context.Context, addr string, h http.Handler) (func(context.Context) error, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("scep: listen %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	go func() { _ = srv.Serve(lis) }()
	return srv.Shutdown, nil
}
