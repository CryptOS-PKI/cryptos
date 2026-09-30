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
	"crypto/x509"
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
)

// handleCACerts serves the CA chain (RFC 7030 section 4.1). It is
// unauthenticated on purpose: a client that does not yet trust this CA has to
// be able to fetch it, and the certificates it returns are public by
// definition.
func (h *Handler) handleCACerts(w http.ResponseWriter, r *http.Request) error {
	chain, err := h.caChain(r.Context())
	if err != nil {
		h.opts.Logf("est: loading the CA chain failed: %v", err)
		return errorf(http.StatusInternalServerError, "the CA chain is unavailable")
	}
	if len(chain) == 0 {
		return errorf(http.StatusInternalServerError, "this node has no CA certificate")
	}
	return writeCertsOnly(w, http.StatusOK, chain)
}

// handleCSRAttrs answers the optional attribute-request endpoint (RFC 7030
// section 4.5). This server imposes no attributes beyond what the profile
// stamps, and section 4.5.2 says a server with nothing to say answers 204
// rather than an empty structure.
func (h *Handler) handleCSRAttrs(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleSimpleEnroll issues to a client presenting an operator-provisioned
// HTTP Basic credential (RFC 7030 section 4.2.1).
//
// There is no proof of control here, so the credential is the only gate on
// who enrols and the identifier allowlist is the only gate on what they get.
func (h *Handler) handleSimpleEnroll(w http.ResponseWriter, r *http.Request) error {
	if h.opts.EnrollAuth == nil {
		return errorf(http.StatusForbidden, "this server does not offer simpleenroll; use simplereenroll or another enrolment protocol")
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return errorf(http.StatusUnauthorized, "simpleenroll requires HTTP Basic authentication")
	}
	if !h.opts.EnrollAuth(username, password) {
		h.opts.Logf("est: simpleenroll rejected credential for %q", username)
		return errorf(http.StatusUnauthorized, "the credential was not accepted")
	}

	csrDER, csr, err := h.readCSR(r)
	if err != nil {
		return err
	}
	names, err := csrNames(csr)
	if err != nil {
		return err
	}
	if err := h.checkAllowedNames(names); err != nil {
		h.opts.Logf("est: simpleenroll for %q rejected names %v: %v", username, names, err)
		return err
	}
	return h.issueAndWrite(r.Context(), w, csrDER, names)
}

// handleSimpleReenroll issues to a client presenting a certificate this CA
// issued (RFC 7030 section 4.2.1). It is the capability EST exists for.
//
// The names on the new certificate are pinned to the names on the old one.
// RFC 7030 section 4.2.2 puts this as a SHOULD on the client; enforcing it on
// the server is what keeps a renewal from becoming an escalation, since
// holding one certificate would otherwise let a client mint another for any
// name the policy allows.
func (h *Handler) handleSimpleReenroll(w http.ResponseWriter, r *http.Request) error {
	clientCert, err := clientCertificate(r)
	if err != nil {
		return err
	}
	if err := h.verifyReenrollClient(r.Context(), clientCert); err != nil {
		return err
	}

	csrDER, csr, err := h.readCSR(r)
	if err != nil {
		return err
	}
	names, err := csrNames(csr)
	if err != nil {
		return err
	}
	current := certNames(clientCert)
	if !sameNameSet(names, current) {
		h.opts.Logf("est: simplereenroll from %q asked for %v, holds %v",
			clientCert.Subject.CommonName, names, current)
		return errorf(http.StatusForbidden,
			"a re-enrolment must request the same names as the certificate it presents")
	}
	return h.issueAndWrite(r.Context(), w, csrDER, current)
}

// verifyReenrollClient checks that the presented certificate was issued by
// this CA, is currently valid, and has not been revoked.
//
// The chain is verified here rather than by the TLS stack because the anchor
// set is the live CA chain from the node, and because a certificate this CA
// issued and then revoked must not renew itself: a TLS handshake that only
// checked the signature would happily let it.
func (h *Handler) verifyReenrollClient(ctx context.Context, cert *x509.Certificate) error {
	chain, err := h.caChain(ctx)
	if err != nil {
		h.opts.Logf("est: loading the CA chain for re-enrolment failed: %v", err)
		return errorf(http.StatusInternalServerError, "the CA chain is unavailable")
	}
	pool := x509.NewCertPool()
	for _, der := range chain {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			h.opts.Logf("est: a CA chain certificate does not parse: %v", perr)
			return errorf(http.StatusInternalServerError, "the CA chain is unusable")
		}
		pool.AddCert(c)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: h.opts.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		h.opts.Logf("est: re-enrolment client certificate does not verify: %v", err)
		return errorf(http.StatusForbidden, "the client certificate was not issued by this CA")
	}

	if h.revoked == nil {
		return nil
	}
	serial := cert.SerialNumber.Text(16)
	revoked, err := h.revoked(ctx, serial)
	if err != nil {
		h.opts.Logf("est: revocation lookup for %s failed: %v", serial, err)
		return errorf(http.StatusInternalServerError, "the revocation status could not be checked")
	}
	if revoked {
		return errorf(http.StatusForbidden, "the client certificate is revoked")
	}
	return nil
}

// issueAndWrite issues and renders the result as a certs-only PKCS#7.
func (h *Handler) issueAndWrite(ctx context.Context, w http.ResponseWriter, csrDER []byte, names []string) error {
	chain, err := h.issue(ctx, csrDER, names)
	if err != nil {
		h.opts.Logf("est: issuing for %v failed: %v", names, err)
		return errorf(http.StatusBadRequest, "the certificate authority refused the request: %v", err)
	}
	if len(chain) == 0 {
		return errorf(http.StatusInternalServerError, "the certificate authority returned no certificate")
	}
	return writeCertsOnly(w, http.StatusOK, chain)
}

// readCSR reads and parses the PKCS#10 body.
//
// RFC 7030 section 4.2.1 specifies a base64-encoded body with
// Content-Transfer-Encoding: base64. Raw DER is accepted as a fallback
// because clients in the field send it, and accepting it costs nothing: the
// request is parsed and its signature verified either way.
func (h *Handler) readCSR(r *http.Request) ([]byte, *x509.CertificateRequest, error) {
	if err := requirePKCS10ContentType(r); err != nil {
		return nil, nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil {
		return nil, nil, errorf(http.StatusBadRequest, "reading the request body failed: %v", err)
	}
	if len(raw) > maxRequestBody {
		return nil, nil, errorf(http.StatusRequestEntityTooLarge, "the request body exceeds %d bytes", maxRequestBody)
	}
	if len(raw) == 0 {
		return nil, nil, errorf(http.StatusBadRequest, "the request carries no certificate request")
	}

	csrDER := raw
	// Base64 may arrive with the line breaks a MIME encoder inserts.
	if decoded, derr := base64.StdEncoding.DecodeString(stripWhitespace(string(raw))); derr == nil && len(decoded) > 0 {
		csrDER = decoded
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, errorf(http.StatusBadRequest, "the body is not a valid PKCS#10 request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, errorf(http.StatusBadRequest, "the certificate request signature does not verify: %v", err)
	}
	return csrDER, csr, nil
}

// requirePKCS10ContentType enforces the RFC 7030 media type, tolerating
// parameters some clients append.
func requirePKCS10ContentType(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return errorf(http.StatusUnsupportedMediaType, "request has no Content-Type; EST requires %s", contentTypePKCS10)
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return errorf(http.StatusUnsupportedMediaType, "request Content-Type %q is not a valid media type", ct)
	}
	if !strings.EqualFold(mt, contentTypePKCS10) {
		return errorf(http.StatusUnsupportedMediaType, "request Content-Type must be %s, got %s", contentTypePKCS10, mt)
	}
	return nil
}

// stripWhitespace removes the line breaks and padding whitespace a base64
// body may carry.
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// csrNames returns the DNS names a certificate request asks for: its dNSName
// SANs plus its common name when that is a hostname the SANs do not already
// carry. Non-DNS SANs are refused rather than dropped, so a client never gets
// back less than it asked for without being told.
func csrNames(csr *x509.CertificateRequest) ([]string, error) {
	if len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, errorf(http.StatusBadRequest,
			"the request carries a non-DNS subject alternative name, which this server does not issue")
	}
	names := collectNames(csr.DNSNames, csr.Subject.CommonName)
	if len(names) == 0 {
		return nil, errorf(http.StatusBadRequest, "the request carries no DNS name to certify")
	}
	if len(names) > maxIdentifiersPerRequest {
		return nil, errorf(http.StatusBadRequest,
			"the request carries %d names, more than the %d this server issues at once",
			len(names), maxIdentifiersPerRequest)
	}
	for _, n := range names {
		if err := validateDNSName(n); err != nil {
			return nil, err
		}
	}
	return names, nil
}

// certNames returns the DNS names on an issued certificate, in the same
// normalized form csrNames produces, so the two can be compared.
func certNames(cert *x509.Certificate) []string {
	return collectNames(cert.DNSNames, cert.Subject.CommonName)
}

// collectNames lowercases, strips a trailing dot, folds in a common name that
// is not already a SAN, and de-duplicates while keeping first-seen order.
func collectNames(dnsNames []string, commonName string) []string {
	seen := make(map[string]bool, len(dnsNames)+1)
	out := make([]string, 0, len(dnsNames)+1)
	add := func(n string) {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range dnsNames {
		add(n)
	}
	// A common name that is not a hostname (an organizational DN component,
	// say) is not a name to certify; only fold it in when it looks like one.
	if strings.Contains(commonName, ".") && !strings.ContainsAny(commonName, " ,=") {
		add(commonName)
	}
	return out
}

// sameNameSet reports whether two name lists hold the same set, order aside.
func sameNameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// checkAllowedNames enforces the simpleenroll identifier allowlist.
func (h *Handler) checkAllowedNames(names []string) error {
	if h.opts.AllowAnyIdentifier {
		return nil
	}
	for _, name := range names {
		if !suffixAllowed(name, h.opts.AllowedSuffixes) {
			return errorf(http.StatusForbidden, "this server does not issue for %s", name)
		}
	}
	return nil
}

// suffixAllowed reports whether name equals or is a subdomain of one of the
// suffixes. Matching is on a label boundary, so "example.org" covers
// "web.example.org" but not "notexample.org".
func suffixAllowed(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		s := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(suffix, "."), "."))
		if s == "" {
			continue
		}
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// validateDNSName applies the preferred-name-syntax rules a certificate SAN
// must satisfy. Wildcards are refused: nothing in EST establishes control of
// a label space, and a wildcard from a shared credential is a large grant
// from a small secret.
func validateDNSName(name string) error {
	if strings.Contains(name, "*") {
		return errorf(http.StatusForbidden, "this server does not issue wildcard certificates")
	}
	if len(name) > 253 {
		return errorf(http.StatusBadRequest, "the name %q exceeds 253 characters", name)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return errorf(http.StatusBadRequest, "the name %q is not a fully qualified domain name", name)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return errorf(http.StatusBadRequest, "the name %q has an empty or over-long label", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errorf(http.StatusBadRequest, "the name %q has a label starting or ending with a hyphen", name)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' {
				return errorf(http.StatusBadRequest, "the name %q contains a character that is not allowed in a hostname", name)
			}
		}
	}
	return nil
}
