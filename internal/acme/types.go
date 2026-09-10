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
	"fmt"
	"net/http"
	"time"
)

// Resource status values (RFC 8555 section 7.1.6). Not every value applies to
// every resource: an account is valid/deactivated/revoked, an order walks
// pending -> ready -> processing -> valid (or invalid), and an authorization
// walks pending -> valid (or invalid/expired/deactivated/revoked).
const (
	StatusPending     = "pending"
	StatusReady       = "ready"
	StatusProcessing  = "processing"
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusRevoked     = "revoked"
)

// IdentifierTypeDNS is the only identifier type this server accepts. RFC 8738
// adds "ip"; http-01 could prove it, but an IP-SAN certificate from an
// internal CA is a separate policy decision and is refused for now.
const IdentifierTypeDNS = "dns"

// ChallengeTypeHTTP01 is the only challenge type this server offers.
const ChallengeTypeHTTP01 = "http-01"

// Identifier is an RFC 8555 section 9.7.7 identifier object.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Directory is the RFC 8555 section 7.1.1 directory object. keyChange is
// deliberately absent: this server does not implement it, and advertising a
// URL that answers 404 is worse than omitting the field, which clients treat
// as "unsupported".
type Directory struct {
	NewNonce   string         `json:"newNonce"`
	NewAccount string         `json:"newAccount"`
	NewOrder   string         `json:"newOrder"`
	RevokeCert string         `json:"revokeCert"`
	Meta       *DirectoryMeta `json:"meta,omitempty"`
}

// DirectoryMeta is the directory "meta" object (RFC 8555 section 7.1.1).
type DirectoryMeta struct {
	TermsOfService          string `json:"termsOfService,omitempty"`
	Website                 string `json:"website,omitempty"`
	ExternalAccountRequired bool   `json:"externalAccountRequired,omitempty"`
}

// AccountResource is the account object as it appears on the wire (RFC 8555
// section 7.1.2). It is not the stored record; see Account in store.go.
type AccountResource struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders"`
}

// OrdersList is the RFC 8555 section 7.1.2.1 orders-list object.
type OrdersList struct {
	Orders []string `json:"orders"`
}

// newAccountRequest is the RFC 8555 section 7.3 new-account payload.
type newAccountRequest struct {
	Contact                []string      `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool          `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting     bool          `json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding *flattenedJWS `json:"externalAccountBinding,omitempty"`
}

// updateAccountRequest is the subset of an account update this server honours
// (RFC 8555 section 7.3.2). Only contact is mutable here; deactivation is not
// implemented, so a status other than "valid" is refused rather than silently
// ignored.
type updateAccountRequest struct {
	Contact []string `json:"contact,omitempty"`
	Status  string   `json:"status,omitempty"`
}

// OrderResource is the order object as it appears on the wire (RFC 8555
// section 7.1.3).
type OrderResource struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Error          *Problem     `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
}

// newOrderRequest is the RFC 8555 section 7.4 new-order payload.
type newOrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

// finalizeRequest is the RFC 8555 section 7.4 finalize payload: a base64url
// DER PKCS#10 CSR.
type finalizeRequest struct {
	CSR string `json:"csr"`
}

// AuthorizationResource is the authorization object as it appears on the wire
// (RFC 8555 section 7.1.4).
type AuthorizationResource struct {
	Status     string              `json:"status"`
	Expires    string              `json:"expires,omitempty"`
	Identifier Identifier          `json:"identifier"`
	Challenges []ChallengeResource `json:"challenges"`
}

// ChallengeResource is the challenge object as it appears on the wire (RFC
// 8555 section 8).
type ChallengeResource struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Status    string   `json:"status"`
	Token     string   `json:"token"`
	Validated string   `json:"validated,omitempty"`
	Error     *Problem `json:"error,omitempty"`
}

// revokeCertRequest is the RFC 8555 section 7.6 revoke-cert payload: the
// base64url DER certificate and an optional RFC 5280 reason code.
type revokeCertRequest struct {
	Certificate string `json:"certificate"`
	Reason      *int   `json:"reason,omitempty"`
}

// Problem is an RFC 7807 problem document carrying an RFC 8555 section 6.7
// error type. It doubles as the error value passed around inside the package,
// so a handler can return one error and the transport layer knows exactly what
// status and body to emit.
type Problem struct {
	Type        string      `json:"type"`
	Detail      string      `json:"detail,omitempty"`
	Status      int         `json:"status,omitempty"`
	Identifier  *Identifier `json:"identifier,omitempty"`
	Subproblems []Problem   `json:"subproblems,omitempty"`
}

// Error implements error so a Problem can be returned from the internal
// handler functions and rendered by one shared writer.
func (p *Problem) Error() string {
	if p.Detail == "" {
		return p.Type
	}
	return fmt.Sprintf("%s: %s", p.Type, p.Detail)
}

// ACME error type URNs (RFC 8555 section 6.7).
const (
	ErrAccountDoesNotExist     = "urn:ietf:params:acme:error:accountDoesNotExist"
	ErrAlreadyRevoked          = "urn:ietf:params:acme:error:alreadyRevoked"
	ErrBadCSR                  = "urn:ietf:params:acme:error:badCSR"
	ErrBadNonce                = "urn:ietf:params:acme:error:badNonce"
	ErrBadPublicKey            = "urn:ietf:params:acme:error:badPublicKey"
	ErrBadRevocationReason     = "urn:ietf:params:acme:error:badRevocationReason"
	ErrBadSignatureAlgorithm   = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	ErrConnection              = "urn:ietf:params:acme:error:connection"
	ErrExternalAccountRequired = "urn:ietf:params:acme:error:externalAccountRequired"
	ErrIncorrectResponse       = "urn:ietf:params:acme:error:incorrectResponse"
	ErrMalformed               = "urn:ietf:params:acme:error:malformed"
	ErrOrderNotReady           = "urn:ietf:params:acme:error:orderNotReady"
	ErrRejectedIdentifier      = "urn:ietf:params:acme:error:rejectedIdentifier"
	ErrServerInternal          = "urn:ietf:params:acme:error:serverInternal"
	ErrUnauthorized            = "urn:ietf:params:acme:error:unauthorized"
	ErrUnsupportedIdentifier   = "urn:ietf:params:acme:error:unsupportedIdentifier"
	ErrUserActionRequired      = "urn:ietf:params:acme:error:userActionRequired"
)

// problemf builds a Problem with a formatted detail.
func problemf(typ string, status int, format string, args ...any) *Problem {
	return &Problem{Type: typ, Status: status, Detail: fmt.Sprintf(format, args...)}
}

// malformed is the catch-all client error: the request did not parse or did
// not satisfy a structural requirement.
func malformed(format string, args ...any) *Problem {
	return problemf(ErrMalformed, http.StatusBadRequest, format, args...)
}

// unauthorized marks a request whose signer is not entitled to the resource.
func unauthorized(format string, args ...any) *Problem {
	return problemf(ErrUnauthorized, http.StatusForbidden, format, args...)
}

// serverInternal wraps a failure on our side. The detail is deliberately
// coarse: the underlying error is logged, not returned to an anonymous caller.
func serverInternal(format string, args ...any) *Problem {
	return problemf(ErrServerInternal, http.StatusInternalServerError, format, args...)
}

// rfc3339 renders t for a wire field, returning "" for the zero time so the
// omitempty tags drop the field entirely.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
