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
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrInvalidContact is the RFC 8555 section 6.7 error for a contact URL the
// server will not accept.
const ErrInvalidContact = "urn:ietf:params:acme:error:invalidContact"

// allowedRevocationReasons is the RFC 5280 reason-code set a client may ask
// for. cACompromise (2) is not a client's call, certificateHold (6) and
// removeFromCRL (8) imply a hold workflow this CA does not implement, and
// aACompromise (10) has no meaning here.
var allowedRevocationReasons = map[int]bool{
	0: true, // unspecified
	1: true, // keyCompromise
	3: true, // affiliationChanged
	4: true, // superseded
	5: true, // cessationOfOperation
	9: true, // privilegeWithdrawn
}

func (h *Handler) now() time.Time { return h.opts.Now().UTC().Truncate(time.Second) }

// handleDirectory serves the RFC 8555 section 7.1.1 directory. It is the only
// unsigned endpoint that returns a body, and it is what a client fetches
// first, so it is deliberately free of any state lookup.
func (h *Handler) handleDirectory(w http.ResponseWriter, _ *http.Request) error {
	dir := Directory{
		NewNonce:   h.url(pathNewNonce),
		NewAccount: h.url(pathNewAccount),
		NewOrder:   h.url(pathNewOrder),
	}
	if h.revoke != nil {
		dir.RevokeCert = h.url(pathRevokeCert)
	}
	if h.opts.TermsOfService != "" || h.opts.Website != "" || h.opts.ExternalAccountRequired {
		dir.Meta = &DirectoryMeta{
			TermsOfService:          h.opts.TermsOfService,
			Website:                 h.opts.Website,
			ExternalAccountRequired: h.opts.ExternalAccountRequired,
		}
	}
	return writeJSON(w, http.StatusOK, dir)
}

// handleNewNonce answers the nonce endpoint. The nonce itself is already in
// the Replay-Nonce header, stamped by wrap for every response; this endpoint
// exists so a client can obtain one without a side effect. RFC 8555 section
// 7.2 fixes the status: 200 for HEAD, 204 for GET.
func (h *Handler) handleNewNonce(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return nil
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleNewAccount implements RFC 8555 section 7.3. A repeat registration
// with a key that is already on file returns the existing account with 200
// rather than minting a second one, which is what makes the endpoint safe for
// a client to call on every run.
func (h *Handler) handleNewAccount(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authEmbeddedKey)
	if err != nil {
		return err
	}
	var body newAccountRequest
	if err := unmarshalPayload(req, &body); err != nil {
		return err
	}

	existing, err := h.store.AccountByThumbprint(r.Context(), req.thumbprint)
	switch {
	case err == nil:
		w.Header().Set("Location", h.url(pathAccount+existing.ID))
		return writeJSON(w, http.StatusOK, h.accountResource(existing))
	case !errors.Is(err, ErrNotFound):
		h.opts.Logf("acme: account lookup by thumbprint failed: %v", err)
		return serverInternal("the server could not look up the account")
	}

	if body.OnlyReturnExisting {
		return problemf(ErrAccountDoesNotExist, http.StatusBadRequest,
			"no account is registered for this key")
	}
	if h.opts.TermsOfService != "" && !body.TermsOfServiceAgreed {
		return problemf(ErrUserActionRequired, http.StatusForbidden,
			"the terms of service at %s must be agreed to", h.opts.TermsOfService)
	}
	if err := validateContacts(body.Contact); err != nil {
		return err
	}

	var eabKeyID string
	if h.opts.ExternalAccountRequired {
		eabKeyID, err = verifyExternalAccountBinding(body.ExternalAccountBinding, req.hdr.URL, req.jwk, h.opts.EABKey)
		if err != nil {
			return err
		}
	}

	id, err := NewID()
	if err != nil {
		h.opts.Logf("acme: minting an account id failed: %v", err)
		return serverInternal("the server could not create the account")
	}
	acct := Account{
		ID:            id,
		Status:        StatusValid,
		Contact:       body.Contact,
		KeyThumbprint: req.thumbprint,
		Key:           *req.jwk,
		EABKeyID:      eabKeyID,
		CreatedAt:     h.now(),
	}
	if err := h.store.PutAccount(r.Context(), acct); err != nil {
		h.opts.Logf("acme: storing account %s failed: %v", id, err)
		return serverInternal("the server could not create the account")
	}
	w.Header().Set("Location", h.url(pathAccount+id))
	return writeJSON(w, http.StatusCreated, h.accountResource(acct))
}

// handleAccount serves and updates an account (RFC 8555 section 7.3.2). Only
// the contact list is mutable; deactivation is not implemented, so a status
// change is refused rather than accepted and ignored.
func (h *Handler) handleAccount(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authAccount)
	if err != nil {
		return err
	}
	if id := r.PathValue("id"); id != req.account.ID {
		return unauthorized("the signing account may not act on account %s", id)
	}
	if req.postAsGet() {
		return writeJSON(w, http.StatusOK, h.accountResource(*req.account))
	}

	var body updateAccountRequest
	if err := unmarshalPayload(req, &body); err != nil {
		return err
	}
	if body.Status != "" && body.Status != StatusValid {
		return malformed("this server does not support changing an account status to %q", body.Status)
	}
	if body.Contact != nil {
		if err := validateContacts(body.Contact); err != nil {
			return err
		}
		acct := *req.account
		acct.Contact = body.Contact
		if err := h.store.PutAccount(r.Context(), acct); err != nil {
			h.opts.Logf("acme: updating account %s failed: %v", acct.ID, err)
			return serverInternal("the server could not update the account")
		}
		return writeJSON(w, http.StatusOK, h.accountResource(acct))
	}
	return writeJSON(w, http.StatusOK, h.accountResource(*req.account))
}

// handleOrdersList serves the RFC 8555 section 7.1.2.1 orders list.
func (h *Handler) handleOrdersList(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authAccount)
	if err != nil {
		return err
	}
	if id := r.PathValue("id"); id != req.account.ID {
		return unauthorized("the signing account may not list orders for account %s", id)
	}
	ids, err := h.store.ListOrderIDs(r.Context(), req.account.ID)
	if err != nil {
		h.opts.Logf("acme: listing orders for %s failed: %v", req.account.ID, err)
		return serverInternal("the server could not list the orders")
	}
	urls := make([]string, 0, len(ids))
	for _, id := range ids {
		urls = append(urls, h.url(pathOrder+id))
	}
	return writeJSON(w, http.StatusOK, OrdersList{Orders: urls})
}

// handleNewOrder implements RFC 8555 section 7.4. Every order gets a fresh
// authorization per identifier: this server does not reuse a valid
// authorization across orders, so an authorization never outlives the order
// that justified it.
func (h *Handler) handleNewOrder(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authAccount)
	if err != nil {
		return err
	}
	var body newOrderRequest
	if err := unmarshalPayload(req, &body); err != nil {
		return err
	}
	// notBefore/notAfter would put the validity window under client control,
	// but the configured profile owns it. Refusing is honest; accepting and
	// ignoring would hand back a certificate that silently contradicts the
	// request.
	if body.NotBefore != "" || body.NotAfter != "" {
		return malformed("this server does not accept notBefore or notAfter; the certificate profile sets the validity window")
	}

	idents, err := h.normalizeIdentifiers(body.Identifiers)
	if err != nil {
		return err
	}

	now := h.now()
	expires := now.Add(h.opts.OrderTTL)
	orderID, err := NewID()
	if err != nil {
		h.opts.Logf("acme: minting an order id failed: %v", err)
		return serverInternal("the server could not create the order")
	}

	authzIDs := make([]string, 0, len(idents))
	authzs := make([]Authorization, 0, len(idents))
	for _, ident := range idents {
		authzID, aerr := NewID()
		if aerr != nil {
			h.opts.Logf("acme: minting an authorization id failed: %v", aerr)
			return serverInternal("the server could not create the order")
		}
		token, terr := NewToken()
		if terr != nil {
			h.opts.Logf("acme: minting a challenge token failed: %v", terr)
			return serverInternal("the server could not create the order")
		}
		authzs = append(authzs, Authorization{
			ID:              authzID,
			AccountID:       req.account.ID,
			OrderID:         orderID,
			Status:          StatusPending,
			Expires:         expires,
			Identifier:      ident,
			Token:           token,
			ChallengeStatus: StatusPending,
		})
		authzIDs = append(authzIDs, authzID)
	}

	// Authorizations are written first: an order that points at a missing
	// authorization is unusable, whereas an orphaned authorization is inert
	// and expires on its own.
	for _, a := range authzs {
		if err := h.store.PutAuthorization(r.Context(), a); err != nil {
			h.opts.Logf("acme: storing authorization %s failed: %v", a.ID, err)
			return serverInternal("the server could not create the order")
		}
	}

	order := Order{
		ID:          orderID,
		AccountID:   req.account.ID,
		Status:      StatusPending,
		Expires:     expires,
		Identifiers: idents,
		AuthzIDs:    authzIDs,
	}
	if err := h.store.PutOrder(r.Context(), order); err != nil {
		h.opts.Logf("acme: storing order %s failed: %v", orderID, err)
		return serverInternal("the server could not create the order")
	}

	w.Header().Set("Location", h.url(pathOrder+orderID))
	return writeJSON(w, http.StatusCreated, h.orderResource(order))
}

// handleOrder serves an order (POST-as-GET), refreshing its derived status
// first so a client polling after a challenge sees "ready".
func (h *Handler) handleOrder(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authAccount)
	if err != nil {
		return err
	}
	order, err := h.loadOrder(r.Context(), r.PathValue("id"), req.account.ID)
	if err != nil {
		return err
	}
	order, err = h.refreshOrder(r.Context(), order)
	if err != nil {
		return err
	}
	w.Header().Set("Location", h.url(pathOrder+order.ID))
	return writeJSON(w, http.StatusOK, h.orderResource(order))
}

// handleAuthz serves an authorization (POST-as-GET).
func (h *Handler) handleAuthz(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authAccount)
	if err != nil {
		return err
	}
	authz, err := h.loadAuthz(r.Context(), r.PathValue("id"), req.account.ID)
	if err != nil {
		return err
	}
	if authz.Status == StatusPending && h.now().After(authz.Expires) {
		authz.Status = StatusExpired
	}
	return writeJSON(w, http.StatusOK, h.authzResource(authz))
}

// handleChallenge triggers and reports an http-01 validation (RFC 8555
// section 7.5.1).
//
// Validation runs inline rather than on a worker: RFC 8555 lets a server
// answer "processing" and validate in the background, but doing it here means
// the client's first poll already carries the answer, there is no queue to
// drain on restart, and a test can drive the whole flow deterministically.
// The cost is that this request blocks for as long as the validator's
// timeout.
func (h *Handler) handleChallenge(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authAccount)
	if err != nil {
		return err
	}
	if typ := r.PathValue("type"); typ != ChallengeTypeHTTP01 {
		return malformed("this server offers only the %s challenge, not %q", ChallengeTypeHTTP01, typ)
	}
	authz, err := h.loadAuthz(r.Context(), r.PathValue("id"), req.account.ID)
	if err != nil {
		return err
	}

	w.Header().Add("Link", `<`+h.url(pathAuthz+authz.ID)+`>;rel="up"`)

	// Re-triggering a settled challenge is a no-op: a client that retries
	// after a timeout must not be able to re-run a validation that already
	// succeeded, nor to retry one that failed without a new order.
	if authz.Status != StatusPending {
		return writeJSON(w, http.StatusOK, h.challengeResource(authz))
	}
	if h.now().After(authz.Expires) {
		authz.Status = StatusExpired
		return writeJSON(w, http.StatusOK, h.challengeResource(authz))
	}

	keyAuth := KeyAuthorization(authz.Token, req.account.KeyThumbprint)
	verr := h.validate(r.Context(), authz.Identifier.Value, authz.Token, keyAuth)
	if verr != nil {
		var prob *Problem
		if !errors.As(verr, &prob) {
			h.opts.Logf("acme: validating %s: %v", authz.Identifier.Value, verr)
			prob = problemf(ErrIncorrectResponse, http.StatusForbidden, "validation failed")
		}
		prob.Identifier = &authz.Identifier
		h.opts.Logf("acme: http-01 validation of %s failed: %s", authz.Identifier.Value, prob.Detail)
		authz.Status = StatusInvalid
		authz.ChallengeStatus = StatusInvalid
		authz.Error = prob
	} else {
		authz.Status = StatusValid
		authz.ChallengeStatus = StatusValid
		authz.Validated = h.now()
	}
	if err := h.store.PutAuthorization(r.Context(), authz); err != nil {
		h.opts.Logf("acme: storing authorization %s failed: %v", authz.ID, err)
		return serverInternal("the server could not record the validation result")
	}

	// Roll the order forward so the client's next poll is authoritative.
	if order, oerr := h.store.GetOrder(r.Context(), authz.OrderID); oerr == nil {
		if _, rerr := h.refreshOrder(r.Context(), order); rerr != nil {
			h.opts.Logf("acme: refreshing order %s after validation: %v", order.ID, rerr)
		}
	}
	return writeJSON(w, http.StatusOK, h.challengeResource(authz))
}

// handleFinalize implements RFC 8555 section 7.4 finalize: it checks the CSR
// against the authorized identifiers and issues.
func (h *Handler) handleFinalize(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authAccount)
	if err != nil {
		return err
	}
	order, err := h.loadOrder(r.Context(), r.PathValue("id"), req.account.ID)
	if err != nil {
		return err
	}
	order, err = h.refreshOrder(r.Context(), order)
	if err != nil {
		return err
	}
	w.Header().Set("Location", h.url(pathOrder+order.ID))

	if order.Status != StatusReady {
		return problemf(ErrOrderNotReady, http.StatusForbidden,
			"order %s is %s, and only a ready order can be finalized", order.ID, order.Status)
	}

	var body finalizeRequest
	if err := unmarshalPayload(req, &body); err != nil {
		return err
	}
	csrDER, derr := b64.DecodeString(body.CSR)
	if derr != nil {
		return problemf(ErrBadCSR, http.StatusBadRequest, "the csr field is not valid base64url: %v", derr)
	}
	if cerr := validateFinalizeCSR(csrDER, order.Identifiers); cerr != nil {
		return cerr
	}

	// Claim the order before issuing. Two clients racing to finalize, or one
	// client retrying after a timeout, would otherwise both see "ready" and
	// both be issued a certificate for the same order. The compare-and-swap
	// to "processing" lets exactly one through; the loser is told the order
	// is no longer ready.
	claimed, err := h.claimOrderForIssuance(r.Context(), order.ID)
	if err != nil {
		return err
	}
	if !claimed {
		return problemf(ErrOrderNotReady, http.StatusForbidden,
			"order %s is already being finalized", order.ID)
	}
	order.Status = StatusProcessing

	names := make([]string, 0, len(order.Identifiers))
	for _, ident := range order.Identifiers {
		names = append(names, ident.Value)
	}

	chainPEM, serialHex, ierr := h.issue(r.Context(), csrDER, names)
	if ierr != nil {
		h.opts.Logf("acme: issuing for order %s failed: %v", order.ID, ierr)
		prob := problemf(ErrBadCSR, http.StatusBadRequest, "the certificate authority refused the request: %v", ierr)
		order.Status = StatusInvalid
		order.Error = prob
		if perr := h.store.PutOrder(r.Context(), order); perr != nil {
			h.opts.Logf("acme: storing failed order %s: %v", order.ID, perr)
		}
		return prob
	}

	certID, err := NewID()
	if err != nil {
		h.opts.Logf("acme: minting a certificate id failed: %v", err)
		return serverInternal("the server could not record the issued certificate")
	}
	rec := CertificateRecord{
		ID:        certID,
		AccountID: req.account.ID,
		OrderID:   order.ID,
		SerialHex: serialHex,
		ChainPEM:  chainPEM,
		IssuedAt:  h.now(),
	}
	if err := h.store.PutCertificate(r.Context(), rec); err != nil {
		h.opts.Logf("acme: storing certificate %s failed: %v", certID, err)
		return serverInternal("the server could not record the issued certificate")
	}

	order.Status = StatusValid
	order.CertID = certID
	if err := h.store.PutOrder(r.Context(), order); err != nil {
		h.opts.Logf("acme: storing finalized order %s failed: %v", order.ID, err)
		return serverInternal("the server could not record the finalized order")
	}
	return writeJSON(w, http.StatusOK, h.orderResource(order))
}

// handleCert serves an issued chain (POST-as-GET, RFC 8555 section 7.4.2).
func (h *Handler) handleCert(w http.ResponseWriter, r *http.Request) error {
	req, err := h.authenticate(r, authAccount)
	if err != nil {
		return err
	}
	rec, gerr := h.store.GetCertificate(r.Context(), r.PathValue("id"))
	if errors.Is(gerr, ErrNotFound) {
		return unauthorized("no such certificate")
	}
	if gerr != nil {
		h.opts.Logf("acme: loading certificate failed: %v", gerr)
		return serverInternal("the server could not load the certificate")
	}
	if rec.AccountID != req.account.ID {
		// Deliberately the same answer a missing certificate gets.
		return unauthorized("no such certificate")
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(rec.ChainPEM))
	return nil
}

// handleRevokeCert implements RFC 8555 section 7.6. The request may be signed
// either by the account that ordered the certificate or by the certificate's
// own key, which is how a holder revokes after losing account access.
func (h *Handler) handleRevokeCert(w http.ResponseWriter, r *http.Request) error {
	if h.revoke == nil {
		return problemf(ErrServerInternal, http.StatusNotImplemented, "this server does not implement revocation over ACME")
	}
	req, err := h.authenticate(r, authEither)
	if err != nil {
		return err
	}
	var body revokeCertRequest
	if err := unmarshalPayload(req, &body); err != nil {
		return err
	}
	der, derr := b64.DecodeString(body.Certificate)
	if derr != nil {
		return malformed("the certificate field is not valid base64url: %v", derr)
	}
	cert, perr := x509.ParseCertificate(der)
	if perr != nil {
		return malformed("the certificate field is not a valid DER certificate: %v", perr)
	}
	reason := 0
	if body.Reason != nil {
		reason = *body.Reason
	}
	if !allowedRevocationReasons[reason] {
		return problemf(ErrBadRevocationReason, http.StatusBadRequest,
			"reason code %d is not accepted by this server", reason)
	}

	serialHex := cert.SerialNumber.Text(16)
	rec, gerr := h.store.CertificateBySerial(r.Context(), serialHex)
	if errors.Is(gerr, ErrNotFound) {
		return unauthorized("this certificate was not issued through ACME by this server")
	}
	if gerr != nil {
		h.opts.Logf("acme: certificate lookup by serial %s failed: %v", serialHex, gerr)
		return serverInternal("the server could not look up the certificate")
	}

	if err := h.authorizeRevocation(req, rec, cert); err != nil {
		return err
	}

	switch rerr := h.revoke(r.Context(), serialHex, reason); {
	case rerr == nil:
	case errors.Is(rerr, ErrCertificateAlreadyRevoked):
		return problemf(ErrAlreadyRevoked, http.StatusBadRequest, "this certificate is already revoked")
	default:
		h.opts.Logf("acme: revoking %s failed: %v", serialHex, rerr)
		return serverInternal("the server could not revoke the certificate")
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// authorizeRevocation checks that the JWS signer is entitled to revoke rec:
// either it is the account that ordered the certificate, or it holds the
// certificate's own key.
func (h *Handler) authorizeRevocation(req *signedRequest, rec CertificateRecord, cert *x509.Certificate) error {
	if req.account != nil {
		if rec.AccountID != req.account.ID {
			return unauthorized("this account did not order the certificate")
		}
		return nil
	}
	certJWK, err := JWKFromPublic(cert.PublicKey)
	if err != nil {
		return problemf(ErrBadPublicKey, http.StatusBadRequest, "unsupported certificate key type")
	}
	certThumb, err := certJWK.Thumbprint()
	if err != nil {
		return err
	}
	if certThumb != req.thumbprint {
		return unauthorized("the request is signed by neither the ordering account nor the certificate key")
	}
	return nil
}

// claimOrderForIssuance moves a ready order to processing under a
// compare-and-swap, and reports whether this caller won. A false return means
// another finalize got there first; an error means the store failed.
func (h *Handler) claimOrderForIssuance(ctx context.Context, orderID string) (bool, error) {
	current, rev, err := h.store.GetOrderRev(ctx, orderID)
	if err != nil {
		h.opts.Logf("acme: re-reading order %s to claim it failed: %v", orderID, err)
		return false, serverInternal("the server could not finalize the order")
	}
	if current.Status != StatusReady {
		return false, nil
	}
	current.Status = StatusProcessing
	ok, err := h.store.PutOrderIfUnchanged(ctx, current, rev)
	if err != nil {
		h.opts.Logf("acme: claiming order %s failed: %v", orderID, err)
		return false, serverInternal("the server could not finalize the order")
	}
	return ok, nil
}

// loadOrder fetches an order and checks it belongs to accountID. A mismatch
// gets the same answer as a missing order so an account cannot probe for
// another account's order IDs.
func (h *Handler) loadOrder(ctx context.Context, id, accountID string) (Order, error) {
	order, err := h.store.GetOrder(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Order{}, unauthorized("no such order")
	}
	if err != nil {
		h.opts.Logf("acme: loading order %s failed: %v", id, err)
		return Order{}, serverInternal("the server could not load the order")
	}
	if order.AccountID != accountID {
		return Order{}, unauthorized("no such order")
	}
	return order, nil
}

// loadAuthz fetches an authorization and checks it belongs to accountID.
func (h *Handler) loadAuthz(ctx context.Context, id, accountID string) (Authorization, error) {
	authz, err := h.store.GetAuthorization(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Authorization{}, unauthorized("no such authorization")
	}
	if err != nil {
		h.opts.Logf("acme: loading authorization %s failed: %v", id, err)
		return Authorization{}, serverInternal("the server could not load the authorization")
	}
	if authz.AccountID != accountID {
		return Authorization{}, unauthorized("no such authorization")
	}
	return authz, nil
}

// refreshOrder recomputes an order's derived status from its authorizations
// and persists any change. A pending order becomes ready once every
// authorization is valid, invalid as soon as one is invalid, and invalid once
// it expires.
//
// Three statuses are left alone. valid and invalid are terminal. processing
// is claimed: an in-flight finalize owns that order, and recomputing it back
// to ready would undo the compare-and-swap that stops a second finalize from
// issuing. A finalize that dies mid-issuance leaves the order processing
// until it expires, which is the safe direction to fail.
func (h *Handler) refreshOrder(ctx context.Context, order Order) (Order, error) {
	switch order.Status {
	case StatusValid, StatusInvalid, StatusProcessing:
		return order, nil
	}
	next := order.Status
	if h.now().After(order.Expires) {
		next = StatusInvalid
	} else {
		allValid := true
		for _, id := range order.AuthzIDs {
			authz, err := h.store.GetAuthorization(ctx, id)
			if err != nil {
				h.opts.Logf("acme: loading authorization %s for order %s failed: %v", id, order.ID, err)
				return Order{}, serverInternal("the server could not evaluate the order")
			}
			switch authz.Status {
			case StatusValid:
			case StatusInvalid, StatusExpired, StatusDeactivated, StatusRevoked:
				allValid = false
				next = StatusInvalid
			default:
				allValid = false
			}
			if next == StatusInvalid {
				break
			}
		}
		if allValid && next != StatusInvalid {
			next = StatusReady
		}
	}
	if next == order.Status {
		return order, nil
	}
	order.Status = next
	if err := h.store.PutOrder(ctx, order); err != nil {
		h.opts.Logf("acme: storing order %s failed: %v", order.ID, err)
		return Order{}, serverInternal("the server could not update the order")
	}
	return order, nil
}

// accountResource renders a stored account for the wire.
func (h *Handler) accountResource(a Account) AccountResource {
	return AccountResource{
		Status:  a.Status,
		Contact: a.Contact,
		Orders:  h.url(pathOrders + a.ID),
	}
}

// orderResource renders a stored order for the wire.
func (h *Handler) orderResource(o Order) OrderResource {
	authzURLs := make([]string, 0, len(o.AuthzIDs))
	for _, id := range o.AuthzIDs {
		authzURLs = append(authzURLs, h.url(pathAuthz+id))
	}
	res := OrderResource{
		Status:         o.Status,
		Expires:        rfc3339(o.Expires),
		Identifiers:    o.Identifiers,
		Error:          o.Error,
		Authorizations: authzURLs,
		Finalize:       h.url(pathOrder + o.ID + "/finalize"),
	}
	if o.CertID != "" {
		res.Certificate = h.url(pathCert + o.CertID)
	}
	return res
}

// authzResource renders a stored authorization for the wire.
func (h *Handler) authzResource(a Authorization) AuthorizationResource {
	return AuthorizationResource{
		Status:     a.Status,
		Expires:    rfc3339(a.Expires),
		Identifier: a.Identifier,
		Challenges: []ChallengeResource{h.challengeResource(a)},
	}
}

// challengeResource renders the single http-01 challenge of an authorization.
func (h *Handler) challengeResource(a Authorization) ChallengeResource {
	return ChallengeResource{
		Type:      ChallengeTypeHTTP01,
		URL:       h.url(pathChallenge + a.ID + "/" + ChallengeTypeHTTP01),
		Status:    a.ChallengeStatus,
		Token:     a.Token,
		Validated: rfc3339(a.Validated),
		Error:     a.Error,
	}
}

// normalizeIdentifiers validates, lowercases and de-duplicates the requested
// identifiers, preserving first-seen order so the SAN order is stable.
func (h *Handler) normalizeIdentifiers(in []Identifier) ([]Identifier, error) {
	if len(in) == 0 {
		return nil, malformed("an order must carry at least one identifier")
	}
	if len(in) > maxIdentifiersPerOrder {
		return nil, malformed("an order may carry at most %d identifiers, got %d", maxIdentifiersPerOrder, len(in))
	}
	seen := make(map[string]bool, len(in))
	out := make([]Identifier, 0, len(in))
	for _, ident := range in {
		if ident.Type != IdentifierTypeDNS {
			return nil, &Problem{
				Type:       ErrUnsupportedIdentifier,
				Status:     http.StatusBadRequest,
				Detail:     "this server issues for dns identifiers only, got " + ident.Type,
				Identifier: &Identifier{Type: ident.Type, Value: ident.Value},
			}
		}
		name := strings.ToLower(strings.TrimSuffix(ident.Value, "."))
		if err := validateDNSName(name); err != nil {
			return nil, err
		}
		if err := h.checkSuffixAllowed(name); err != nil {
			return nil, err
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, Identifier{Type: IdentifierTypeDNS, Value: name})
	}
	return out, nil
}

// checkSuffixAllowed enforces the operator's identifier allowlist. An empty
// allowlist permits any name: proof of control is then the only gate, which
// is the right default for a CA whose ACME endpoint is already behind an
// external account binding.
func (h *Handler) checkSuffixAllowed(name string) error {
	if len(h.opts.AllowedSuffixes) == 0 {
		return nil
	}
	for _, suffix := range h.opts.AllowedSuffixes {
		s := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(suffix, "."), "."))
		if name == s || strings.HasSuffix(name, "."+s) {
			return nil
		}
	}
	return &Problem{
		Type:       ErrRejectedIdentifier,
		Status:     http.StatusForbidden,
		Detail:     "this server does not issue for " + name,
		Identifier: &Identifier{Type: IdentifierTypeDNS, Value: name},
	}
}

// validateDNSName applies the preferred-name-syntax rules a certificate SAN
// must satisfy. Wildcards are refused outright: http-01 proves control of one
// name served over HTTP, which is not control of a whole label space.
func validateDNSName(name string) error {
	if name == "" {
		return malformed("an identifier value must not be empty")
	}
	if strings.HasPrefix(name, "*.") || strings.Contains(name, "*") {
		return &Problem{
			Type:       ErrRejectedIdentifier,
			Status:     http.StatusForbidden,
			Detail:     "wildcard identifiers need dns-01, which this server does not offer",
			Identifier: &Identifier{Type: IdentifierTypeDNS, Value: name},
		}
	}
	if len(name) > 253 {
		return malformed("identifier %q exceeds 253 characters", name)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return malformed("identifier %q is not a fully qualified domain name", name)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return malformed("identifier %q has an empty or over-long label", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return malformed("identifier %q has a label starting or ending with a hyphen", name)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' {
				return malformed("identifier %q contains a character that is not allowed in a hostname", name)
			}
		}
	}
	return nil
}

// validateContacts checks the contact list. Only mailto is accepted: it is
// the only scheme this server could act on, and accepting a scheme it will
// never use would be a silent no-op.
func validateContacts(contacts []string) error {
	for _, c := range contacts {
		u, err := url.Parse(c)
		if err != nil {
			return problemf(ErrInvalidContact, http.StatusBadRequest, "contact %q is not a valid URL", c)
		}
		if !strings.EqualFold(u.Scheme, "mailto") {
			return problemf(ErrInvalidContact, http.StatusBadRequest,
				"contact %q must use the mailto scheme", c)
		}
		addr := u.Opaque
		if addr == "" || !strings.Contains(addr, "@") || strings.Contains(addr, ",") {
			return problemf(ErrInvalidContact, http.StatusBadRequest,
				"contact %q must be a single mailto address", c)
		}
		if u.RawQuery != "" {
			return problemf(ErrInvalidContact, http.StatusBadRequest,
				"contact %q must not carry mailto header fields", c)
		}
	}
	return nil
}

// validateFinalizeCSR parses csrDER, verifies its self-signature, and checks
// that the names it requests are exactly the order's identifiers. The parsed
// request is discarded: the DER is what gets signed, so re-encoding it here
// would only invite a mismatch between what was checked and what was issued.
//
// RFC 8555 section 7.4 requires the CSR to indicate the same set of
// identifiers as the order. Checking set equality in both directions is the
// whole point: a subset would silently issue for less than the client asked
// for, and a superset would issue for a name nobody proved control of.
func validateFinalizeCSR(csrDER []byte, idents []Identifier) error {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return problemf(ErrBadCSR, http.StatusBadRequest, "the csr is not a valid PKCS#10 request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return problemf(ErrBadCSR, http.StatusBadRequest, "the csr signature does not verify: %v", err)
	}
	if len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return problemf(ErrBadCSR, http.StatusBadRequest,
			"the csr requests a non-DNS subject alternative name, which this server does not issue")
	}

	want := make(map[string]bool, len(idents))
	for _, ident := range idents {
		want[ident.Value] = true
	}
	got := make(map[string]bool, len(csr.DNSNames)+1)
	for _, n := range csr.DNSNames {
		got[strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}
	// A common name that duplicates a SAN is fine; one that does not is a
	// name the client never proved control of.
	if cn := strings.ToLower(strings.TrimSuffix(csr.Subject.CommonName, ".")); cn != "" {
		got[cn] = true
	}

	for name := range want {
		if !got[name] {
			return problemf(ErrBadCSR, http.StatusBadRequest,
				"the csr does not request the authorized identifier %q", name)
		}
	}
	for name := range got {
		if !want[name] {
			return problemf(ErrBadCSR, http.StatusBadRequest,
				"the csr requests %q, which is not an identifier of this order", name)
		}
	}
	return nil
}
