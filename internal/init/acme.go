package init

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
	"fmt"
	"log"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/acme"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
)

// defaultACMEHTTPPort is the port the ACME listener binds when the config
// leaves it at zero. It is not 80: that belongs to the CRL/OCSP listener,
// which must stay on the port a CDP URL points at. ACME is normally reached
// through a TLS front end, so a high port is the sane default for the
// origin behind it.
const defaultACMEHTTPPort = 8555

// acmeIssuer returns the acme.IssueFunc backed by this node's CA signer.
//
// It routes through IssueLeafForNames so the certificate's SANs are the
// identifiers the client actually proved control of, while every other
// extension still comes from the named profile. IssueLeafForNames also runs
// the issued-certificate recorder, so an ACME-issued certificate is revocable
// and lands on the CRL exactly like an operator-ferried one.
func acmeIssuer(signer *node.CASigner, profileName string) acme.IssueFunc {
	return func(ctx context.Context, csrDER []byte, dnsNames []string) (string, string, error) {
		chainDER, chainPEM, err := signer.IssueLeafForNames(ctx, csrDER, profileName, dnsNames)
		if err != nil {
			return "", "", err
		}
		leaf, err := x509.ParseCertificate(chainDER[0])
		if err != nil {
			return "", "", fmt.Errorf("init: parse the certificate this node just issued: %w", err)
		}
		// Text(16) is the serial encoding the revocation store keys on.
		return chainPEM, leaf.SerialNumber.Text(16), nil
	}
}

// acmeRevoker returns the acme.RevokeFunc backed by the node's revocation
// engine. The store's Revoke is idempotent, which is right for the gRPC path
// but wrong for ACME: RFC 8555 section 7.6 wants a distinct alreadyRevoked
// answer, so the revoked set is consulted first.
func acmeRevoker(r *nodeRevoker) acme.RevokeFunc {
	return func(ctx context.Context, serialHex string, reason int) error {
		_, revoked, err := r.store.GetRevoked(ctx, serialHex)
		if err != nil {
			return err
		}
		if revoked {
			return acme.ErrCertificateAlreadyRevoked
		}
		if _, err := r.Revoke(ctx, serialHex, reason); err != nil {
			return err
		}
		return nil
	}
}

// acmeOptions maps the validated node config onto acme.Options. The config
// layer has already checked the base URL, the profile and the binding keys,
// so a failure here is a decode of something validateACME accepted.
func acmeOptions(c *config.ACME) (acme.Options, error) {
	opts := acme.Options{
		BaseURL:         c.BaseURL,
		TermsOfService:  c.TermsOfService,
		Website:         c.Website,
		AllowedSuffixes: c.AllowedIdentifierSuffixes,
		OrderTTL:        time.Duration(c.OrderTTLHours) * time.Hour,
		Logf:            log.Printf,
		// The config knob is the permissive one, so the requirement is its
		// negation: leaving allow_anonymous_accounts alone demands a binding.
		ExternalAccountRequired: !c.AllowAnonymousAccounts,
	}
	if !opts.ExternalAccountRequired {
		return opts, nil
	}
	keys := make(map[string][]byte, len(c.ExternalAccountKeys))
	for _, k := range c.ExternalAccountKeys {
		raw, err := base64.RawURLEncoding.DecodeString(k.HMACKeyBase64)
		if err != nil {
			return acme.Options{}, fmt.Errorf("init: decode external account key %q: %w", k.KeyID, err)
		}
		keys[k.KeyID] = raw
	}
	opts.EABKey = acme.StaticEABKeys(keys)
	return opts, nil
}
