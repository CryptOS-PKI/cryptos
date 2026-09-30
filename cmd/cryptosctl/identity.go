package main

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
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func newIdentityCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Inspect and validate the node's CA identity",
	}
	cmd.AddCommand(newIdentityShowCmd(opts), newIdentityValidateCmd(opts))
	return cmd
}

func newIdentityShowCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the node's CA certificate chain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := fetchIdentity(cmd, opts)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			switch opts.output {
			case formatPEM:
				_, err := io.WriteString(w, id.ChainPem)
				return err
			case formatHuman:
				out, err := humanIdentity(id)
				if err != nil {
					return err
				}
				_, err = io.WriteString(w, out)
				return err
			default:
				return renderProto(w, id, opts.output)
			}
		},
	}
}

func newIdentityValidateCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate the node's CA certificate chain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := fetchIdentity(cmd, opts)
			if err != nil {
				return err
			}
			if err := validateChain(id); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "OK: certificate chain validates")
			return err
		},
	}
}

// fetchIdentity calls GetIdentity, mapping the FAILED_PRECONDITION
// no-identity case to a friendlier error.
func fetchIdentity(cmd *cobra.Command, opts *globalOpts) (*cryptosv1.Identity, error) {
	client, closeConn, err := dial(opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeConn() }()

	resp, err := client.GetIdentity(cmd.Context(), &cryptosv1.GetIdentityRequest{})
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return nil, errNoIdentity
		}
		return nil, err
	}
	return resp.Identity, nil
}

// validateChain verifies the identity's leaf-first DER chain. For a
// Phase 1 Root (chain length 1) it confirms the cert is a self-signed CA
// that verifies against itself.
func validateChain(id *cryptosv1.Identity) error {
	if id == nil || len(id.ChainDer) == 0 {
		return errors.New("identity has an empty certificate chain")
	}
	certs := make([]*x509.Certificate, 0, len(id.ChainDer))
	for i, der := range id.ChainDer {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse chain[%d]: %w", i, err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	// The last cert in the chain is the trust anchor (the Root itself for
	// a self-signed Phase 1 Root); middle certs are intermediates.
	roots.AddCert(certs[len(certs)-1])
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
		return fmt.Errorf("chain does not validate: %w", err)
	}
	return nil
}

// humanIdentity renders an Identity summary for human output.
func humanIdentity(id *cryptosv1.Identity) (string, error) {
	if id == nil || len(id.ChainDer) == 0 {
		return "(no identity)\n", nil
	}
	leaf, err := x509.ParseCertificate(id.ChainDer[0])
	if err != nil {
		return "", fmt.Errorf("parse leaf: %w", err)
	}
	return fmt.Sprintf(
		"Subject:      %s\nIssuer:       %s\nSerial:       %x\nNotBefore:    %s\nNotAfter:     %s\nIsCA:         %t\nSHA-256:      %s\nChain length: %d\n",
		leaf.Subject, leaf.Issuer, leaf.SerialNumber, leaf.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), leaf.IsCA, hex.EncodeToString(id.LeafSha256), len(id.ChainDer),
	), nil
}
