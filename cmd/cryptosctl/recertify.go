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
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// newGetRenewalCSRCmd fetches a CSR signed by an established subordinate's
// CURRENT CA key, with the subject of its current CA certificate, so the parent
// can re-certify the same key (child side). Nothing is staged on the node. The
// printed CSR is ferried to the parent's sign-subordinate, then handed back with
// submit-renewed-cert. Requires admin authorization on the node.
func newGetRenewalCSRCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "get-renewal-csr",
		Short: "Fetch a CSR for this node's current CA key, to re-certify it without re-keying (child)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.GetRenewalCSR(cmd.Context(), &cryptosv1.GetRenewalCSRRequest{})
			if err != nil {
				return err
			}
			return writePEMBlock(cmd.OutOrStdout(), "CERTIFICATE REQUEST", resp.GetCsrDer())
		},
	}
}

// newSubmitRenewedCertCmd hands the parent-signed chain for the node's current
// key back to the child, which verifies it (pinned parent anchor, same key,
// subject and SKI, CA constraints) and replaces its CA certificate without a
// reboot (child side). Requires admin authorization on the node.
func newSubmitRenewedCertCmd(opts *globalOpts) *cobra.Command {
	var chainFile string
	cmd := &cobra.Command{
		Use:   "submit-renewed-cert",
		Short: "Submit the parent-signed chain that re-certifies this node's current CA key (child)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if chainFile == "" {
				return errors.New("--chain is required")
			}
			raw, err := os.ReadFile(chainFile)
			if err != nil {
				return fmt.Errorf("read chain: %w", err)
			}
			chainDER, err := chainToDER(raw)
			if err != nil {
				return fmt.Errorf("parse chain: %w", err)
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.SubmitRenewedCertificate(cmd.Context(), &cryptosv1.SubmitRenewedCertificateRequest{
				ChainDer: chainDER,
			})
			if err != nil {
				return err
			}
			return writeIdentity(cmd.OutOrStdout(), resp.GetIdentity(), opts.output)
		},
	}
	cmd.Flags().StringVar(&chainFile, "chain", "", "parent-signed leaf-first chain file for the current key (PEM, required)")
	return cmd
}
