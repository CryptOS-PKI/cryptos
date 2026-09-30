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

// newRotateKeyCmd begins a CA key rotation on an established subordinate: the
// node generates a new CA key and stages its CSR while it keeps serving with
// its current key. The printed CSR is ferried to the parent's sign-subordinate,
// then handed back with submit-rotation. Requires admin authorization on the
// node.
func newRotateKeyCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-key",
		Short: "Begin a CA key rotation and print the new CSR (child)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.BeginKeyRotation(cmd.Context(), &cryptosv1.BeginKeyRotationRequest{})
			if err != nil {
				return err
			}
			return writePEMBlock(cmd.OutOrStdout(), "CERTIFICATE REQUEST", resp.GetCsrDer())
		},
	}
}

// newSubmitRotationCmd hands the parent-signed chain for the rotated key back to
// the child node, which verifies it against its pinned parent anchor and the
// staged rotation key, then atomically swaps to it (child side). Requires admin
// authorization on the node.
func newSubmitRotationCmd(opts *globalOpts) *cobra.Command {
	var chainFile string
	cmd := &cobra.Command{
		Use:   "submit-rotation",
		Short: "Submit the parent-signed chain for the rotated key to this node (child)",
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

			resp, err := client.CompleteKeyRotation(cmd.Context(), &cryptosv1.CompleteKeyRotationRequest{
				ChainDer: chainDER,
			})
			if err != nil {
				return err
			}
			return writeIdentity(cmd.OutOrStdout(), resp.GetIdentity(), opts.output)
		},
	}
	cmd.Flags().StringVar(&chainFile, "chain", "", "parent-signed leaf-first chain file for the rotated key (PEM, required)")
	return cmd
}
