//go:build debug_signcsr

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
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// addDebugCommands wires the debug-only sign subcommand into the tree.
func addDebugCommands(root *cobra.Command, opts *globalOpts) {
	sign := &cobra.Command{
		Use:   "sign",
		Short: "Debug-only signing helpers (compiled with -tags=debug_signcsr)",
	}
	sign.AddCommand(newSignCSRCmd(opts))
	root.AddCommand(sign)
}

func newSignCSRCmd(opts *globalOpts) *cobra.Command {
	var (
		file    string
		profile string
	)
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Sign a PKCS#10 CSR with the Root CA key (debug only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return errors.New("-f/--file is required")
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read csr: %w", err)
			}
			der := raw
			if block, _ := pem.Decode(raw); block != nil {
				der = block.Bytes
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.SignCSR(cmd.Context(), &cryptosv1.SignCSRRequest{CsrDer: der, Profile: profile})
			if err != nil {
				return err
			}
			return pem.Encode(cmd.OutOrStdout(), &pem.Block{Type: "CERTIFICATE", Bytes: resp.CertDer})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "PKCS#10 CSR file (PEM or DER, required)")
	cmd.Flags().StringVar(&profile, "profile", "", "issuance profile")
	return cmd
}
