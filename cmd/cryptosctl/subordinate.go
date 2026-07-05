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
	"io"
	"os"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// newCACmd groups the subordinate-enrollment ferry verbs that move a CSR
// from a child node to its parent for signing and the resulting chain
// back to the child.
func newCACmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Subordinate-CA enrollment (CSR ferry)",
	}
	cmd.AddCommand(
		newGetSubordinateCSRCmd(opts),
		newSignSubordinateCmd(opts),
		newSubmitSubordinateCertCmd(opts),
	)
	return cmd
}

// newGetSubordinateCSRCmd fetches the child node's pending subordinate CSR
// (child side). The node must be awaiting a certificate.
func newGetSubordinateCSRCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "get-subordinate-csr",
		Short: "Fetch this node's pending subordinate-CA CSR (child)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.GetSubordinateCSR(cmd.Context(), &cryptosv1.GetSubordinateCSRRequest{})
			if err != nil {
				return err
			}
			return writePEMBlock(cmd.OutOrStdout(), "CERTIFICATE REQUEST", resp.GetCsrDer())
		},
	}
}

// newSignSubordinateCmd hands a child CSR to this (parent) node's CA to be
// signed under a profile, printing the returned leaf-first chain as PEM
// (parent side).
func newSignSubordinateCmd(opts *globalOpts) *cobra.Command {
	var (
		csrFile string
		profile string
	)
	cmd := &cobra.Command{
		Use:   "sign-subordinate",
		Short: "Sign a child subordinate-CA CSR under a profile (parent)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if csrFile == "" {
				return errors.New("--csr is required")
			}
			if profile == "" {
				return errors.New("--profile is required")
			}
			csrDER, err := readCertDER(csrFile, "CERTIFICATE REQUEST")
			if err != nil {
				return fmt.Errorf("read csr: %w", err)
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.SignSubordinateCSR(cmd.Context(), &cryptosv1.SignSubordinateCSRRequest{
				CsrDer:      csrDER,
				ProfileName: profile,
			})
			if err != nil {
				return err
			}
			return writeChainPEM(cmd.OutOrStdout(), resp.GetChainPem(), resp.GetChainDer())
		},
	}
	cmd.Flags().StringVar(&csrFile, "csr", "", "child subordinate-CA CSR file (PEM or DER, required)")
	cmd.Flags().StringVar(&profile, "profile", "", "issuance profile (required)")
	return cmd
}

// newSubmitSubordinateCertCmd hands the parent-signed chain back to the
// child node, which verifies it against its pinned parent anchor and
// commits (child side). Requires admin authorization on the node.
func newSubmitSubordinateCertCmd(opts *globalOpts) *cobra.Command {
	var chainFile string
	cmd := &cobra.Command{
		Use:   "submit-subordinate-cert",
		Short: "Submit the parent-signed chain to this node (child)",
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

			resp, err := client.SubmitSubordinateCertificate(cmd.Context(), &cryptosv1.SubmitSubordinateCertificateRequest{
				ChainDer: chainDER,
			})
			if err != nil {
				return err
			}
			return writeIdentity(cmd.OutOrStdout(), resp.GetIdentity(), opts.output)
		},
	}
	cmd.Flags().StringVar(&chainFile, "chain", "", "parent-signed leaf-first chain file (PEM, required)")
	return cmd
}

// writePEMBlock encodes der under blockType as a single PEM block.
func writePEMBlock(w io.Writer, blockType string, der []byte) error {
	if len(der) == 0 {
		return fmt.Errorf("node returned an empty %s", blockType)
	}
	return pem.Encode(w, &pem.Block{Type: blockType, Bytes: der})
}

// readCertDER reads a PEM- or DER-encoded object of the given block type
// from path, returning its DER bytes. A PEM file's first matching block is
// used; a file with no PEM block is treated as raw DER.
func readCertDER(path, blockType string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rest := raw
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == blockType {
			return block.Bytes, nil
		}
		rest = next
	}
	return raw, nil
}

// writeChainPEM prints the leaf-first chain. It prefers the server-provided
// PEM when present; otherwise it encodes the DER certificates itself.
func writeChainPEM(w io.Writer, chainPEM string, chainDER [][]byte) error {
	if chainPEM != "" {
		_, err := io.WriteString(w, chainPEM)
		return err
	}
	if len(chainDER) == 0 {
		return errors.New("node returned an empty certificate chain")
	}
	for _, der := range chainDER {
		if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	return nil
}

// chainToDER decodes a PEM chain into a leaf-first list of DER certificates.
// A file that carries no PEM block is treated as a single DER certificate.
func chainToDER(raw []byte) ([][]byte, error) {
	var chain [][]byte
	rest := raw
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
		rest = next
	}
	if len(chain) == 0 {
		if len(raw) == 0 {
			return nil, errors.New("chain file is empty")
		}
		return [][]byte{raw}, nil
	}
	return chain, nil
}

// writeIdentity renders the committed identity per the output format.
func writeIdentity(w io.Writer, id *cryptosv1.Identity, format string) error {
	switch format {
	case formatPEM:
		if id == nil {
			return errors.New("node returned no identity")
		}
		_, err := io.WriteString(w, id.GetChainPem())
		return err
	case formatHuman:
		out, err := humanIdentity(id)
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, out)
		return err
	default:
		return renderProto(w, id, format)
	}
}
