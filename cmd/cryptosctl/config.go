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
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

func newConfigCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage the node's declarative machine configuration",
	}
	cmd.AddCommand(newConfigApplyCmd(opts))
	return cmd
}

func newConfigApplyCmd(opts *globalOpts) *cobra.Command {
	var file string
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a machine configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return errors.New("-f/--file is required")
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read config: %w", err)
			}
			// Validate client-side so the operator gets a clear error
			// before the round-trip; the node re-validates authoritatively.
			cfg, err := config.Parse(raw)
			if err != nil {
				return err
			}

			// Enabling allow_unverified_revocation_url bypasses the fail-closed
			// revocation preflight, so the node will issue certs carrying a
			// CDP/AIA pointer that may never resolve. That is irreversible for
			// every cert issued while it is set, and on a Root for every sub-CA
			// it signs. Make it a deliberate, confirmed choice.
			if cfg.PKI.AllowUnverifiedRevocationURL {
				if err := confirmUnverifiedRevocation(cmd, cfg, assumeYes); err != nil {
					return err
				}
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.ApplyConfig(cmd.Context(), &cryptosv1.ApplyConfigRequest{Config: cfg.ToProto()})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"applied: generation=%d requires_reboot=%t digest=%s\n",
				resp.Generation, resp.RequiresReboot, hex.EncodeToString(resp.ConfigDigest))
			return err
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "machine config YAML to apply (required)")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "skip the interactive confirmation for allow_unverified_revocation_url (for automation)")
	return cmd
}

// confirmUnverifiedRevocation blocks an apply that enables
// allow_unverified_revocation_url behind a strong, irreversibility-focused
// confirmation. On a Root the operator must type the Root CA CN exactly (the
// stakes are highest there: every sub-CA the Root signs bakes in the
// unverified revocation URL permanently); on an intermediate/issuing node a
// plain "yes" suffices. assumeYes (--yes) skips the prompt for automation.
func confirmUnverifiedRevocation(cmd *cobra.Command, cfg *config.Config, assumeYes bool) error {
	out := cmd.OutOrStdout()
	isRoot := cfg.Role.Kind == config.RoleRoot

	var b strings.Builder
	b.WriteString("WARNING: allow_unverified_revocation_url is set.\n")
	b.WriteString("The node will issue certificates whose CRL/OCSP (CDP/AIA) pointer is NOT\n")
	b.WriteString("verified to resolve. Any certificate issued while this is set carries that\n")
	b.WriteString("pointer permanently -- this cannot be undone for already-issued certificates.\n")
	if isRoot {
		b.WriteString("This is a ROOT: every subordinate CA it signs inherits the unverified pointer,\n")
		b.WriteString("so a wrong or unreachable URL breaks revocation checking for the whole hierarchy\n")
		b.WriteString("and cannot be fixed without re-issuing every subordinate.\n")
	}
	if assumeYes {
		b.WriteString("--yes given: proceeding without confirmation.\n")
		if _, err := fmt.Fprint(out, b.String()); err != nil {
			return err
		}
		return nil
	}
	if isRoot {
		prompt := fmt.Sprintf("To proceed, type the Root CA common name exactly (%q): ", cfg.PKI.RootSubject.CommonName)
		b.WriteString(prompt)
	} else {
		b.WriteString("To proceed, type yes: ")
	}
	if _, err := fmt.Fprint(out, b.String()); err != nil {
		return err
	}

	line, err := readConfirmLine(cmd)
	if err != nil {
		return err
	}
	if isRoot {
		if line != cfg.PKI.RootSubject.CommonName {
			return errors.New("confirmation did not match the Root CA common name; aborted")
		}
		return nil
	}
	if !strings.EqualFold(line, "yes") {
		return errors.New("not confirmed; aborted")
	}
	return nil
}

// readConfirmLine reads a single trimmed line from the command's input.
func readConfirmLine(cmd *cobra.Command) (string, error) {
	r := bufio.NewReader(cmd.InOrStdin())
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read confirmation: %w", err)
	}
	return strings.TrimSpace(line), nil
}
