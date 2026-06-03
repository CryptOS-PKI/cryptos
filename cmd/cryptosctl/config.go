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
	"encoding/hex"
	"errors"
	"fmt"
	"os"

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
	return cmd
}
