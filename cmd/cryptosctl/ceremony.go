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
	"io"
	"os"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func newCeremonyCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ceremony",
		Short: "Drive node ceremonies",
	}
	cmd.AddCommand(newCeremonyStartCmd(opts))
	return cmd
}

func newCeremonyStartCmd(opts *globalOpts) *cobra.Command {
	var configFile string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Run the first-boot Root ceremony",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configFile == "" {
				return errors.New("--config is required")
			}
			yamlBytes, err := os.ReadFile(configFile)
			if err != nil {
				return fmt.Errorf("read config: %w", err)
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			stream, err := client.StartCeremony(cmd.Context(), &cryptosv1.StartCeremonyRequest{
				Kind:              cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT,
				MachineConfigYaml: yamlBytes,
			})
			if err != nil {
				return err
			}
			return streamCeremony(cmd.OutOrStdout(), stream.Recv)
		},
	}
	cmd.Flags().StringVar(&configFile, "config", "", "machine config YAML to apply (required)")
	return cmd
}

// streamCeremony consumes ceremony events from recv until EOF, printing
// each as it arrives.
func streamCeremony(w io.Writer, recv func() (*cryptosv1.StartCeremonyResponse, error)) error {
	for {
		resp, err := recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, formatEvent(resp.Event)); err != nil {
			return err
		}
	}
}

// formatEvent renders a single ceremony event one-liner.
func formatEvent(ev *cryptosv1.CeremonyEvent) string {
	if ev == nil {
		return "(nil event)"
	}
	switch d := ev.Detail.(type) {
	case *cryptosv1.CeremonyEvent_KeyCreated:
		return fmt.Sprintf("KEY_CREATED      tpm_public=%d bytes", len(d.KeyCreated.TpmPublic))
	case *cryptosv1.CeremonyEvent_CertSigned:
		return fmt.Sprintf("CERT_SIGNED      cert_sha256=%s", hex.EncodeToString(d.CertSigned.CertSha256))
	case *cryptosv1.CeremonyEvent_ManifestWritten:
		return fmt.Sprintf("MANIFEST_WRITTEN manifest_id=%s", d.ManifestWritten.ManifestId)
	case *cryptosv1.CeremonyEvent_AdminRotated:
		return fmt.Sprintf("ADMIN_ROTATED    admin_cert_sha256=%s", hex.EncodeToString(d.AdminRotated.AdminCertSha256))
	case *cryptosv1.CeremonyEvent_Complete:
		return "COMPLETE"
	default:
		return ev.Kind.String()
	}
}
