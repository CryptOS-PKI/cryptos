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
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/buildinfo"
)

// versionReport is what `cryptosctl version` prints: always the CLI's own
// build identity, and the node's software version when a node was named.
type versionReport struct {
	Client clientVersion `json:"client"`
	Node   *nodeVersion  `json:"node,omitempty"`
}

type clientVersion struct {
	buildinfo.Info
	GoVersion string `json:"go_version"`
}

type nodeVersion struct {
	Version string `json:"version"`
}

func newVersionCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the cryptosctl build, and the node's version when --endpoint or --socket is given",
		Long: "version prints the build identity of this cryptosctl binary (version, commit, build date).\n" +
			"When --endpoint or --socket is set it also asks that node for its software version\n" +
			"(the same value `status` reports), so a stale local binary or a node that did not\n" +
			"boot the expected image is visible at a glance.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := versionReport{Client: clientVersion{Info: buildinfo.Get(), GoVersion: runtime.Version()}}

			var nodeErr error
			if cmd.Flags().Changed("endpoint") || cmd.Flags().Changed("socket") {
				report.Node, nodeErr = queryNodeVersion(cmd, opts)
			}
			if err := writeVersion(cmd.OutOrStdout(), report, opts.output); err != nil {
				return err
			}
			return nodeErr
		},
	}
}

// queryNodeVersion reads the node's software version from GetStatus.
func queryNodeVersion(cmd *cobra.Command, opts *globalOpts) (*nodeVersion, error) {
	client, closeConn, err := dial(opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeConn() }()
	resp, err := client.GetStatus(cmd.Context(), &cryptosv1.GetStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("query node version: %w", err)
	}
	return &nodeVersion{Version: resp.GetStatus().GetSoftwareVersion()}, nil
}

func writeVersion(w io.Writer, r versionReport, format string) error {
	switch format {
	case formatHuman:
		_, err := io.WriteString(w, humanVersion(r))
		return err
	case formatJSON, formatYAML:
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		if format == formatYAML {
			b, err = jsonToYAML(b)
			if err != nil {
				return err
			}
			_, err = w.Write(b)
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	default:
		return fmt.Errorf("unsupported output format %q (want human, json, or yaml)", format)
	}
}

func humanVersion(r versionReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Client version:  %s\n", r.Client.Version)
	fmt.Fprintf(&b, "Client commit:   %s\n", r.Client.Commit)
	fmt.Fprintf(&b, "Client built:    %s\n", r.Client.BuildDate)
	fmt.Fprintf(&b, "Go version:      %s\n", r.Client.GoVersion)
	if r.Node != nil {
		fmt.Fprintf(&b, "Node version:    %s\n", r.Node.Version)
	}
	return b.String()
}
