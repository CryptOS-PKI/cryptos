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
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func newStatusCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show node role, identity state, and subsystem health",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.GetStatus(cmd.Context(), &cryptosv1.GetStatusRequest{})
			if err != nil {
				return err
			}
			if opts.output == formatHuman {
				_, err := io.WriteString(cmd.OutOrStdout(), humanStatus(resp.Status))
				return err
			}
			return renderProto(cmd.OutOrStdout(), resp.Status, opts.output)
		},
	}
}

// humanStatus renders a NodeStatus as an aligned human-readable block.
func humanStatus(s *cryptosv1.NodeStatus) string {
	if s == nil {
		return "(no status)\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Role:            %s\n", trimEnum(s.Role.String(), "NODE_ROLE_"))
	fmt.Fprintf(&b, "Identity:        %s\n", trimEnum(s.IdentityState.String(), "IDENTITY_STATE_"))
	fmt.Fprintf(&b, "TPM:             %s\n", trimEnum(s.TpmState.String(), "TPM_STATE_"))
	fmt.Fprintf(&b, "etcd:            %s\n", trimEnum(s.EtcdState.String(), "ETCD_STATE_"))
	fmt.Fprintf(&b, "Boot count:      %d\n", s.BootCount)
	fmt.Fprintf(&b, "Version:         %s\n", s.SoftwareVersion)
	if p := s.GetRevocationPreflight(); p != nil {
		fmt.Fprintf(&b, "Revocation:      %s\n", humanPreflight(p))
	}
	if r := s.GetResolver(); r != nil {
		fmt.Fprintf(&b, "DNS:             %s\n", humanResolver(r))
	}
	return b.String()
}

// humanPreflight renders the revocation preflight as one line: the state, the
// base URL checked, when, and the last error while failing.
func humanPreflight(p *cryptosv1.RevocationPreflight) string {
	line := trimEnum(p.GetState().String(), "REVOCATION_PREFLIGHT_STATE_")
	if u := p.GetBaseUrl(); u != "" {
		line += " " + u
	}
	if p.GetCheckedAt() != nil {
		line += " (checked " + p.GetCheckedAt().AsTime().UTC().Format(time.RFC3339) + ")"
	}
	if e := p.GetLastError(); e != "" {
		line += ": " + e
	}
	return line
}

// humanResolver renders the resolver as one line: the source, the nameservers
// in order, and the search list.
func humanResolver(r *cryptosv1.ResolverStatus) string {
	line := trimEnum(r.GetSource().String(), "RESOLVER_SOURCE_")
	if ns := r.GetNameservers(); len(ns) > 0 {
		line += " " + strings.Join(ns, ", ")
	}
	if sd := r.GetSearch(); len(sd) > 0 {
		line += " (search " + strings.Join(sd, " ") + ")"
	}
	return line
}

// trimEnum strips a proto enum prefix for human display.
func trimEnum(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}
