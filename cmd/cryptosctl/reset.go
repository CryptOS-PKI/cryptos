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

// The destructive re-provision path (#216). NodeService has exposed Reset and
// RemoteReset all along; nothing in this CLI reached them, so re-provisioning
// an established node meant writing a gRPC client.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// newResetCmd destroys a node's identity so it can be re-provisioned.
//
// Which RPC to call is read from how the operator is already addressing the
// node rather than from a separate flag. Reset is served only on the local
// console socket (physical-console trust, no authentication); RemoteReset is
// the admin-authorized mTLS counterpart. --socket already says which side of
// that boundary the caller is on, so asking again would only create a way to
// get it wrong.
func newResetCmd(opts *globalOpts) *cobra.Command {
	var (
		assumeYes bool
		confirm   string
	)
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Destroy this node's identity and reboot into re-provision maintenance",
		Long: "Erase the node's state-partition key material and reboot it into re-provision " +
			"maintenance, so it can be given a new configuration and a new CA identity.\n\n" +
			"This is irreversible. Every certificate the node's CA key signed stays valid " +
			"until it expires, but the key is gone and the node can no longer issue, renew " +
			"or publish a fresh CRL for them. Export the key first with `ca export-key` if " +
			"any of that still matters.\n\n" +
			"Over a UNIX socket (--socket) this calls the local console Reset; otherwise it " +
			"calls RemoteReset, which requires the bootstrap admin client certificate.\n\n" +
			"After the reboot the node brings up loopback and takes its address from the " +
			"kernel's ip=dhcp. On a segment with no DHCP relay it will not be reachable, " +
			"and re-provisioning it then needs console or hypervisor access.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if confirm == "" {
				return errors.New("--confirm is required: echo the node's CA common name")
			}
			if err := confirmReset(cmd, confirm, opts.socket != "", assumeYes); err != nil {
				return err
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			if opts.socket != "" {
				_, err = client.Reset(cmd.Context(), &cryptosv1.ResetRequest{ConfirmCommonName: confirm})
			} else {
				_, err = client.RemoteReset(cmd.Context(), &cryptosv1.RemoteResetRequest{ConfirmCommonName: confirm})
			}
			if err != nil {
				return err
			}

			_, err = fmt.Fprintln(cmd.OutOrStdout(),
				"reset accepted: the node is erasing its identity and rebooting into re-provision maintenance")

			return err
		},
	}
	cmd.Flags().StringVar(&confirm, "confirm", "", "the node's CA common name, echoed to authorize the erase")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "skip the interactive confirmation (for automation)")

	return cmd
}

// confirmReset gates the erase behind a warning and a typed confirmation, the
// same shape ca export-key uses on a root. --confirm alone is not treated as
// consent: it is a value the node compares, and it is easy to paste from a
// runbook into the wrong terminal. Typing it is the deliberate act.
func confirmReset(cmd *cobra.Command, cn string, local, assumeYes bool) error {
	out := cmd.OutOrStdout()

	var b strings.Builder
	b.WriteString("WARNING: reset erases this node's state-partition key material.\n")
	b.WriteString("The CA key is destroyed. Certificates it signed stay valid until they expire,\n")
	b.WriteString("but nothing can renew or revoke them afterwards. Export the key first if that matters.\n")
	if local {
		b.WriteString("Addressing the local console socket: this is the unauthenticated Reset.\n")
	}
	if assumeYes {
		b.WriteString("--yes given: proceeding without confirmation.\n")
		_, err := fmt.Fprint(out, b.String())

		return err
	}

	fmt.Fprintf(&b, "To proceed, type the CA common name exactly (%q): ", cn)
	if _, err := fmt.Fprint(out, b.String()); err != nil {
		return err
	}

	line, err := readLineUnbuffered(cmd.InOrStdin())
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if strings.TrimSpace(string(line)) != cn {
		return errors.New("confirmation did not match; aborted")
	}

	return nil
}
