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

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// newRebootCmd restarts or powers off a running node through its orderly
// shutdown (#231), so a change that config apply reported as
// requires_reboot can take effect without a hypervisor hard reset.
func newRebootCmd(opts *globalOpts) *cobra.Command {
	var (
		confirm  string
		powerOff bool
	)
	cmd := &cobra.Command{
		Use:   "reboot",
		Short: "Reboot (or power off) the node through an orderly shutdown",
		Long: "Restart the node, or power it off with --power-off. The node stops its " +
			"listeners, closes etcd and the audit log, and unmounts and locks the state " +
			"volume before the kernel restarts, which a hypervisor hard reset skips.\n\n" +
			"This takes the CA offline for the duration of the boot, so it asks for the " +
			"CA common name as confirmation, the same echo 'image activate' requires. " +
			"Over mTLS it requires the bootstrap admin client certificate. A powered-off " +
			"node stays off until the hypervisor or a person powers it back on.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if confirm == "" {
				return errors.New("--confirm is required: echo the node's CA common name")
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			if _, err := client.Reboot(cmd.Context(), &cryptosv1.RebootRequest{
				ConfirmCaCn: confirm,
				PowerOff:    powerOff,
			}); err != nil {
				return err
			}
			msg := "reboot accepted: the node is shutting down cleanly and rebooting"
			if powerOff {
				msg = "power-off accepted: the node is shutting down cleanly and powering off"
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), msg)

			return err
		},
	}
	cmd.Flags().StringVar(&confirm, "confirm", "", "the node's CA common name, echoed to authorize the reboot")
	cmd.Flags().BoolVar(&powerOff, "power-off", false, "power the node off instead of restarting it")

	return cmd
}
