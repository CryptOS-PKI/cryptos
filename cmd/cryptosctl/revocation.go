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
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// newRevokeCmd revokes a certificate this node issued, identified by its hex
// serial, with an RFC 5280 reason code. The node records the revocation and
// refreshes the published CRL.
func newRevokeCmd(opts *globalOpts) *cobra.Command {
	var (
		serial string
		reason int
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a certificate this node issued (by hex serial)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if serial == "" {
				return errors.New("--serial is required")
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.RevokeCertificate(cmd.Context(), &cryptosv1.RevokeCertificateRequest{
				SerialHex:  serial,
				ReasonCode: int32(reason),
			})
			if err != nil {
				return err
			}
			return writeRevocations(cmd.OutOrStdout(), []*cryptosv1.Revocation{resp.GetRevocation()}, opts.output)
		},
	}
	cmd.Flags().StringVar(&serial, "serial", "", "hex serial of the certificate to revoke (required)")
	cmd.Flags().IntVar(&reason, "reason", 0, "RFC 5280 CRL reason code (0 = unspecified)")
	return cmd
}

// newListIssuedCmd lists the certificates this node has issued.
func newListIssuedCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "list-issued",
		Short: "List certificates this node has issued",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.ListIssued(cmd.Context(), &cryptosv1.ListIssuedRequest{})
			if err != nil {
				return err
			}
			return writeIssued(cmd.OutOrStdout(), resp.GetIssued(), opts.output)
		},
	}
}

// newRevocationsCmd lists this node's revoked certificates.
func newRevocationsCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "revocations",
		Short: "List this node's revoked certificates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.ListRevocations(cmd.Context(), &cryptosv1.ListRevocationsRequest{})
			if err != nil {
				return err
			}
			return writeRevocations(cmd.OutOrStdout(), resp.GetRevocations(), opts.output)
		},
	}
}

// newCRLCmd prints the current revocation list. There is no GetCRL RPC over the
// mTLS API (the DER CRL is served on the node's separate anonymous HTTP
// listener), so this prints the same revoked set returned by ListRevocations as
// a readable table rather than fetching a signed DER.
func newCRLCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "crl",
		Short: "Print this node's revocation list as a table",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.ListRevocations(cmd.Context(), &cryptosv1.ListRevocationsRequest{})
			if err != nil {
				return err
			}
			return writeRevocations(cmd.OutOrStdout(), resp.GetRevocations(), opts.output)
		},
	}
}

// writeIssued renders the issued-certificate inventory per the output format.
func writeIssued(w io.Writer, issued []*cryptosv1.IssuedCert, format string) error {
	if format != formatHuman {
		return renderProto(w, &cryptosv1.ListIssuedResponse{Issued: issued}, format)
	}
	if len(issued) == 0 {
		_, err := io.WriteString(w, "(no issued certificates)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERIAL\tSUBJECT\tPROFILE\tNOT_AFTER")
	for _, c := range issued {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			c.GetSerialHex(), c.GetSubjectDn(), c.GetProfileName(), formatTimestamp(c.GetNotAfter().AsTime()))
	}
	return tw.Flush()
}

// writeRevocations renders a set of revocations per the output format.
func writeRevocations(w io.Writer, revs []*cryptosv1.Revocation, format string) error {
	if format != formatHuman {
		return renderProto(w, &cryptosv1.ListRevocationsResponse{Revocations: revs}, format)
	}
	if len(revs) == 0 {
		_, err := io.WriteString(w, "(no revocations)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERIAL\tREASON\tREVOKED_AT")
	for _, r := range revs {
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\n",
			r.GetSerialHex(), r.GetReasonCode(), formatTimestamp(r.GetRevokedAt().AsTime()))
	}
	return tw.Flush()
}

// formatTimestamp renders a time in RFC 3339 for human output; a zero time
// (an unset proto timestamp) renders as a dash.
func formatTimestamp(t time.Time) string {
	if t.IsZero() || t.Unix() == 0 {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
