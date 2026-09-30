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
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/audit"
)

// newAuditCmd groups the verbs that read the node's hash-chained audit log.
func newAuditCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read and verify the node's audit log",
	}
	cmd.AddCommand(newAuditListCmd(opts), newAuditVerifyCmd(opts))
	return cmd
}

func newAuditListCmd(opts *globalOpts) *cobra.Command {
	var (
		since, until, eventType, actor, pageToken string
		pageSize                                  int32
		all                                       bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit log entries, oldest first",
		Long: "List the node's audit log entries, oldest first, a page at a time. " +
			"--since and --until take an RFC3339 time or a duration back from now (for example 24h). " +
			"--type matches the call's method name (for example RevokeCertificate) and --actor matches " +
			"part of the caller's certificate subject, case-sensitively.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			now := time.Now()
			from, err := auditTimeFlag("--since", since, now)
			if err != nil {
				return err
			}
			to, err := auditTimeFlag("--until", until, now)
			if err != nil {
				return err
			}

			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			req := &cryptosv1.ListAuditEventsRequest{
				PageSize:  pageSize,
				PageToken: pageToken,
				FromTime:  from,
				ToTime:    to,
				EventType: eventType,
				Actor:     actor,
			}
			resp, err := client.ListAuditEvents(cmd.Context(), req)
			if err != nil {
				return err
			}
			for all && resp.GetNextPageToken() != "" {
				req.PageToken = resp.GetNextPageToken()
				next, err := client.ListAuditEvents(cmd.Context(), req)
				if err != nil {
					return err
				}
				resp.Entries = append(resp.Entries, next.GetEntries()...)
				resp.NextPageToken = next.GetNextPageToken()
			}
			return writeAuditEntries(cmd.OutOrStdout(), resp, opts.output)
		},
	}
	f := cmd.Flags()
	f.StringVar(&since, "since", "", "only entries at or after this time (RFC3339, or a duration such as 24h)")
	f.StringVar(&until, "until", "", "only entries before this time (RFC3339, or a duration such as 1h)")
	f.StringVar(&eventType, "type", "", "only this call, by method name (e.g. RevokeCertificate) or full method")
	f.StringVar(&actor, "actor", "", "only entries whose actor subject contains this text (case-sensitive)")
	f.Int32Var(&pageSize, "page-size", 0, "most entries per page (0 = the node's default)")
	f.StringVar(&pageToken, "page-token", "", "continue from the token a previous page printed")
	f.BoolVar(&all, "all", false, "fetch every page")
	return cmd
}

// auditTimeFlag turns a --since/--until value into the RFC3339 time the RPC
// takes: an RFC3339 time as given, or a duration counted back from now.
func auditTimeFlag(name, v string, now time.Time) (string, error) {
	if v == "" {
		return "", nil
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t.UTC().Format(time.RFC3339Nano), nil
	}
	if d, err := time.ParseDuration(v); err == nil && d >= 0 {
		return now.Add(-d).UTC().Format(time.RFC3339Nano), nil
	}
	return "", fmt.Errorf("%s %q: want an RFC3339 time (2026-06-03T12:00:00Z) or a duration (24h)", name, v)
}

func writeAuditEntries(w io.Writer, resp *cryptosv1.ListAuditEventsResponse, format string) error {
	if format != formatHuman {
		return renderProto(w, resp, format)
	}
	if len(resp.GetEntries()) == 0 {
		_, err := io.WriteString(w, "(no audit entries)\n")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SEQ\tTIME\tACTOR\tEVENT\tOUTCOME\tSUMMARY")
	for _, e := range resp.GetEntries() {
		ev := e.GetEvent()
		actor := ev.GetActorSubject()
		if actor == "" {
			actor = "(local socket)"
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
			ev.GetSeq(),
			ev.GetTs().AsTime().UTC().Format(time.RFC3339),
			actor,
			audit.MethodName(ev.GetRpcMethod()),
			auditOutcome(ev.GetOutcome()),
			e.GetSummary())
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if tok := resp.GetNextPageToken(); tok != "" {
		_, err := fmt.Fprintf(w, "(more entries: repeat with --page-token %s, or use --all)\n", tok)
		return err
	}
	return nil
}

func auditOutcome(o cryptosv1.Outcome) string {
	switch o {
	case cryptosv1.Outcome_OUTCOME_OK:
		return "ok"
	case cryptosv1.Outcome_OUTCOME_DENIED:
		return "denied"
	case cryptosv1.Outcome_OUTCOME_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

func newAuditVerifyCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit log's signatures and hash chain; fails on a broken chain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, closeConn, err := dial(opts)
			if err != nil {
				return err
			}
			defer func() { _ = closeConn() }()

			resp, err := client.VerifyAuditChain(cmd.Context(), &cryptosv1.VerifyAuditChainRequest{})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if opts.output != formatHuman {
				if err := renderProto(out, resp, opts.output); err != nil {
					return err
				}
			} else if resp.GetIntact() {
				if _, err := fmt.Fprintf(out, "audit chain intact: %d entries verified\n", resp.GetEntryCount()); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(out, "audit chain broken at seq %d of %d entries: %s\n",
					resp.GetFirstBrokenSequence(), resp.GetEntryCount(), resp.GetReason()); err != nil {
					return err
				}
			}
			if !resp.GetIntact() {
				return fmt.Errorf("the audit chain is broken at seq %d", resp.GetFirstBrokenSequence())
			}
			return nil
		},
	}
}
