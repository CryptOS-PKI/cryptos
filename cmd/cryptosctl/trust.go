package main

/*
Apache License 2.0

Copyright The CryptOS Authors.

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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/CryptOS-PKI/cryptos/internal/console"
)

// trustFetchTimeout bounds the TCP connect plus TLS handshake used to read the
// node's certificate.
const trustFetchTimeout = 10 * time.Second

func newTrustCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage the pinned management certificate of a node",
	}
	cmd.AddCommand(newTrustFetchCmd(opts))
	return cmd
}

func newTrustFetchCmd(opts *globalOpts) *cobra.Command {
	var expect string
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch the node's management certificate and save it as the --trust pin",
		Long: "Connects to --endpoint, reads the certificate the node presents, prints its SHA-256\n" +
			"and saves it to the --trust path. The node regenerates this certificate on every boot,\n" +
			"so run this again after each reboot. Pass --expect-sha256 with the fingerprint shown\n" +
			"on the node console to refuse any other certificate.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var want []byte
			if expect != "" {
				w, err := parseFingerprint(expect)
				if err != nil {
					return err
				}
				want = w
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), trustFetchTimeout)
			defer cancel()
			cert, err := fetchServerCert(ctx, opts.endpoint, serverName(opts))
			if err != nil {
				return err
			}
			got := console.Fingerprint(cert.Raw)
			if want != nil && got != console.FormatFingerprint(want) {
				return fmt.Errorf("the certificate %s presented does not match --expect-sha256: got %s, want %s; nothing was saved",
					opts.endpoint, got, console.FormatFingerprint(want))
			}
			if err := savePin(opts.trustCert, cert); err != nil {
				return err
			}
			return writeFetchReport(cmd.OutOrStdout(), cert, got, opts.trustCert, want != nil)
		},
	}
	cmd.Flags().StringVar(&expect, "expect-sha256", "", "SHA-256 the certificate must have, as shown on the node console (spaces, colons and case are ignored)")
	return cmd
}

// parseFingerprint accepts a SHA-256 in the console form ("ABCD EF01 ..."), the
// openssl form ("AB:CD:..."), or plain hex, in either case.
func parseFingerprint(s string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "").Replace(strings.TrimSpace(s))
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("--expect-sha256 %q is not a SHA-256 fingerprint (64 hex digits)", s)
	}
	return b, nil
}

// fetchServerCert completes enough of a TLS 1.3 handshake with addr to read the
// server's leaf certificate. It sends no client certificate: the node sends its
// certificate before asking for one, so the handshake is expected to fail once
// the node sees there is none, and that failure is ignored when the
// certificate was already received.
func fetchServerCert(ctx context.Context, addr, name string) (*x509.Certificate, error) {
	var leaf *x509.Certificate
	cfg := &tls.Config{
		// The whole point is to read a certificate nothing vouches for yet;
		// the caller checks it by fingerprint.
		InsecureSkipVerify: true, //nolint:gosec // pin bootstrap: verified by fingerprint, not by chain
		MinVersion:         tls.VersionTLS13,
		ServerName:         name,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				leaf = cs.PeerCertificates[0]
			}
			return nil
		},
	}
	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if conn != nil {
		_ = conn.Close()
	}
	if leaf == nil {
		if err == nil {
			err = errors.New("no certificate presented")
		}
		return nil, fmt.Errorf("fetch certificate from %s: %w", addr, err)
	}
	return leaf, nil
}

// savePin writes cert as PEM to path, creating its directory when missing.
func savePin(path string, cert *x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("save pin: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("save pin: %w", err)
	}
	return nil
}

func writeFetchReport(w io.Writer, cert *x509.Certificate, fp, path string, verified bool) error {
	sans := make([]string, 0, len(cert.IPAddresses)+len(cert.DNSNames))
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.DNSNames...)

	var b strings.Builder
	fmt.Fprintf(&b, "Subject:    %s\n", cert.Subject.String())
	fmt.Fprintf(&b, "Issuer:     %s\n", cert.Issuer.String())
	fmt.Fprintf(&b, "SANs:       %s\n", strings.Join(sans, ", "))
	fmt.Fprintf(&b, "Not after:  %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "SHA-256:    %s\n", fp)
	fmt.Fprintf(&b, "Saved to:   %s\n", path)
	if verified {
		b.WriteString("Pin verified: the SHA-256 matches --expect-sha256.\n")
	} else {
		b.WriteString("Pin not verified: compare the SHA-256 above with the Mgmt SHA-256 on the node console before relying on it.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
