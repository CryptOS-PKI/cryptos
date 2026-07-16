// Command cryptos-sbkey generates a UEFI Secure Boot signing key and a
// self-signed certificate for it. The build pipeline signs the UKI with the
// key (via sbsign); the certificate is enrolled into platform firmware (the
// db variable) so the firmware will load the signed image. See
// docs/secure-boot.md for the enrollment procedure.
//
// It writes three files into --out-dir:
//
//	sb.key  RSA private key, PKCS#8 PEM (2048 bits by default, or 4096
//	        with --bits 4096)                -> sbsign --key
//	sb.crt  certificate, PEM                   -> sbsign --cert / sbverify
//	sb.der  certificate, raw DER               -> firmware db enrollment
//
// Existing files are never clobbered without --force.
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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/secureboot"
)

func main() {
	var (
		outDir = flag.String("out-dir", ".", "directory to write sb.key, sb.crt, sb.der into")
		cn     = flag.String("cn", "CryptOS Secure Boot", "certificate subject common name")
		days   = flag.Int("days", 0, "certificate validity in days (0 = ~10 years)")
		bits   = flag.Int("bits", 2048, "RSA signing key size in bits: 2048 (default) or 4096")
		force  = flag.Bool("force", false, "overwrite existing output files")
	)
	flag.Parse()

	if err := run(*outDir, *cn, *days, *bits, *force); err != nil {
		fmt.Fprintln(os.Stderr, "cryptos-sbkey:", err)
		os.Exit(1)
	}
}

func run(outDir, cn string, days, bits int, force bool) error {
	// Warn only for the valid opt-in size; an unsupported size falls through
	// to Generate, which rejects it, so warning about it here would mislead.
	if bits == 4096 {
		fmt.Fprintf(os.Stderr, "cryptos-sbkey: warning: RSA-%d Secure Boot keys load only on firmware that supports RSA-%d in db; RSA-2048 is the UEFI-mandated baseline. If the target firmware rejects this key, the signed image will not boot.\n", bits, bits)
	}

	opts := secureboot.Options{CommonName: cn, KeyBits: bits}
	if days > 0 {
		opts.Validity = time.Duration(days) * 24 * time.Hour
	}

	m, err := secureboot.Generate(opts)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create out-dir: %w", err)
	}

	// The private key is 0600; the certs are public material.
	outputs := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"sb.key", m.KeyPEM, 0o600},
		{"sb.crt", m.CertPEM, 0o644},
		{"sb.der", m.CertDER, 0o644},
	}

	if !force {
		for _, o := range outputs {
			p := filepath.Join(outDir, o.name)
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s already exists (use --force to overwrite)", p)
			}
		}
	}

	for _, o := range outputs {
		p := filepath.Join(outDir, o.name)
		if err := os.WriteFile(p, o.data, o.mode); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
		fmt.Println("wrote", p)
	}
	return nil
}
