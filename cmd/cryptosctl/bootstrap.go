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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

// bootstrapCredential is a freshly minted bootstrap admin credential.
type bootstrapCredential struct {
	CertPEM []byte
	KeyPEM  []byte
	SHA256  [32]byte
}

func newBootstrapCmd(_ *globalOpts) *cobra.Command {
	var (
		commonName string
		validity   time.Duration
		outDir     string
	)
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Generate a bootstrap admin keypair + self-signed client certificate",
		Long: "bootstrap generates an ECDSA P-256 keypair and a self-signed clientAuth " +
			"certificate on the operator's workstation. Stamp the printed certificate (or " +
			"its SHA-256) into the node's machine config so the node trusts it on first boot.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cred, err := generateBootstrapCredential(commonName, validity)
			if err != nil {
				return err
			}
			if outDir == "" {
				outDir = defaultIdentityDir()
			}
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				return fmt.Errorf("create %s: %w", outDir, err)
			}
			certPath := filepath.Join(outDir, "identity.crt")
			keyPath := filepath.Join(outDir, "identity.key")
			if err := os.WriteFile(certPath, cred.CertPEM, 0o600); err != nil {
				return fmt.Errorf("write cert: %w", err)
			}
			if err := os.WriteFile(keyPath, cred.KeyPEM, 0o600); err != nil {
				return fmt.Errorf("write key: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"wrote %s\nwrote %s\nSHA-256: %s\n\n"+
					"Stamp into machine config under bootstrap.admin_cert_pem (or admin_cert_sha256):\n%s",
				certPath, keyPath, hex.EncodeToString(cred.SHA256[:]), string(cred.CertPEM))
			return err
		},
	}
	cmd.Flags().StringVar(&commonName, "common-name", "cryptos bootstrap admin", "certificate common name")
	cmd.Flags().DurationVar(&validity, "validity", 365*24*time.Hour, "certificate validity duration")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory to write identity.crt/identity.key (default ~/.cryptos)")
	return cmd
}

// generateBootstrapCredential mints an ECDSA P-256 keypair and a
// self-signed clientAuth certificate suitable as a bootstrap admin.
func generateBootstrapCredential(commonName string, validity time.Duration) (*bootstrapCredential, error) {
	if validity <= 0 {
		return nil, fmt.Errorf("validity must be positive, got %s", validity)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return &bootstrapCredential{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		SHA256:  sha256.Sum256(der),
	}, nil
}
