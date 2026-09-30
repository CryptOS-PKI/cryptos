package console

/*
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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
)

// ManagementCertPath is where init publishes the public certificate the
// management listener presents this boot. The console reads it so an operator
// can compare the fingerprint a client sees against the node's own screen
// before pinning it.
const ManagementCertPath = "/run/cryptos-mgmt.crt"

// Fingerprint returns the SHA-256 of der as uppercase hex in space-separated
// groups of four digits, the form shown on the console and printed by
// cryptosctl so the two can be read against each other.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return FormatFingerprint(sum[:])
}

// FormatFingerprint renders an already computed digest in the grouped form
// Fingerprint uses.
func FormatFingerprint(sum []byte) string {
	h := strings.ToUpper(hex.EncodeToString(sum))
	groups := make([]string, 0, len(h)/4)
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:i+4])
	}
	return strings.Join(groups, " ")
}

// ManagementFingerprint reads the PEM certificate at path and returns its
// Fingerprint, or "" when the file is missing or holds no parseable
// certificate. An empty result keeps the line off the dashboard instead of
// showing a value the node did not publish.
func ManagementFingerprint(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ""
	}
	return Fingerprint(block.Bytes)
}
