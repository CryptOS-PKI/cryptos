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
	"net"
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
	cert := readManagementCert(path)
	if cert == nil {
		return ""
	}
	return Fingerprint(cert.Raw)
}

// ManagementCASigned reports whether the certificate at path was issued by a
// CA rather than signed by its own key. The node switches to a CA-signed
// management certificate once it has a CA; from then on clients trust the CA,
// and the fingerprint, which changes every boot, is not something to pin.
// A missing or unparseable file reads as false.
func ManagementCASigned(path string) bool {
	cert := readManagementCert(path)
	if cert == nil {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil
}

func readManagementCert(path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// ManagementAddrs returns, in order, the addresses in addrs an operator can
// reach the management listener on: IPv4 only, since the node configures no
// IPv6, and neither loopback nor link-local.
func ManagementAddrs(addrs []net.Addr) []string {
	var out []string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ip4.String())
	}
	return out
}

// LocalManagementAddrs returns ManagementAddrs for this host's interfaces, or
// nil when they cannot be read.
func LocalManagementAddrs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	return ManagementAddrs(addrs)
}
