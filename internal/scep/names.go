package scep

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
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
)

// maxNamesPerRequest bounds the SAN count on one request.
const maxNamesPerRequest = 100

// requestNames returns the names a certificate request asks for: its DNS
// SANs plus the subject common name. Anything SCEP does not issue (an IP,
// email or URI SAN) is refused rather than dropped, so a device never gets
// back less than it asked for without being told.
//
// The common name counts as a name whenever it is set: unlike EST, where a
// non-hostname CN is ignored, the SCEP allowlist bounds the subject CN too,
// because a device's trustpoint subject-name is usually its FQDN.
func requestNames(csr *x509.CertificateRequest) ([]string, error) {
	if len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, fmt.Errorf("the request carries an IP, email or URI subject alternative name; SCEP here issues DNS names only")
	}
	names := collectNames(csr.DNSNames, csr.Subject.CommonName)
	if len(names) == 0 {
		return nil, fmt.Errorf("the request carries no name to certify")
	}
	if len(names) > maxNamesPerRequest {
		return nil, fmt.Errorf("the request carries %d names, more than the %d allowed", len(names), maxNamesPerRequest)
	}
	for _, n := range names {
		if err := validateDNSName(n); err != nil {
			return nil, err
		}
	}
	return names, nil
}

// certNames returns a certificate's names in requestNames form.
func certNames(c *x509.Certificate) []string {
	return collectNames(c.DNSNames, c.Subject.CommonName)
}

// collectNames lowercases, strips a trailing dot and de-duplicates, keeping
// first-seen order, with the common name last.
func collectNames(dnsNames []string, commonName string) []string {
	seen := make(map[string]bool, len(dnsNames)+1)
	out := make([]string, 0, len(dnsNames)+1)
	for _, n := range append(append([]string(nil), dnsNames...), commonName) {
		n = normalizeName(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func normalizeName(n string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
}

func sameNameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// suffixAllowed reports whether name equals or is a subdomain of a suffix,
// on a label boundary: "example.com" covers "sw1.example.com" but not
// "badexample.com".
func suffixAllowed(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		s := normalizeName(strings.TrimPrefix(strings.TrimSpace(suffix), "."))
		if s == "" {
			continue
		}
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// checkAllowlist refuses any name outside the allowlist.
func checkAllowlist(names, suffixes []string) error {
	for _, n := range names {
		if !suffixAllowed(n, suffixes) {
			return fmt.Errorf("%s is outside the allowed identifier suffixes", n)
		}
	}
	return nil
}

// checkBound refuses any name a challenge was not bound to. An unbound
// challenge (no names) allows whatever the allowlist allows.
func checkBound(names, bound []string) error {
	if len(bound) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(bound))
	for _, b := range bound {
		allowed[normalizeName(b)] = true
	}
	for _, n := range names {
		if !allowed[n] {
			return fmt.Errorf("%s is not one of the names the challenge is bound to", n)
		}
	}
	return nil
}

// validateDNSName applies the hostname rules a DNS SAN must meet. Wildcards
// are refused: a challenge establishes nothing about a label space.
func validateDNSName(name string) error {
	if strings.Contains(name, "*") {
		return fmt.Errorf("%q: wildcard names are not issued over SCEP", name)
	}
	if len(name) > 253 {
		return fmt.Errorf("%q exceeds 253 characters", name)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q is not a fully qualified domain name", name)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q has an empty or over-long label", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with a hyphen", name)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("%q contains a character not allowed in a hostname", name)
			}
		}
	}
	return nil
}
