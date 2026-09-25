package config

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
	"net/netip"
	"net/url"
	"strings"
)

// Resolver limits. They match the classic resolv.conf limits (MAXNS and
// MAXDNSRCH) so the generated file means the same thing to any resolver that
// reads it, not only to Go's.
const (
	MaxNameservers   = 3
	MaxSearchDomains = 6
)

// validateNameservers enforces that each nameserver is a distinct IPv4 literal.
// CryptOS is IPv4-only, and a hostname here would need a resolver to find the
// resolver.
func validateNameservers(ns []string) error {
	if len(ns) > MaxNameservers {
		return fmt.Errorf("config: network.nameservers: at most %d entries, got %d", MaxNameservers, len(ns))
	}
	seen := make(map[netip.Addr]bool, len(ns))
	for i, s := range ns {
		a, err := ParseNameserver(s)
		if err != nil {
			return fmt.Errorf("config: network.nameservers[%d]: %w", i, err)
		}
		if seen[a] {
			return fmt.Errorf("config: network.nameservers[%d]: %s is listed twice", i, a)
		}
		seen[a] = true
	}
	return nil
}

// ParseNameserver parses s as a usable IPv4 nameserver address.
func ParseNameserver(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("must be an IPv4 address: %w", err)
	}
	if !a.Is4() {
		return netip.Addr{}, fmt.Errorf("must be an IPv4 address, got %q", s)
	}
	if a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, fmt.Errorf("%s is not a unicast address", a)
	}
	return a, nil
}

// validateSearch enforces that each search domain is a syntactically valid DNS
// name. The check also keeps whitespace and newlines out of the generated
// resolv.conf, where they would split or inject directives.
func validateSearch(search []string) error {
	if len(search) > MaxSearchDomains {
		return fmt.Errorf("config: network.search: at most %d entries, got %d", MaxSearchDomains, len(search))
	}
	for i, d := range search {
		if err := ValidateSearchDomain(d); err != nil {
			return fmt.Errorf("config: network.search[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateSearchDomain reports whether name is a valid DNS search domain:
// letters, digits and hyphens in labels of 1-63 octets, at most 253 octets in
// total, with an optional trailing dot. A single label is allowed.
func ValidateSearchDomain(name string) error {
	n := strings.TrimSuffix(name, ".")
	if n == "" {
		return errors.New("must not be empty")
	}
	if len(n) > 253 {
		return fmt.Errorf("%q exceeds 253 characters", name)
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q has an empty or over-long label", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with a hyphen", name)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("%q contains a character that is not allowed in a domain name", name)
			}
		}
	}
	return nil
}

// RevocationResolverWarning returns a warning when pki.revocation_base_url
// names a host but network.nameservers is empty, and "" otherwise. Such a node
// resolves the host only if its DHCP lease supplies DNS servers; if it does
// not, the fail-closed revocation preflight refuses every issuance. It is a
// warning rather than a validation error because a lease that carries DNS
// servers is a valid deployment.
func (c *Config) RevocationResolverWarning() string {
	if c.PKI.RevocationBaseURL == "" || len(c.Network.Nameservers) > 0 {
		return ""
	}
	u, err := url.Parse(c.PKI.RevocationBaseURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return ""
	}
	return fmt.Sprintf("pki.revocation_base_url names the host %q but network.nameservers is empty. "+
		"The node can resolve it only if its DHCP lease supplies DNS servers; if it cannot, "+
		"the revocation preflight fails and the node refuses all issuance. "+
		"Set network.nameservers to the DNS servers that resolve that name.", u.Hostname())
}
