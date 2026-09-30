package config

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
	"fmt"
	"net/netip"
	"strings"
)

// MaxNTPServers caps network.ntp_servers. It matches the kernel's limit on
// DHCP option 42 servers and the nameserver limit, so a leased list and a
// declared one hold the same number of servers.
const MaxNTPServers = 3

// validateNTPServers enforces that each time server is a unicast IPv4 literal
// or a syntactically valid hostname, and that none is listed twice. A literal
// is checked like a nameserver; anything that does not parse as an address is
// checked as a DNS name, which also keeps ports and whitespace out.
func validateNTPServers(servers []string) error {
	if len(servers) > MaxNTPServers {
		return fmt.Errorf("config: network.ntp_servers: at most %d entries, got %d", MaxNTPServers, len(servers))
	}
	seen := make(map[string]bool, len(servers))
	for i, s := range servers {
		key, err := ntpServerKey(s)
		if err != nil {
			return fmt.Errorf("config: network.ntp_servers[%d]: %w", i, err)
		}
		if seen[key] {
			return fmt.Errorf("config: network.ntp_servers[%d]: %s is listed twice", i, s)
		}
		seen[key] = true
	}
	return nil
}

// ntpServerKey validates s and returns the form used to spot duplicates: the
// address for a literal, the lower-cased name without a trailing dot for a
// hostname.
func ntpServerKey(s string) (string, error) {
	if _, err := netip.ParseAddr(s); err == nil {
		a, err := ParseNameserver(s)
		if err != nil {
			return "", err
		}
		return a.String(), nil
	}
	if err := ValidateSearchDomain(s); err != nil {
		return "", fmt.Errorf("must be an IPv4 address or a hostname: %w", err)
	}
	return strings.ToLower(strings.TrimSuffix(s, ".")), nil
}

// IsNTPHostname reports whether a validated network.ntp_servers entry is a
// hostname rather than an IPv4 literal.
func IsNTPHostname(s string) bool {
	_, err := netip.ParseAddr(s)
	return err != nil
}

// NTPResolverWarning returns a warning when network.ntp_servers names a host
// but network.nameservers is empty, and "" otherwise. Such a node reaches that
// server only if its DHCP lease supplies DNS servers. It is a warning rather
// than a validation error because a lease that carries DNS servers is a valid
// deployment, the same call RevocationResolverWarning makes.
func (c *Config) NTPResolverWarning() string {
	if len(c.Network.Nameservers) > 0 {
		return ""
	}
	for _, s := range c.Network.NTPServers {
		if IsNTPHostname(s) {
			return fmt.Sprintf("network.ntp_servers names the host %q but network.nameservers is empty. "+
				"The node can resolve it only if its DHCP lease supplies DNS servers; if it cannot, "+
				"that server is never queried and, with no other server answering, the node refuses "+
				"to sign until its clock syncs (unless pki.allow_unsynced_clock is set). "+
				"Set network.nameservers, or name the server by IPv4 address.", s)
		}
	}
	return ""
}

// TimeSourceWarning returns a warning when network.ntp_servers is empty, and
// "" otherwise. The node then keeps its clock in sync only if its DHCP lease
// supplies NTP servers; with none it runs on its hardware clock, which drifts,
// and the dates it stamps drift with it. An offline Root is expected to run
// this way, so it is a warning, not an error.
func (c *Config) TimeSourceWarning() string {
	if len(c.Network.NTPServers) > 0 {
		return ""
	}
	return "network.ntp_servers is empty. The node syncs its clock only if its DHCP lease supplies " +
		"NTP servers (option 42); with none it runs on its hardware clock, and certificate and CRL " +
		"dates follow that clock's drift. Set network.ntp_servers unless the node is meant to run offline."
}
