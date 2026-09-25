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
	"strings"
	"testing"
)

// A node with no resolver cannot resolve a hostname revocation_base_url, so
// the fail-closed revocation preflight refuses every issuance (#233). The
// resolver is declared under network.
func TestParseNetworkNameserversAndSearch(t *testing.T) {
	raw := strings.Replace(string(validYAML(t)), "  gateway: 10.0.0.1\n",
		"  gateway: 10.0.0.1\n  nameservers: [10.0.0.53, 10.0.1.53]\n  search: [pki.example.org, example.org]\n", 1)
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := strings.Join(cfg.Network.Nameservers, ","); got != "10.0.0.53,10.0.1.53" {
		t.Errorf("Nameservers = %q", got)
	}
	if got := strings.Join(cfg.Network.Search, ","); got != "pki.example.org,example.org" {
		t.Errorf("Search = %q", got)
	}
}

func TestValidateNetworkNameservers(t *testing.T) {
	cases := []struct {
		name string
		ns   []string
		ok   bool
	}{
		{"none", nil, true},
		{"one", []string{"10.0.0.53"}, true},
		{"three", []string{"10.0.0.53", "10.0.1.53", "10.0.2.53"}, true},
		{"four exceeds the resolver limit", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, false},
		{"ipv6 is refused on an IPv4-only node", []string{"2001:db8::53"}, false},
		{"ipv4-mapped ipv6", []string{"::ffff:10.0.0.53"}, false},
		{"hostname", []string{"dns.example.org"}, false},
		{"unspecified", []string{"0.0.0.0"}, false},
		{"empty entry", []string{""}, false},
		{"with a port", []string{"10.0.0.53:53"}, false},
		{"duplicate", []string{"10.0.0.53", "10.0.0.53"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg.Network.Nameservers = tc.ns
			err = cfg.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("Validate accepted an invalid nameserver list")
				}
				if !strings.Contains(err.Error(), "network.nameservers") {
					t.Fatalf("error %q does not name network.nameservers", err)
				}
			}
		})
	}
}

func TestValidateNetworkSearch(t *testing.T) {
	cases := []struct {
		name   string
		search []string
		ok     bool
	}{
		{"none", nil, true},
		{"fqdn", []string{"pki.example.org"}, true},
		{"single label", []string{"corp"}, true},
		{"trailing dot", []string{"example.org."}, true},
		{"mixed case", []string{"Example.ORG"}, true},
		{"empty", []string{""}, false},
		{"whitespace would split the resolv.conf line", []string{"example.org other.org"}, false},
		{"newline would inject a resolv.conf directive", []string{"example.org\nnameserver 192.0.2.1"}, false},
		{"empty label", []string{"example..org"}, false},
		{"leading hyphen", []string{"-example.org"}, false},
		{"over-long label", []string{strings.Repeat("a", 64) + ".org"}, false},
		{"over-long name", []string{strings.Repeat("a.", 127) + "org"}, false},
		{"seven exceeds the resolver limit", []string{"a.org", "b.org", "c.org", "d.org", "e.org", "f.org", "g.org"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg.Network.Search = tc.search
			err = cfg.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("Validate accepted an invalid search list")
				}
				if !strings.Contains(err.Error(), "network.search") {
					t.Fatalf("error %q does not name network.search", err)
				}
			}
		})
	}
}

// The resolver settings must survive ToProto -> FromProto: cryptosctl applies
// config over the wire and the maintenance installer stages an installed node's
// config from the proto, so a field the proto drops never reaches the node.
func TestNetworkResolverSurvivesProtoRoundTrip(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.Network.Nameservers = []string{"10.0.0.53", "10.0.1.53"}
	cfg.Network.Search = []string{"pki.example.org"}

	pb := cfg.ToProto()
	if got := strings.Join(pb.Network.Nameservers, ","); got != "10.0.0.53,10.0.1.53" {
		t.Fatalf("ToProto nameservers = %q", got)
	}
	got, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if s := strings.Join(got.Network.Nameservers, ","); s != "10.0.0.53,10.0.1.53" {
		t.Errorf("Nameservers = %q, want both preserved in order", s)
	}
	if s := strings.Join(got.Network.Search, ","); s != "pki.example.org" {
		t.Errorf("Search = %q, want it preserved", s)
	}
}

// A hostname revocation base URL with no static resolver depends on the DHCP
// lease for DNS; config apply warns about it rather than refusing, because a
// lease that does carry DNS servers is a valid deployment.
func TestRevocationResolverWarning(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		ns      []string
		warn    bool
	}{
		{"no revocation url", "", nil, false},
		{"hostname without nameservers", "http://pki.example.org", nil, true},
		{"hostname with nameservers", "http://pki.example.org", []string{"10.0.0.53"}, false},
		{"ipv4 literal needs no resolver", "http://10.0.0.10:8080", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{}
			c.PKI.RevocationBaseURL = tc.baseURL
			c.Network.Nameservers = tc.ns
			got := c.RevocationResolverWarning()
			if tc.warn && got == "" {
				t.Fatal("expected a warning")
			}
			if !tc.warn && got != "" {
				t.Fatalf("unexpected warning: %q", got)
			}
		})
	}
}
