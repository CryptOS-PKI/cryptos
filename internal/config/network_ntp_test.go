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

func TestParseNetworkNTPServersAndClockOverride(t *testing.T) {
	raw := strings.Replace(string(validYAML(t)), "  gateway: 10.0.0.1\n",
		"  gateway: 10.0.0.1\n  ntp_servers: [10.0.0.123, time.example.org]\n", 1)
	raw = strings.Replace(raw, "pki:\n", "pki:\n  allow_unsynced_clock: true\n", 1)
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := strings.Join(cfg.Network.NTPServers, ","); got != "10.0.0.123,time.example.org" {
		t.Errorf("NTPServers = %q", got)
	}
	if !cfg.PKI.AllowUnsyncedClock {
		t.Error("AllowUnsyncedClock = false, want true")
	}
}

func TestValidateNetworkNTPServers(t *testing.T) {
	cases := []struct {
		name    string
		servers []string
		ok      bool
	}{
		{"none", nil, true},
		{"ipv4 literal", []string{"10.0.0.123"}, true},
		{"hostname", []string{"time.example.org"}, true},
		{"single label hostname", []string{"ntp"}, true},
		{"three mixed", []string{"10.0.0.123", "time.example.org", "10.0.1.123"}, true},
		{"four exceeds the cap", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, false},
		{"ipv6 is refused on an IPv4-only node", []string{"2001:db8::123"}, false},
		{"ipv4-mapped ipv6", []string{"::ffff:10.0.0.123"}, false},
		{"unspecified", []string{"0.0.0.0"}, false},
		{"broadcast", []string{"255.255.255.255"}, false},
		{"multicast", []string{"224.0.1.1"}, false},
		{"empty entry", []string{""}, false},
		{"with a port", []string{"10.0.0.123:123"}, false},
		{"hostname with a port", []string{"time.example.org:123"}, false},
		{"whitespace", []string{"time example.org"}, false},
		{"duplicate literal", []string{"10.0.0.123", "10.0.0.123"}, false},
		{"duplicate hostname ignoring case and trailing dot", []string{"Time.Example.org", "time.example.org."}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg.Network.NTPServers = tc.servers
			err = cfg.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("Validate accepted an invalid ntp_servers list")
				}
				if !strings.Contains(err.Error(), "network.ntp_servers") {
					t.Fatalf("error %q does not name network.ntp_servers", err)
				}
			}
		})
	}
}

// The time settings must survive ToProto -> FromProto, for the same reason the
// resolver settings must: config reaches an installed node through the proto.
func TestTimeSyncConfigSurvivesProtoRoundTrip(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg.Network.NTPServers = []string{"10.0.0.123", "time.example.org"}
	cfg.PKI.AllowUnsyncedClock = true

	pb := cfg.ToProto()
	if got := strings.Join(pb.Network.NtpServers, ","); got != "10.0.0.123,time.example.org" {
		t.Errorf("proto NtpServers = %q", got)
	}
	if !pb.Pki.AllowUnsyncedClock {
		t.Error("proto AllowUnsyncedClock = false")
	}
	got, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if strings.Join(got.Network.NTPServers, ",") != "10.0.0.123,time.example.org" {
		t.Errorf("round-tripped NTPServers = %v", got.Network.NTPServers)
	}
	if !got.PKI.AllowUnsyncedClock {
		t.Error("round-tripped AllowUnsyncedClock = false")
	}
}

func TestNTPResolverWarning(t *testing.T) {
	cases := []struct {
		name        string
		servers     []string
		nameservers []string
		wantHost    string
	}{
		{"no servers", nil, nil, ""},
		{"literals need no resolver", []string{"10.0.0.123"}, nil, ""},
		{"hostname with a static resolver", []string{"time.example.org"}, []string{"10.0.0.53"}, ""},
		{"hostname without a static resolver", []string{"10.0.0.123", "time.example.org"}, nil, "time.example.org"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(validYAML(t))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg.Network.NTPServers = tc.servers
			cfg.Network.Nameservers = tc.nameservers
			w := cfg.NTPResolverWarning()
			if tc.wantHost == "" {
				if w != "" {
					t.Fatalf("NTPResolverWarning = %q, want none", w)
				}
				return
			}
			if !strings.Contains(w, tc.wantHost) || !strings.Contains(w, "network.nameservers") {
				t.Fatalf("NTPResolverWarning = %q, want it to name %q and network.nameservers", w, tc.wantHost)
			}
		})
	}
}

func TestTimeSourceWarning(t *testing.T) {
	cfg, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if w := cfg.TimeSourceWarning(); !strings.Contains(w, "network.ntp_servers") {
		t.Fatalf("TimeSourceWarning with no servers = %q, want it to name network.ntp_servers", w)
	}
	cfg.Network.NTPServers = []string{"10.0.0.123"}
	if w := cfg.TimeSourceWarning(); w != "" {
		t.Fatalf("TimeSourceWarning with servers = %q, want none", w)
	}
}
