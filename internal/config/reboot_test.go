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
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/protobuf/proto"
)

func baseConfig() *Config {
	return &Config{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata:   Metadata{Name: "node-a"},
		Role:       Role{Kind: RoleIntermediate},
		Network:    Network{Interface: "eth0", Address: "10.0.0.10/24", Gateway: "10.0.0.1"},
		Install:    Install{Disk: "/dev/nvme0n1"},
		StateKey:   StateKey{Mode: "nodeid"},
		PKI: PKI{
			RootKeyAlg:  RootKeyECDSAP384,
			RootSubject: Subject{CommonName: "ACME Intermediate CA"},
			Parent:      &Parent{CACertPEM: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"},
		},
	}
}

func TestNeedsReboot(t *testing.T) {
	t.Run("identical config needs no reboot", func(t *testing.T) {
		if NeedsReboot(baseConfig(), baseConfig()) {
			t.Error("identical configs should not require a reboot")
		}
	})

	t.Run("adding a cert profile is hot (no reboot)", func(t *testing.T) {
		old := baseConfig()
		next := baseConfig()
		next.PKI.Profiles = []CertificateProfile{{Name: "server-tls"}}
		if NeedsReboot(old, next) {
			t.Error("a profiles-only change must be hot, not require a reboot")
		}
	})

	t.Run("acknowledging root leaf issuance is hot (no reboot)", func(t *testing.T) {
		old := baseConfig()
		next := baseConfig()
		next.PKI.RootLeafIssuance = RootLeafIssuanceAcknowledged
		if NeedsReboot(old, next) {
			t.Error("a root_leaf_issuance-only change must be hot, not require a reboot")
		}
	})

	t.Run("network change requires a reboot", func(t *testing.T) {
		old := baseConfig()
		next := baseConfig()
		next.Network.Address = "10.0.0.20/24"
		if !NeedsReboot(old, next) {
			t.Error("a network change must require a reboot")
		}
	})

	t.Run("install disk change requires a reboot", func(t *testing.T) {
		old := baseConfig()
		next := baseConfig()
		next.Install.Disk = "/dev/sda"
		if !NeedsReboot(old, next) {
			t.Error("an install disk change must require a reboot")
		}
	})

	t.Run("revocation endpoint change requires a reboot", func(t *testing.T) {
		old := baseConfig()
		next := baseConfig()
		next.PKI.RevocationBaseURL = "http://10.0.0.10"
		if !NeedsReboot(old, next) {
			t.Error("a revocation base URL change gates the boot-time listener and must require a reboot")
		}
	})

	t.Run("nil configs fail safe to reboot", func(t *testing.T) {
		if !NeedsReboot(nil, baseConfig()) {
			t.Error("a nil old config (first apply) must require a reboot")
		}
	})
}

// A config that went over the wire comes back with nil where the stored YAML
// parsed an empty list. That is the same config, so it must not read as a
// reboot-required change.
func TestNeedsRebootIgnoresNilVersusEmpty(t *testing.T) {
	stored := &Config{Network: Network{Nameservers: []string{}, Search: []string{}}}
	stored.PKI.ACME = &ACME{BaseURL: "https://ca.example.org/acme", AllowedIdentifierSuffixes: []string{}}
	wire := &Config{}
	wire.PKI.ACME = &ACME{BaseURL: "https://ca.example.org/acme"}
	if NeedsReboot(stored, wire) {
		t.Error("nil and empty lists were classified as a reboot-required change")
	}
	wire.PKI.ACME.AllowedIdentifierSuffixes = []string{"example.org"}
	if !NeedsReboot(stored, wire) {
		t.Error("a real protocol change was classified as live")
	}
}

// roundTrip returns the two views of a config that ApplyConfig compares: the
// running config as the node reads it back from its store, and the incoming
// config, after mutate, as it arrives over the wire. The wire matters: an
// empty list is written to the store as [] and reads back as an empty slice,
// while the same list crossing gRPC decodes as nil.
func roundTrip(t *testing.T, mutate func(*Config)) (*Config, *Config) {
	t.Helper()
	stored, err := Parse(validYAML(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	raw, err := stored.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	old, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse stored: %v", err)
	}
	incoming, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse incoming: %v", err)
	}
	mutate(incoming)
	wire, err := proto.Marshal(incoming.ToProto())
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	var pb nodev1.MachineConfig
	if err := proto.Unmarshal(wire, &pb); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	next, err := FromProto(&pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	return old, next
}

func TestNeedsRebootThroughTheStoreAndTheWire(t *testing.T) {
	t.Run("identical re-apply through the store and the API needs no reboot", func(t *testing.T) {
		old, next := roundTrip(t, func(*Config) {})
		if NeedsReboot(old, next) {
			t.Error("re-applying the running config must not require a reboot")
		}
	})

	t.Run("profile-only change through the store and the API needs no reboot", func(t *testing.T) {
		old, next := roundTrip(t, func(c *Config) { c.PKI.Profiles = sampleProfiles() })
		if NeedsReboot(old, next) {
			t.Error("a profiles-only change must not require a reboot")
		}
	})

	t.Run("network change through the store and the API requires a reboot", func(t *testing.T) {
		old, next := roundTrip(t, func(c *Config) { c.Network.Nameservers = []string{"192.0.2.53"} })
		if !NeedsReboot(old, next) {
			t.Error("adding a nameserver must require a reboot")
		}
	})
}

func TestNeedsRebootLiveFields(t *testing.T) {
	t.Run("allow_unverified_revocation_url is read live by the signer (no reboot)", func(t *testing.T) {
		old, next := roundTrip(t, func(c *Config) {
			c.PKI.RevocationBaseURL = "http://192.0.2.10"
			c.PKI.AllowUnverifiedRevocationURL = true
		})
		old.PKI.RevocationBaseURL = "http://192.0.2.10"
		if NeedsReboot(old, next) {
			t.Error("an allow_unverified_revocation_url-only change must not require a reboot")
		}
	})

	t.Run("allow_unsynced_clock is read live by the signer (no reboot)", func(t *testing.T) {
		old, next := roundTrip(t, func(c *Config) { c.PKI.AllowUnsyncedClock = true })
		if NeedsReboot(old, next) {
			t.Error("an allow_unsynced_clock-only change must not require a reboot")
		}
	})
}
