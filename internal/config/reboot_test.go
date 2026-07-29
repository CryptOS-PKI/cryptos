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

import "testing"

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
