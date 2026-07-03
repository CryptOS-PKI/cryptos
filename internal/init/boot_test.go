package init

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
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

func testConfig() *config.Config {
	c := &config.Config{}
	c.Network.Address = "10.0.0.10/24"
	return c
}

func TestDerivePaths(t *testing.T) {
	p := DerivePaths()
	// Device is intentionally not set by DerivePaths — it is resolved at boot
	// from the partition's GPT name via sysfs (see resolveStateDevice).
	cases := map[string]string{
		"Mount":     "/var/lib/cryptos",
		"ConfigDir": "/var/lib/cryptos/config",
		"Seed":      "/var/lib/cryptos/seed",
		"EtcdDir":   "/var/lib/cryptos/etcd",
		"AuditDir":  "/var/lib/cryptos/audit",
	}
	got := map[string]string{"Mount": p.Mount, "ConfigDir": p.ConfigDir, "Seed": p.Seed, "EtcdDir": p.EtcdDir, "AuditDir": p.AuditDir}
	for k, want := range cases {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

func TestServerSANs(t *testing.T) {
	sans, err := ServerSANs(testConfig())
	if err != nil {
		t.Fatalf("ServerSANs: %v", err)
	}
	if len(sans) != 2 || sans[0] != "10.0.0.10" || sans[1] != "localhost" {
		t.Errorf("SANs = %v, want [10.0.0.10 localhost]", sans)
	}
	bad := &config.Config{}
	bad.Network.Address = "not-a-cidr"
	if _, err := ServerSANs(bad); err == nil {
		t.Error("ServerSANs(bad address) should error")
	}
}

func TestManagementAddr(t *testing.T) {
	addr, err := ManagementAddr(testConfig())
	if err != nil {
		t.Fatalf("ManagementAddr: %v", err)
	}
	if addr != "10.0.0.10:443" {
		t.Errorf("ManagementAddr = %q, want 10.0.0.10:443", addr)
	}
}

func TestStateLabelConstant(t *testing.T) {
	if StateLabel != "cryptos-state" {
		t.Errorf("StateLabel = %q, want cryptos-state", StateLabel)
	}
	if StateLabel != StateMappedName {
		t.Errorf("StateLabel %q should match StateMappedName %q", StateLabel, StateMappedName)
	}
}
