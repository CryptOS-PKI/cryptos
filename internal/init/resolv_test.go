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
	"os"
	"path/filepath"
	"slices"
	"testing"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// pnpDHCP is /proc/net/pnp as the kernel writes it after an ip=dhcp lease.
const pnpDHCP = "#PROTO: DHCP\ndomain lease.example.org\nnameserver 192.0.2.53\nnameserver 192.0.2.54\nbootserver 192.0.2.1\n"

func TestResolvConfStaticWins(t *testing.T) {
	n := config.Network{
		Nameservers: []string{"10.0.0.53", "10.0.1.53"},
		Search:      []string{"pki.example.org", "example.org"},
	}
	got := string(resolvConf(n, []byte(pnpDHCP)))
	want := "# Written by cryptos init from network.nameservers in the machine config.\n" +
		"nameserver 10.0.0.53\nnameserver 10.0.1.53\nsearch pki.example.org example.org\n"
	if got != want {
		t.Fatalf("resolvConf =\n%s\nwant\n%s", got, want)
	}
}

// A static resolver is used as declared: the lease's domain belongs to the
// lease's servers and is not mixed in.
func TestResolvConfStaticNameserversIgnoreLeaseDomain(t *testing.T) {
	n := config.Network{Nameservers: []string{"10.0.0.53"}}
	got := string(resolvConf(n, []byte(pnpDHCP)))
	want := "# Written by cryptos init from network.nameservers in the machine config.\n" +
		"nameserver 10.0.0.53\n"
	if got != want {
		t.Fatalf("resolvConf =\n%s\nwant\n%s", got, want)
	}
}

func TestResolvConfFallsBackToDHCPLease(t *testing.T) {
	got := string(resolvConf(config.Network{}, []byte(pnpDHCP)))
	want := "# Written by cryptos init from the kernel DHCP lease (/proc/net/pnp).\n" +
		"nameserver 192.0.2.53\nnameserver 192.0.2.54\nsearch lease.example.org\n"
	if got != want {
		t.Fatalf("resolvConf =\n%s\nwant\n%s", got, want)
	}
}

func TestResolvConfStaticSearchOverridesLeaseDomain(t *testing.T) {
	got := string(resolvConf(config.Network{Search: []string{"example.org"}}, []byte(pnpDHCP)))
	want := "# Written by cryptos init from the kernel DHCP lease (/proc/net/pnp).\n" +
		"nameserver 192.0.2.53\nnameserver 192.0.2.54\nsearch example.org\n"
	if got != want {
		t.Fatalf("resolvConf =\n%s\nwant\n%s", got, want)
	}
}

// The kernel lease is untrusted input: junk entries are dropped rather than
// copied into resolv.conf, and more than the resolver limit is truncated.
func TestResolvConfIgnoresBadLeaseEntries(t *testing.T) {
	pnp := "#PROTO: DHCP\ndomain bad domain\nnameserver 0.0.0.0\nnameserver not-an-ip\n" +
		"nameserver 192.0.2.1\nnameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 192.0.2.3\nnameserver 192.0.2.4\n"
	got := string(resolvConf(config.Network{}, []byte(pnp)))
	want := "# Written by cryptos init from the kernel DHCP lease (/proc/net/pnp).\n" +
		"nameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 192.0.2.3\n"
	if got != want {
		t.Fatalf("resolvConf =\n%s\nwant\n%s", got, want)
	}
}

func TestResolvConfNoResolver(t *testing.T) {
	for name, pnp := range map[string]string{
		"no lease":             "",
		"static kernel config": "#MANUAL\n",
	} {
		if got := resolvConf(config.Network{Search: []string{"example.org"}}, []byte(pnp)); got != nil {
			t.Errorf("%s: resolvConf = %q, want nil", name, got)
		}
	}
}

func TestWriteResolverConfig(t *testing.T) {
	dir := t.TempDir()
	pnp := filepath.Join(dir, "pnp")
	out := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(pnp, []byte(pnpDHCP), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := writeResolverConfig(config.Network{Nameservers: []string{"10.0.0.53"}}, pnp, out); err != nil {
		t.Fatalf("writeResolverConfig: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(resolvConf(config.Network{Nameservers: []string{"10.0.0.53"}}, []byte(pnpDHCP))) {
		t.Fatalf("wrote %q", b)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", fi.Mode().Perm())
	}

	// No resolver anywhere: nothing is written and a stale file is not left
	// behind to point at servers the config no longer names.
	if _, err := writeResolverConfig(config.Network{}, filepath.Join(dir, "missing"), out); err != nil {
		t.Fatalf("writeResolverConfig without a resolver: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("resolv.conf still present after a boot with no resolver: %v", err)
	}
}

// The status surface reports where the resolver came from and what it holds,
// the same facts written to resolv.conf.
func TestResolverFor(t *testing.T) {
	cases := []struct {
		name    string
		n       config.Network
		pnp     string
		source  cryptosv1.ResolverSource
		servers []string
		search  []string
	}{
		{
			name:    "machine config",
			n:       config.Network{Nameservers: []string{"10.0.0.53"}, Search: []string{"example.org"}},
			pnp:     pnpDHCP,
			source:  cryptosv1.ResolverSource_RESOLVER_SOURCE_MACHINE_CONFIG,
			servers: []string{"10.0.0.53"},
			search:  []string{"example.org"},
		},
		{
			name:    "DHCP lease",
			pnp:     pnpDHCP,
			source:  cryptosv1.ResolverSource_RESOLVER_SOURCE_DHCP_LEASE,
			servers: []string{"192.0.2.53", "192.0.2.54"},
			search:  []string{"lease.example.org"},
		},
		{
			name:   "none",
			source: cryptosv1.ResolverSource_RESOLVER_SOURCE_NONE,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolverFor(tc.n, []byte(tc.pnp))
			if got.GetSource() != tc.source {
				t.Errorf("source = %v, want %v", got.GetSource(), tc.source)
			}
			if !slices.Equal(got.GetNameservers(), tc.servers) {
				t.Errorf("nameservers = %v, want %v", got.GetNameservers(), tc.servers)
			}
			if !slices.Equal(got.GetSearch(), tc.search) {
				t.Errorf("search = %v, want %v", got.GetSearch(), tc.search)
			}
		})
	}
}

// writeResolverConfig returns what it wrote, so boot can hand it to GetStatus.
func TestWriteResolverConfigReportsTheResolver(t *testing.T) {
	dir := t.TempDir()
	pnp := filepath.Join(dir, "pnp")
	if err := os.WriteFile(pnp, []byte(pnpDHCP), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := writeResolverConfig(config.Network{}, pnp, filepath.Join(dir, "resolv.conf"))
	if err != nil {
		t.Fatalf("writeResolverConfig: %v", err)
	}
	if got.GetSource() != cryptosv1.ResolverSource_RESOLVER_SOURCE_DHCP_LEASE ||
		!slices.Equal(got.GetNameservers(), []string{"192.0.2.53", "192.0.2.54"}) {
		t.Fatalf("resolver = %v, want the DHCP lease servers", got)
	}
}
