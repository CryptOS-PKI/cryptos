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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// The rootfs is a read-only SquashFS, so /etc/resolv.conf in the image is a
// symlink to resolvConfPath on the /run tmpfs (build/squashfs/build.sh). Go's
// resolver reads /etc/resolv.conf through that link; with no file there it
// falls back to a nameserver on localhost, where nothing listens.
const (
	resolvConfPath = "/run/resolv.conf"
	// pnpPath is where the kernel's ip= autoconfiguration reports what it
	// learned: "nameserver" lines (at most three) and a "domain" line from a
	// DHCP lease. The kernel does not honour DHCP option 119 (search list).
	pnpPath = "/proc/net/pnp"
)

// configureResolver writes the node's resolver configuration at boot (#233).
func configureResolver(n config.Network) error {
	return writeResolverConfig(n, pnpPath, resolvConfPath)
}

// writeResolverConfig renders the resolver configuration from n and the kernel
// lease at pnp and writes it to out. With no resolver from either source any
// existing out is removed, so the node never resolves through servers the
// current config does not name.
func writeResolverConfig(n config.Network, pnp, out string) error {
	lease, err := os.ReadFile(pnp)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("init: read %s: %w", pnp, err)
	}
	content := resolvConf(n, lease)
	if content == nil {
		log.Printf("init: no DNS resolver: network.nameservers is empty and the kernel DHCP lease supplied none")
		if err := os.Remove(out); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("init: remove %s: %w", out, err)
		}
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".resolv.conf-*")
	if err != nil {
		return fmt.Errorf("init: write %s: %w", out, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("init: write %s: %w", out, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("init: write %s: %w", out, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("init: write %s: %w", out, err)
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return fmt.Errorf("init: write %s: %w", out, err)
	}
	return nil
}

// resolvConf renders a resolv.conf, or returns nil when there is no nameserver
// to name. network.nameservers wins when set and is used as declared, with only
// network.search. Otherwise the nameservers and domain from the kernel DHCP
// lease are used, with network.search replacing the lease domain when set.
func resolvConf(n config.Network, pnp []byte) []byte {
	source := "network.nameservers in the machine config"
	servers := n.Nameservers
	search := n.Search
	if len(servers) == 0 {
		var domain string
		servers, domain = parsePNP(pnp)
		if len(servers) == 0 {
			return nil
		}
		source = "the kernel DHCP lease (" + pnpPath + ")"
		if len(search) == 0 && domain != "" {
			search = []string{domain}
		}
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Written by cryptos init from %s.\n", source)
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
	}
	return b.Bytes()
}

// parsePNP extracts the nameservers and domain from /proc/net/pnp. The lease is
// input from the network, so every value is validated with the same rules as
// the machine config and anything else is dropped.
func parsePNP(pnp []byte) (servers []string, domain string) {
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(pnp))
	for sc.Scan() {
		key, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "nameserver":
			a, err := config.ParseNameserver(val)
			if err != nil || seen[a.String()] || len(servers) == config.MaxNameservers {
				continue
			}
			seen[a.String()] = true
			servers = append(servers, a.String())
		case "domain":
			if config.ValidateSearchDomain(val) == nil {
				domain = val
			}
		}
	}
	return servers, domain
}
