package netlink

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
)

// Config is the Phase 1 static network configuration for one interface.
type Config struct {
	// Name is the interface name (e.g. "eth0").
	Name string
	// Address is the static IPv4 address + prefix (e.g. 10.0.0.10/24).
	Address netip.Prefix
	// Gateway is the default-route next hop (e.g. 10.0.0.1). Zero value
	// means no default route is added.
	Gateway netip.Addr
}

// indexFunc resolves an interface name to its kernel index.
type indexFunc func(name string) (int, error)

// sendFunc sends a single rtnetlink request and waits for the kernel ACK.
type sendFunc func(msg []byte) error

// bringUpLoopback sets IFF_UP on "lo".
func bringUpLoopback(ifIndex indexFunc, send sendFunc) error {
	idx, err := ifIndex("lo")
	if err != nil {
		return fmt.Errorf("netlink: loopback index: %w", err)
	}
	if err := send(buildLinkUpRequest(1, idx)); err != nil {
		return fmt.Errorf("netlink: bring up loopback: %w", err)
	}
	return nil
}

// configure brings the named interface up, assigns its static address,
// and (if set) installs a default route via the gateway. Each step is a
// separate ACK'd request, applied in order; the first failure aborts.
func configure(cfg Config, ifIndex indexFunc, send sendFunc) error {
	if cfg.Name == "" {
		return errors.New("netlink: configure: interface name is required")
	}
	if !cfg.Address.IsValid() || !cfg.Address.Addr().Is4() {
		return fmt.Errorf("netlink: configure: %q needs a valid IPv4 address/prefix", cfg.Name)
	}
	if cfg.Gateway.IsValid() && !cfg.Gateway.Is4() {
		return errors.New("netlink: configure: gateway must be IPv4")
	}

	idx, err := ifIndex(cfg.Name)
	if err != nil {
		return fmt.Errorf("netlink: %s index: %w", cfg.Name, err)
	}

	var seq uint32 = 1
	if err := send(buildLinkUpRequest(seq, idx)); err != nil {
		return fmt.Errorf("netlink: set %s up: %w", cfg.Name, err)
	}
	seq++
	if err := send(buildAddrRequest(seq, idx, cfg.Address)); err != nil {
		return fmt.Errorf("netlink: add %s to %s: %w", cfg.Address, cfg.Name, err)
	}
	seq++
	if cfg.Gateway.IsValid() {
		if err := send(buildDefaultRouteRequest(seq, idx, cfg.Gateway)); err != nil {
			return fmt.Errorf("netlink: add default route via %s: %w", cfg.Gateway, err)
		}
	}
	return nil
}
