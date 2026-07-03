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
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// Fixed boot-time paths (the machine config is baked into the rootfs at
// build time; everything else lives under the unlocked state volume).
const (
	// DefaultConfigPath is where the UKI/rootfs build places machine.yaml.
	DefaultConfigPath = "/etc/cryptos/machine.yaml"
	// StateMountPoint is where the unlocked state volume is mounted.
	StateMountPoint = "/var/lib/cryptos"
	// StateMappedName is the dm-crypt name for the unlocked volume.
	StateMappedName = "cryptos-state"
	// StateLabel is the GPT partition name of the encrypted state partition.
	// State discovery uses this constant, never the machine config, because the
	// config lives ON the state partition and cannot be read before it is found.
	StateLabel = "cryptos-state"
	// StateTokenID is the LUKS2 token id holding the sealed key.
	StateTokenID = 0
	// LocalSocketPath is the on-box management UNIX socket.
	LocalSocketPath = "/run/cryptos.sock"
	// ManagementPort is the mTLS gRPC listener port.
	ManagementPort = 443
)

// BootPaths are the resolved filesystem locations for one node, derived
// from its machine config.
type BootPaths struct {
	// Device is the state-partition block device.
	Device string
	// Mount is the mount point for the unlocked volume.
	Mount string
	// Seed is the master-seed file path.
	Seed string
	// EtcdDir is the embedded-etcd data directory.
	EtcdDir string
	// AuditDir is the audit-log directory.
	AuditDir string
}

// DerivePaths computes the boot paths from the machine config. Device is left
// empty here and resolved at boot from the partition's GPT name via sysfs (see
// resolveStateDevice) — the image has no udev, so /dev/disk/by-partlabel/*
// symlinks never exist.
func DerivePaths() BootPaths {
	return BootPaths{
		Mount:    StateMountPoint,
		Seed:     filepath.Join(StateMountPoint, "seed"),
		EtcdDir:  filepath.Join(StateMountPoint, "etcd"),
		AuditDir: filepath.Join(StateMountPoint, "audit"),
	}
}

// ServerSANs returns the SANs for the pre-identity management server
// certificate: the configured interface IP plus "localhost".
func ServerSANs(cfg *config.Config) ([]string, error) {
	p, err := netip.ParsePrefix(cfg.Network.Address)
	if err != nil {
		return nil, fmt.Errorf("init: ServerSANs: network.address %q: %w", cfg.Network.Address, err)
	}
	return []string{p.Addr().String(), "localhost"}, nil
}

// ManagementAddr returns the host:port the mTLS listener binds, from the
// configured interface address.
func ManagementAddr(cfg *config.Config) (string, error) {
	p, err := netip.ParsePrefix(cfg.Network.Address)
	if err != nil {
		return "", fmt.Errorf("init: ManagementAddr: network.address %q: %w", cfg.Network.Address, err)
	}
	return netip.AddrPortFrom(p.Addr(), ManagementPort).String(), nil
}
