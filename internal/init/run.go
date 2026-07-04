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
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/go-tpm/tpm2"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/audit"
	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/console"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/init/mounts"
	"github.com/CryptOS-PKI/cryptos/internal/init/netlink"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos/internal/storage/luks"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// Version is the running build's software version, surfaced via GetStatus.
var Version = "phase-1-dev"

// StateKeyMode selects the state-key/root-key providers. Default "tpm"; a
// nodeID image sets "nodeid" via -ldflags -X at build time. See
// plan/2026-07-03-nodeid-state-key-design.md.
var StateKeyMode = "tpm"

// cryptsetupBinary is the static cryptsetup shipped in the rootfs.
const cryptsetupBinary = "/sbin/cryptsetup"

// newStateKeyBackends builds the state-key protector and Root-key backend for
// the configured mode. "nodeid" never opens the TPM; "tpm" opens it and fails
// closed (with a hint) if absent. The returned func releases the TPM (no-op in
// nodeid mode).
func newStateKeyBackends(mode string) (StateKeyProtector, ceremony.RootKeyBackend, func(), cryptosv1.TpmState, error) {
	if mode == "nodeid" {
		return newNodeIDProtector(readProductUUID, StateLabel), softRootBackend{},
			func() {}, cryptosv1.TpmState_TPM_STATE_UNAVAILABLE, nil
	}
	tp, err := tpm.Open("")
	if err != nil {
		return nil, nil, func() {}, cryptosv1.TpmState_TPM_STATE_UNAVAILABLE,
			fmt.Errorf("init: open TPM: %w (if this host cannot provide a vTPM, use the nodeID image variant)", err)
	}
	caps, err := tp.Probe()
	if err != nil {
		_ = tp.Close()
		return nil, nil, func() {}, cryptosv1.TpmState_TPM_STATE_UNAVAILABLE, fmt.Errorf("init: probe TPM: %w", err)
	}
	if !caps.SupportsCurve(tpm2.TPMECCNistP384) {
		_ = tp.Close()
		return nil, nil, func() {}, cryptosv1.TpmState_TPM_STATE_INSUFFICIENT_CAPABILITY,
			errors.New("init: TPM does not advertise ECDSA P-384")
	}
	return newTPMProtector(tp, tpm.DefaultSealPCRs), tpmRootBackend{tp},
		func() { _ = tp.Close() }, cryptosv1.TpmState_TPM_STATE_OK, nil
}

// Boot runs the full PID 1 bring-up sequence and blocks serving the
// management API until a shutdown signal arrives. Every step is
// fail-closed: any error returns and PID 1 reboots (there is no recovery
// shell).
//
// NOTE: this is device-level I/O and only runs on a Linux node with a
// TPM; on a dev host the platform helpers fail fast. Runtime validation
// is the QEMU + swtpm integration boot.
func Boot(ctx context.Context) (err error) {
	// 1. Early kernel mounts (must precede /dev-dependent steps).
	if err := mounts.EarlyMounts(); err != nil {
		return err
	}

	// Route verbose stdlib logging to the kernel ring buffer now that devtmpfs
	// has created /dev/kmsg. This must happen after EarlyMounts and before the
	// first log.Printf below, otherwise the lines fall through to init's stderr
	// and clutter the branded console= device on prod.
	routeVerboseLogs()

	// Branded boot: open the console and render the shield once. Each bring-up
	// step below marks its status. Best-effort: if the console cannot be opened,
	// step is a no-op and boot proceeds unchanged.
	var scr *console.Renderer
	if cons, err := openConsole(); err == nil {
		scr = console.NewRenderer(cons)
		_ = scr.Banner()
	}
	step := func(name string, ok bool) {
		if scr == nil {
			return
		}
		st := console.StepOK
		if !ok {
			st = console.StepFail
		}
		_ = scr.Step(name, st)
	}

	// 2. Derive paths; probe for the state partition before touching the TPM.
	// Maintenance mode: no cryptos-state partition means nothing is installed
	// (booted from the ISO). Serve the limited maintenance API instead of the
	// normal TPM/LUKS/ceremony bring-up. Probe before the TPM step so a VM with
	// no vTPM still enters maintenance cleanly.
	paths := DerivePaths()
	if stateDeviceMissing(StateLabel) {
		return runMaintenance(ctx)
	}

	// 3. State-key + Root-key backends (TPM-sealed by default; nodeID/software
	// for the TPM-less dev image).
	protector, rootBackend, closeBackends, tpmState, err := newStateKeyBackends(StateKeyMode)
	if err != nil {
		return err
	}
	defer closeBackends()
	log.Printf("state key mode: %s", protector.Name())

	// 4. Open (or first-boot-format) the encrypted state volume. Resolve the
	// state partition by its GPT name via sysfs (the image has no udev, so the
	// by-partlabel symlinks never exist); devtmpfs has created the /dev node.
	// First-boot is decided from the partition itself (!IsLUKS), not from config,
	// because config does not exist yet.
	stateDevice, err := resolveStateDevice(StateLabel)
	if err != nil {
		return err
	}
	paths.Device = stateDevice
	dev := &luks.Device{Path: paths.Device, Runner: &luks.ExecRunner{Binary: cryptsetupBinary}}
	firstBoot := !dev.IsLUKS(ctx)
	vol, err := OpenStateVolume(ctx, StateVolumeConfig{
		Protector: protector, Device: dev, MappedName: StateMappedName,
		TokenID: StateTokenID, FirstBoot: firstBoot,
	})
	if err != nil {
		return err
	}
	if firstBoot {
		if err := mkfsExt4(vol.Path); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(paths.Mount, 0o700); err != nil {
		return fmt.Errorf("init: mkdir %s: %w", paths.Mount, err)
	}
	if err := mountFS(vol.Path, paths.Mount, "ext4"); err != nil {
		return err
	}
	step("state volume", true)
	// paths.ConfigDir is intentionally not created here — config.FileStore.Write
	// creates it (MkdirAll) when it first persists, and the read path tolerates
	// its absence (missing dir reads as "no config yet").
	for _, d := range []string{paths.EtcdDir, paths.AuditDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("init: mkdir %s: %w", d, err)
		}
	}

	// 5. Load machine config from the state fs. Precedence: persisted config →
	// ESP-staged config (seeded by the installer at EFI/cryptos/machine.yaml).
	// Missing or unparseable config on an already-installed node drops to
	// maintenance mode.
	cfgStore := config.NewFileStore(paths.ConfigDir)
	cfg, err := loadOrSeedConfig(cfgStore, realESPStageAccessors())
	if err != nil {
		if errors.Is(err, errEnterMaintenance) {
			log.Printf("MAINTENANCE: %v", err)
			return runMaintenance(ctx)
		}
		return err
	}
	step("configuration", true)

	// 6. Apply config-dependent bring-up. Early connectivity (if needed before
	// this point) is provided by kernel ip=dhcp; the static apply is idempotent.
	if err := netlink.BringUpLoopback(); err != nil {
		return err
	}
	if err := setHostname(cfg.Metadata.Name); err != nil {
		return err
	}
	nlCfg, err := networkConfig(cfg)
	if err != nil {
		return err
	}
	if err := netlink.ConfigureInterface(nlCfg); err != nil {
		return err
	}
	step("network", true)

	// 7. Master seed (audit + ceremony signing keys derive from it).
	seed, err := LoadOrCreateSeed(paths.Seed)
	if err != nil {
		return err
	}

	// 8. Embedded etcd + state store.
	es, err := etcd.Open(paths.EtcdDir)
	if err != nil {
		return fmt.Errorf("init: start etcd: %w", err)
	}
	step("embedded etcd", true)
	defer func() { _ = es.Close() }()
	cli, err := es.Client()
	if err != nil {
		return fmt.Errorf("init: etcd client: %w", err)
	}
	defer func() { _ = cli.Close() }()
	store, err := node.New(cli)
	if err != nil {
		return err
	}
	if _, err := store.IncrementBootCount(ctx); err != nil {
		return fmt.Errorf("init: boot count: %w", err)
	}

	// 9. Bootstrap admin trust + audit log.
	trust, err := bootstrap.LoadTrust(cfg.Bootstrap)
	if err != nil {
		return err
	}
	logger, err := audit.Open(paths.AuditDir, seed)
	if err != nil {
		return fmt.Errorf("init: open audit: %w", err)
	}
	defer func() { _ = logger.Close() }()

	// 10. Providers + ceremony engine, shared by both listeners.
	statusProv, err := node.NewStatusProvider(node.StatusConfig{
		Store:           store,
		Role:            cryptosv1.NodeRole_NODE_ROLE_ROOT,
		SoftwareVersion: Version,
		TPMState:        func() cryptosv1.TpmState { return tpmState },
	})
	if err != nil {
		return err
	}
	eng, err := ceremony.New(ceremony.Config{RootKey: rootBackend, Store: store, ConfigStore: cfgStore, Trust: trust, Seed: seed})
	if err != nil {
		return err
	}
	baseCfg := func() cgrpc.ServerConfig {
		return cgrpc.ServerConfig{
			Auditor:     logger,
			Identity:    node.NewIdentityProvider(store),
			Status:      statusProv,
			Ceremony:    eng,
			ConfigStore: node.NewConfigStore(cfgStore),
		}
	}

	// 11. Local UNIX-socket listener (root-only, no TLS).
	_ = os.Remove(LocalSocketPath)
	localSrv, err := cgrpc.NewLocal(baseCfg())
	if err != nil {
		return err
	}
	localLis, err := net.Listen("unix", LocalSocketPath)
	if err != nil {
		return fmt.Errorf("init: listen %s: %w", LocalSocketPath, err)
	}
	go func() { _ = localSrv.Serve(localLis) }()
	defer localSrv.Stop()

	// 12. mTLS listener on the configured address.
	sans, err := ServerSANs(cfg)
	if err != nil {
		return err
	}
	serverCert, err := GenerateServerCert(sans)
	if err != nil {
		return err
	}
	tlsCfg, err := ServerTLSConfig(serverCert, trust)
	if err != nil {
		return err
	}
	mtlsCfg := baseCfg()
	mtlsCfg.TLSConfig = tlsCfg
	mtlsSrv, err := cgrpc.New(mtlsCfg)
	if err != nil {
		return err
	}
	addr, err := ManagementAddr(cfg)
	if err != nil {
		return err
	}
	mtlsLis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("init: listen %s: %w", addr, err)
	}
	go func() { _ = mtlsSrv.Serve(mtlsLis) }()
	defer mtlsSrv.Stop()

	step("management API", true)
	log.Printf("listeners up: mTLS=%s local=%s first_boot=%t", addr, LocalSocketPath, firstBoot)

	// 13. Park until a shutdown signal; PID 1 then returns and reboots.
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	<-sigCtx.Done()
	log.Printf("shutdown signal received")
	return nil
}

// networkConfig builds the netlink config from the machine config.
func networkConfig(cfg *config.Config) (netlink.Config, error) {
	p, err := netip.ParsePrefix(cfg.Network.Address)
	if err != nil {
		return netlink.Config{}, fmt.Errorf("init: network.address: %w", err)
	}
	var gw netip.Addr
	if cfg.Network.Gateway != "" {
		if gw, err = netip.ParseAddr(cfg.Network.Gateway); err != nil {
			return netlink.Config{}, fmt.Errorf("init: network.gateway: %w", err)
		}
	}
	return netlink.Config{Name: cfg.Network.Interface, Address: p, Gateway: gw}, nil
}
