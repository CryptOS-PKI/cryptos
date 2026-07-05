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
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	"github.com/CryptOS-PKI/cryptos/internal/reset"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos/internal/storage/luks"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// resetRebootDelay is the grace period between accepting a Reset and
// restarting the node, so the gRPC ResetResponse flushes to the console
// before the connection drops on reboot.
const resetRebootDelay = 2 * time.Second

// nodeResetter adapts internal/reset to the grpc.Resetter interface. It is
// wired only on the local console socket. Reset delegates to reset.Wipe,
// which checks the confirmation CN against rootCN, erases the state-key
// material (fail-safe: no reboot on an erase error), clears the staged ESP
// config best-effort, and reboots. On a confirm-CN mismatch it returns
// reset.ErrConfirmMismatch, which the grpc handler maps to PermissionDenied.
type nodeResetter struct {
	rootCN     string
	device     reset.Eraser
	clearStage func() error
	reboot     func()
}

// Reset implements grpc.Resetter.
func (r nodeResetter) Reset(ctx context.Context, confirmCommonName string) error {
	return reset.Wipe(ctx, confirmCommonName, reset.Options{
		RootCN:     r.rootCN,
		Device:     r.device,
		ClearStage: r.clearStage,
		Reboot:     r.reboot,
	})
}

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
	// Branded per-stage progress. begin marks a stage as in progress; done marks
	// it complete with [ok]. If Boot returns an error before done() (a fail-closed
	// reboot; there is no shell to inspect), the deferred renderer surfaces [!!]
	// on the stage that was running, so the console shows WHERE boot died.
	var currentStep string
	begin := func(name string) { currentStep = name }
	done := func() {
		if scr != nil && currentStep != "" {
			_ = scr.Step(currentStep, console.StepOK)
		}
		currentStep = ""
	}
	defer func() {
		if err != nil && scr != nil && currentStep != "" {
			_ = scr.Step(currentStep, console.StepFail)
		}
	}()

	// 2. Derive paths; probe for the state partition before touching the TPM.
	// Maintenance mode: no cryptos-state partition means nothing is installed
	// (booted from the ISO). Serve the limited maintenance API instead of the
	// normal TPM/LUKS/ceremony bring-up. Probe before the TPM step so a VM with
	// no vTPM still enters maintenance cleanly.
	paths := DerivePaths()
	if stateDeviceMissing(StateLabel) {
		return runMaintenance(ctx)
	}
	begin("state volume")

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
	done()
	begin("configuration")
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
			// The state partition exists (the early stateDeviceMissing ISO path
			// was not taken) but holds no config: this is the re-provision
			// landing after a console Reset. Serve re-provision maintenance,
			// which persists the applied config to the mounted state and reboots
			// into the ceremony, rather than the bare-disk installer.
			log.Printf("REPROVISION: %v", err)
			return runReprovisionMaintenance(ctx, cfgStore)
		}
		return err
	}
	done()
	begin("network")

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
	done()
	begin("embedded etcd")

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
	done()
	begin("management API")
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

	// 8b. Subordinate first-boot key + CSR. On an intermediate/issuing node with
	// no identity yet, generate the CA key and stage the CSR, entering
	// awaiting-cert; the node then serves the CSR and waits for a parent-signed
	// chain. A Root, or a subordinate already awaiting-cert or established, is a
	// no-op here and loads normally. The Root self-signing ceremony is never run
	// for a subordinate.
	if err := stageSubordinateIfNeeded(ctx, cfg, store, rootBackend); err != nil {
		return err
	}

	// 9. Bootstrap admin trust + audit log.
	trust, err := bootstrap.LoadTrust(cfg.Bootstrap.AdminCertPEM, cfg.Bootstrap.AdminCertSHA256)
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
		Role:            cfg.NodeRole(),
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

	// CA signing service backing the P3a signing RPCs. The CA key is never held
	// after boot: the loader re-reads the persisted key blobs and reloads them
	// through the same RootKeyBackend the ceremony provisioned with (the TPM in
	// tpm mode, the software backend in nodeID mode), returning a Close for the
	// handler to release once signing completes. The issuer getter parses this
	// node's own committed CA certificate; the config getter returns the loaded
	// machine config so profile lookups and the ROOT leaf-issuance ack are read
	// from the live config. The signers are wired only into the management
	// listeners below; the maintenance/reprovision servers never see them, so the
	// signing RPCs refuse there.
	keyLoader := func(ctx context.Context) (crypto.Signer, func(), error) {
		priv, pub, ok, err := store.RootKeyBlobs(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("init: read CA key blobs: %w", err)
		}
		if !ok {
			return nil, nil, errors.New("init: no CA key material (ceremony not committed)")
		}
		signer, err := rootBackend.LoadKey(priv, pub)
		if err != nil {
			return nil, nil, fmt.Errorf("init: load CA key: %w", err)
		}
		return signer, func() { _ = signer.Close() }, nil
	}
	issuerFunc := func(ctx context.Context) (*x509.Certificate, error) {
		id, err := store.Identity(ctx)
		if err != nil {
			return nil, err
		}
		if len(id.ChainDer) == 0 {
			return nil, errors.New("init: identity has no certificate chain")
		}
		return x509.ParseCertificate(id.ChainDer[0])
	}
	configFunc := func(context.Context) (*config.Config, error) { return cfg, nil }
	caSigner := node.NewCASigner(keyLoader, issuerFunc, configFunc)

	// Subordinate enroller backing the P3b subordinate-ceremony RPCs. It is built
	// only on an intermediate/issuing node: cfg.ParentTrust returns the pinned
	// parent anchor (a Root returns nil, nil). The enroller reads the staged CSR
	// from the store and, on AcceptCertificate, verifies the offered chain roots
	// to that anchor and matches this node's staged key before committing. Like
	// the CA signers it is wired only into the management listeners below; the
	// maintenance/reprovision servers never see it, so the ceremony RPCs refuse
	// there with Unimplemented.
	var subEnroller cgrpc.SubordinateEnroller
	parentTrust, err := cfg.ParentTrust()
	if err != nil {
		return fmt.Errorf("init: load parent trust anchor: %w", err)
	}
	if parentTrust != nil {
		enr, err := node.NewSubordinateEnroller(store, parentTrust)
		if err != nil {
			return fmt.Errorf("init: build subordinate enroller: %w", err)
		}
		subEnroller = enr
	}

	// 11. Local UNIX-socket listener (root-only, no TLS). Only this server
	// carries the Resetter, so the destructive Reset RPC is refused
	// (Unimplemented) on the mTLS listener.
	//
	// rootCN is the node's Root CA leaf CN, read best-effort from the
	// identity provider. It is empty before the ceremony commits; with an
	// empty rootCN any confirmation fails closed, which is correct: an
	// unprovisioned node has no key material to wipe.
	rootCN := ""
	if id, idErr := node.NewIdentityProvider(store).Get(ctx); idErr == nil {
		rootCN = console.RootCN(id)
	}
	rst := nodeResetter{
		rootCN:     rootCN,
		device:     dev,
		clearStage: realESPStageAccessors().stageDeleter,
		reboot: func() {
			// Reboot off the RPC goroutine after a short grace period so
			// the ResetResponse flushes before the connection drops.
			go func() {
				time.Sleep(resetRebootDelay)
				rebootNode()
			}()
		},
	}
	localCfg := baseCfg()
	localCfg.Resetter = rst
	localCfg.SubordinateSigner = caSigner
	localCfg.LeafSigner = caSigner
	localCfg.SubordinateEnroller = subEnroller
	localCfg.Trust = trust
	_ = os.Remove(LocalSocketPath)
	localSrv, err := cgrpc.NewLocal(localCfg)
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
	mtlsCfg.SubordinateSigner = caSigner
	mtlsCfg.LeafSigner = caSigner
	mtlsCfg.SubordinateEnroller = subEnroller
	mtlsCfg.Trust = trust
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

	done()
	log.Printf("listeners up: mTLS=%s local=%s first_boot=%t", addr, LocalSocketPath, firstBoot)

	// 13. Supervise the console dashboard now that the listeners are up. It
	// polls the local socket and redraws the node status frame. A console crash
	// is non-critical: superviseConsole restarts it and never returns an error
	// that would reboot a serving CA.
	go superviseConsole(ctx)

	// 14. Park until a shutdown signal; PID 1 then returns and reboots.
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
