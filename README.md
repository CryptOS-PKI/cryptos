# cryptos 🧠

> 🔐 The OS / engine for [CryptOS-PKI](https://github.com/CryptOS-PKI) — an immutable, API-driven, high-assurance PKI operating system in the Talos Linux tradition.

Builds a signed Unified Kernel Image (UKI): hardened kernel + Go-based PID 1 + read-only SquashFS rootfs + TPM-unsealed encrypted state partition. A single image boots into a Root, Intermediate, or Issuing CA role based on its machine config. No SSH, no shell, no interactive access. Private keys are TPM-bound and never live on disk in the clear.

## ✨ Architecture at a glance

- 🪨 **Immutable rootfs** — SquashFS, read-only. Persistent state only on the encrypted partition, unsealed by the local TPM.
- 🔑 **TPM-bound identity** — CA private keys are created inside the TPM and never leave it. ECDSA P-384 for Roots, P-256 for Issuing CAs.
- 🚫 **No interactive access** — no SSH, no shell, no usernames/passwords. **No web frontend in the image either.** Management is `cryptosctl` over mTLS gRPC, or the Fleet Manager (which talks the same mTLS gRPC).
- 📐 **RFC-strict** — TLS 1.3 (RFC 8446), X.509 (RFC 5280), and every protocol adapter follows its RFC to the letter.
- 📜 **Declarative** — machine config in YAML (`apiVersion: cryptos.dev/v1alpha1`), applied via `ApplyConfig`. No click-ops.
- 🧪 **Stdlib-only on the cert path** — `crypto/x509`, `crypto/tls`, `crypto/ecdsa`, `crypto/rand`, `golang.org/x/crypto`. No `cfssl`, no `smallstep`, no PKI wrappers — ever.

## 📂 Layout

```
cmd/
  init/             # PID 1 binary; becomes /init in the SquashFS
  cryptosctl/       # operator CLI (the only management surface on a standalone node)
  cryptos-install/  # bare-metal disk installer (GPT + ESP + UKI)
  cryptos-sbkey/    # Secure Boot signing key + cert generator (for db enrollment)
  cryptos-switchroot/ # shim /init: loop-mounts the SquashFS root and pivots into it
internal/
  init/             # supervisor + boot bring-up
    netlink/        # NIC bring-up via rtnetlink
    mounts/         # early mount sequence
  tpm/              # go-tpm wrapper, SRK provisioning, crypto.Signer impl
  ca/               # RFC 5280 cert template builder
  ceremony/         # first-boot ceremony state machine
  storage/
    luks/           # TPM-sealed LUKS2 open/format
    etcd/           # embedded etcd config + schema
  grpc/             # mTLS gRPC server, RPC handlers
  node/             # typed etcd state layer + gRPC Identity/Status/Config providers
  install/          # bare-metal disk provisioning (partition plan + UKI install)
  switchroot/       # SquashFS-root pivot sequence (loop-mount + switch_root)
  audit/            # hash-chained audit log
  config/           # machine config parser + validator
  bootstrap/        # bootstrap admin cert loading + first-ceremony rotation
build/              # kernel config, UKI assembly recipes, SquashFS templates
testdata/configs/   # sample machine configs
```

## 🛠️ Build + run (dev loop)

Requires Go 1.24+, [`go-task`](https://taskfile.dev), `golangci-lint`, `golic`, and (for integration testing) `qemu-system-x86_64` + `swtpm` + OVMF.

```bash
task ci          # fmt + lint + vet + test + build (both binaries)
task build       # produces bin/init and bin/cryptosctl, stamped with the build identity
task license     # re-inject Apache 2.0 headers via golic
```

`bin/cryptosctl version` prints the version, commit, and build date the binary was built from (`git describe --tags --always --dirty`; see [`build/README.md`](build/README.md#build-identity)); pass `--endpoint` to also show the node's version.

The image pipeline (`task image` — hardened kernel build, SquashFS rootfs, UKI assembly + Secure Boot signing) has draft recipes under `build/` that run on a Linux build host; see [`build/README.md`](build/README.md). They are written but not yet executed end to end. The QEMU + `swtpm` integration harness lands in a subsequent PR.

### Bring your own Secure Boot key

CryptOS ships no signing key and trusts none that the project generated. You generate your own RSA Secure Boot key and certificate (with openssl or `cryptos-sbkey`), then build with it:

```bash
export SB_KEY=/path/to/sb.key SB_CERT=/path/to/sb.crt
task image PLATFORM=vmware STATEKEY=nodeid    # or: task iso PLATFORM=vmware STATEKEY=nodeid
```

Keep `SB_CERT` set for the whole run: `rootfs:build` stamps it into the image as the upgrade anchor, and `uki:sign` signs the UKI and writes the detached `.uki.sig` with the same key. A node only stages later images signed by that key, so losing the key means re-provisioning to change anchors. Enroll the certificate in firmware `db` (vSphere, firmware UI, `sbctl`, or `efitools`) to boot with Secure Boot on, or run with Secure Boot off and rely on the stamped anchor for upgrades.

Public release assets are unsigned, or a build recipe only. [`docs/secure-boot.md`](docs/secure-boot.md) is the full guide: key generation, enrollment, building, verifying with `sbverify` and openssl, upgrades, and key custody.

## 🤖 Continuous integration

GitHub Actions:

- **`ci-go`** ([`ci-go.yml`](.github/workflows/ci-go.yml)) — `task ci` (format, lint, vet, test, build) on every pull request + push to `main`, on a GitHub-hosted Linux runner.
- **`ci-image`** ([`ci-image.yml`](.github/workflows/ci-image.yml)) — builds the UKI on a **GitHub-hosted runner** (amd64 on `ubuntu-latest`, arm64 on `ubuntu-24.04-arm`), installing the kernel / `ukify` / `sbsign` toolchain per run. Runs on push to `main`, tags, and manual dispatch; use `workflow_dispatch` on a branch to validate image changes before merging.

The QEMU + `swtpm` integration boot is run on a real host by the operator, not in CI.

## 🔑 Management surfaces

A CA node has exactly two ways to be managed:

| | When | What |
|---|---|---|
| `cryptosctl` | Always — and the **only** option on a standalone (unlinked) node. | Local UNIX socket on the node for break-glass; remote mTLS gRPC for everything else. |
| Fleet Manager | Optional. When you want a web UI or multi-node view. | The `manager/` backend serves the `web/` frontend; talks to nodes via the same mTLS gRPC API. |

There is no third surface. The OS image ships no web frontend — neither source nor compiled — by design.

Remote `cryptosctl` pins the node's management certificate with `--trust`. That certificate is self-signed and regenerated on every boot, so a CA certificate does not verify it and a pin goes stale on reboot. [`docs/management-trust.md`](docs/management-trust.md) covers fetching and refreshing it.

An intermediate can get a fresh certificate for the key it already holds, for example one that carries CRL, OCSP and caIssuers pointers after the parent's `revocation_base_url` was set: `cryptosctl ca get-renewal-csr`, `ca sign-subordinate` on the parent, then `ca submit-renewed-cert`. No re-key and no reboot. [`docs/subordinate-recertify.md`](docs/subordinate-recertify.md) has the procedure and the openssl checks.

Issuing LDAPS and KDC certificates to Active Directory domain controllers, including `certreq` on Server Core, is covered in [`docs/active-directory.md`](docs/active-directory.md).

### Rebooting or powering off a node

Most `config apply` changes report `requires_reboot=true`. Restart the node through its orderly shutdown rather than a hypervisor hard reset:

```sh
cryptosctl --endpoint pki-root.example:443 reboot --confirm "Example Root CA G1"
cryptosctl --endpoint pki-root.example:443 reboot --confirm "Example Root CA G1" --power-off
```

`--confirm` must be the node's CA common name, and over mTLS the call needs the bootstrap admin client certificate. The node replies, then stops its listeners, closes etcd and the audit log, unmounts and locks the state volume, and restarts (or powers off). A hard reset skips all of that. The management certificate is regenerated on every boot, so refresh a `--trust` pin afterwards.

The same orderly shutdown also runs, without the API, when:

- the ACPI power button is pressed (a hypervisor guest shutdown that goes through ACPI, such as `virsh shutdown`). The node **powers off**.
- Ctrl-Alt-Del reaches the console (for example, the vSphere console's "Send Ctrl+Alt+Delete"; the VMware image carries the PS/2 keyboard driver for this). The node **reboots**.
- PID 1 receives `SIGTERM` or `SIGINT`. The node **reboots**.

The image ships no guest tools, so a vSphere "Shut Down Guest OS" or "Restart Guest OS" request is not available. Use `cryptosctl reboot`, or the console's Ctrl+Alt+Delete.

## 🚦 Status

**Pre-alpha.** Phase 1 scaffolding has landed; subsystem implementation is in progress.

1. 🪨 **Phase 1 — Core OS + single-node Root CA MVP.** Boot a UKI in QEMU + `swtpm`, generate a TPM-resident ECDSA P-384 Root key, self-sign an RFC 5280-strict Root cert, validate via `cryptosctl`.
2. 🔌 **Phase 2 — Role-aware API + protocol adapters + Fleet Manager.** Root / Intermediate / Issuing role split, ACME / SCEP / EST / WSTEP / RFC 3161 / OCSP / CRL.
3. 🛡️ **Phase 3 — Pool, HA, extensions, isolation, recovery.** 2-node HA pairs (Infoblox-style failover, VRRPv3 VIP), multi-Root topology (configurable depth, default cap 3), Fleet Manager linkage protocol, Talos-style signed late-binding extensions, disaster-recovery escrow.

## 🧭 Companion repos

- 📡 [`api`](https://github.com/CryptOS-PKI/api) — shared `.proto` definitions and generated gRPC stubs.
- 🛰️ [`manager`](https://github.com/CryptOS-PKI/manager) — Fleet Manager backend (optional).
- 🎨 [`web`](https://github.com/CryptOS-PKI/web) — Fleet Manager web frontend (optional, served by `manager/`).

## 📄 License

[Apache License 2.0](LICENSE). Copyright 2026 Shane.
