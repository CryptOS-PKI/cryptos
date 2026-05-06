# cryptos

The OS / engine for [CryptOS-PKI](https://github.com/CryptOS-PKI) — an immutable, API-driven, high-assurance PKI operating system in the Talos Linux mold.

Builds the UKI (Unified Kernel Image): hardened kernel + Go-based PID 1 + read-only SquashFS + TPM-unsealed encrypted state partition. A single image boots into either **Root CA** or **Issuing CA** role based on its machine config. No SSH, no shell, no interactive access — every operation flows through an mTLS-authenticated gRPC API. Private keys are TPM-bound and never live on disk in the clear.

## Status

Pre-alpha. See [Build phases](https://github.com/CryptOS-PKI) in the org overview for the rollout plan.

## Companion repos

- [`api`](https://github.com/CryptOS-PKI/api) — shared `.proto` definitions and generated gRPC code.
- [`manager`](https://github.com/CryptOS-PKI/manager) — Fleet Manager web control plane.
