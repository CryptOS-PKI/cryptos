package node

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
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// IdentityProvider adapts a Store to the grpc.Identity interface.
type IdentityProvider struct {
	store *Store
}

// NewIdentityProvider returns an IdentityProvider over store.
func NewIdentityProvider(store *Store) *IdentityProvider {
	return &IdentityProvider{store: store}
}

// Get returns the node's Identity, or ErrNoIdentity before the ceremony
// has committed. The gRPC layer maps the error to FAILED_PRECONDITION.
func (p *IdentityProvider) Get(ctx context.Context) (*cryptosv1.Identity, error) {
	return p.store.Identity(ctx)
}

// StatusConfig configures a StatusProvider. Store and Role are required;
// the health functions are optional and default to OK when nil.
type StatusConfig struct {
	// Store reads phase + boot count.
	Store *Store
	// Role is the node's configured role.
	Role cryptosv1.NodeRole
	// SoftwareVersion is the running build's version string.
	SoftwareVersion string
	// TPMState reports live TPM health; nil defaults to TPM_STATE_OK.
	TPMState func() cryptosv1.TpmState
	// EtcdState reports live datastore health; nil defaults to ETCD_STATE_OK.
	EtcdState func() cryptosv1.EtcdState
}

// StatusProvider adapts a Store + live health probes to grpc.StatusProvider.
type StatusProvider struct {
	cfg StatusConfig
}

// NewStatusProvider returns a StatusProvider. Returns an error if Store
// is nil.
func NewStatusProvider(cfg StatusConfig) (*StatusProvider, error) {
	if cfg.Store == nil {
		return nil, errors.New("node: NewStatusProvider: Store is required")
	}
	return &StatusProvider{cfg: cfg}, nil
}

// Status builds the live NodeStatus.
func (p *StatusProvider) Status(ctx context.Context) (*cryptosv1.NodeStatus, error) {
	phase, err := p.cfg.Store.Phase(ctx)
	if err != nil {
		return nil, err
	}
	bootCount, err := p.cfg.Store.BootCount(ctx)
	if err != nil {
		return nil, err
	}
	tpmState := cryptosv1.TpmState_TPM_STATE_OK
	if p.cfg.TPMState != nil {
		tpmState = p.cfg.TPMState()
	}
	etcdState := cryptosv1.EtcdState_ETCD_STATE_OK
	if p.cfg.EtcdState != nil {
		etcdState = p.cfg.EtcdState()
	}
	return &cryptosv1.NodeStatus{
		Role:            p.cfg.Role,
		IdentityState:   phase.IdentityState(),
		TpmState:        tpmState,
		EtcdState:       etcdState,
		BootCount:       bootCount,
		SoftwareVersion: p.cfg.SoftwareVersion,
		// Thin M4: no Fleet Manager endpoint concept yet, so a node is not
		// enrolled. The real connected/disconnected signal arrives with the
		// future Fleet Manager enrollment spec.
		FleetManager: cryptosv1.FleetManagerState_FLEET_MANAGER_STATE_NOT_ENROLLED,
	}, nil
}

// ConfigStore adapts a config.FileStore to the grpc.ConfigStore interface.
type ConfigStore struct {
	fs *config.FileStore
}

// NewConfigStore returns a ConfigStore backed by fs.
func NewConfigStore(fs *config.FileStore) *ConfigStore {
	return &ConfigStore{fs: fs}
}

// Current returns the node's currently persisted machine config, parsed and
// converted to its proto representation. It returns an error if no config
// has been written yet: SetManagement (the only caller today) is a
// read-modify-write over an existing config and has nothing to merge into
// before the first ApplyConfig/install has persisted one.
func (c *ConfigStore) Current(ctx context.Context) (*cryptosv1.MachineConfig, error) {
	raw, _, ok, err := c.fs.Read()
	if err != nil {
		return nil, fmt.Errorf("node: Current: %w", err)
	}
	if !ok {
		return nil, errors.New("node: Current: no config persisted yet")
	}
	parsed, err := config.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("node: Current: parse: %w", err)
	}
	return parsed.ToProto(), nil
}

// Apply converts cfg to YAML, validates it, persists it via the FileStore,
// and returns the new generation, digest, and whether a reboot is required.
//
// A config that fails the schema rules is rejected with codes.InvalidArgument
// and nothing is written: the store's generation and contents are unchanged.
// This is a live CA, so fail closed -- profiles are read live for signing, and
// everything else is only checked again by config.Parse on the next boot.
func (c *ConfigStore) Apply(ctx context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	if cfg == nil {
		return nil, status.Error(codes.InvalidArgument, "node: Apply: nil config")
	}
	parsed, err := config.FromProto(cfg)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node: Apply: %v", err)
	}

	// Read the current config before anything is written. It serves two
	// purposes: carrying forward what the proto cannot express, and
	// classifying whether the change needs a reboot.
	//
	// Classify BEFORE overwriting: a change limited to the hot-reconfigurable
	// fields (cert profiles, root-leaf-issuance acknowledgement) takes effect
	// live for signing, so the caller need not reboot. Any other change — or a
	// first apply with no prior config — requires a reboot. Fail safe to reboot
	// if the current config cannot be read or parsed.
	requiresReboot := true
	if oldRaw, _, ok, rerr := c.fs.Read(); rerr == nil && ok {
		if oldCfg, perr := config.Parse(oldRaw); perr == nil {
			// MachineConfig has no acme or est field, so a config built from a
			// proto has neither. Writing that as the whole config disabled the
			// protocols the node was serving (#205), which any Fleet
			// Manager-driven apply would do.
			parsed.CarryForwardProtoGaps(oldCfg)
			requiresReboot = config.NeedsReboot(oldCfg, parsed)
		}
	}

	// Validate exactly what will be written: after the carry-forward, so a
	// carried ACME or EST block is checked against the incoming profiles, and
	// before anything touches the store.
	if err := parsed.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node: Apply: validate: %v", err)
	}

	raw, err := parsed.Marshal()
	if err != nil {
		return nil, fmt.Errorf("node: Apply: marshal: %w", err)
	}

	gen, err := c.fs.Write(raw)
	if err != nil {
		return nil, fmt.Errorf("node: Apply: persist: %w", err)
	}
	digest := sha256.Sum256(raw)
	return &cryptosv1.ApplyConfigResponse{
		Generation:     gen,
		RequiresReboot: requiresReboot,
		ConfigDigest:   digest[:],
	}, nil
}
