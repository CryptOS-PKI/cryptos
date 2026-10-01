package node

/*
Copyright The CryptOS Authors.

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
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// The Fleet Manager switches a protocol by reading the config, flipping
// enabled and applying it back. Off keeps the block's settings on the node, so
// the same flip switches it back on, with the secret kept and never returned.
func TestConfigStoreApply_SwitchOffAndBackOnFromReadBack(t *testing.T) {
	ctx := context.Background()
	fs, cs := seededStore(t, protocolsOffSeed)
	pb := storedConfig(t, fs).ToProto()
	pb.Pki.Acme = acmeOn()
	if _, err := cs.Apply(ctx, pb); err != nil {
		t.Fatalf("Apply (ACME on): %v", err)
	}

	// Off, from the read-back.
	current, err := cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	current.Pki.Acme.Enabled = false
	resp, err := cs.Apply(ctx, current)
	if err != nil {
		t.Fatalf("Apply (ACME off from the read-back): %v", err)
	}
	if !resp.GetRequiresReboot() {
		t.Error("switching ACME off did not answer requires_reboot")
	}
	if stored := storedConfig(t, fs); stored.PKI.ACME != nil {
		t.Fatalf("ACME is still on after switching it off: %+v", stored.PKI.ACME)
	}

	current, err = cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	a := current.GetPki().GetAcme()
	if a.GetEnabled() || a.GetBaseUrl() != "https://ca.example.org/acme" || a.GetProfile() != "leaf-server" {
		t.Fatalf("GetConfig of a switched-off ACME = %v, want enabled=false with its settings", a)
	}
	if keys := a.GetExternalAccountKeys(); len(keys) != 1 || keys[0].GetKeyId() != "ops" || keys[0].GetHmacKeyBase64() != "" {
		t.Errorf("GetConfig of a switched-off ACME returned keys %v, want key_id ops with the secret blank", keys)
	}

	// Back on, from the read-back, flipping enabled only.
	current.Pki.Acme.Enabled = true
	resp, err = cs.Apply(ctx, current)
	if err != nil {
		t.Fatalf("Apply (ACME on from the read-back): %v", err)
	}
	if !resp.GetRequiresReboot() {
		t.Error("switching ACME back on did not answer requires_reboot")
	}
	stored := storedConfig(t, fs)
	if stored.PKI.ACME == nil || stored.PKI.ACME.BaseURL != "https://ca.example.org/acme" ||
		stored.PKI.ACME.ExternalAccountKeys[0].HMACKeyBase64 != testEABKey {
		t.Fatalf("stored ACME after switching back on = %+v, want the block with its secret", stored.PKI.ACME)
	}
}

func TestConfigStoreApply_ESTSwitchOnFromReadBack(t *testing.T) {
	ctx := context.Background()
	fs, cs := seededStore(t, protocolsOffSeed)
	pb := storedConfig(t, fs).ToProto()
	pb.Pki.Est = &nodev1.Est{
		Enabled:   false,
		Hostnames: []string{"est.example.org"},
		Profile:   "leaf-server",
		Label:     "devices",
	}
	resp, err := cs.Apply(ctx, pb)
	if err != nil {
		t.Fatalf("Apply (EST settings, off): %v", err)
	}
	if resp.GetRequiresReboot() {
		t.Error("storing the settings of an EST block that stays off asked for a reboot")
	}

	current, err := cs.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if e := current.GetPki().GetEst(); e.GetEnabled() || e.GetProfile() != "leaf-server" || e.GetLabel() != "devices" {
		t.Fatalf("GetConfig of an off EST block = %v, want its settings with enabled=false", e)
	}
	current.Pki.Est.Enabled = true
	if _, err := cs.Apply(ctx, current); err != nil {
		t.Fatalf("Apply (EST on from the read-back): %v", err)
	}
	if stored := storedConfig(t, fs); stored.PKI.EST == nil || stored.PKI.EST.Label != "devices" {
		t.Fatalf("stored EST after switching on = %+v, want the block", stored.PKI.EST)
	}
}

// An off block is not a configured protocol.
func TestStatusProviderOffBlockIsNotConfigured(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	fs, cs := seededStore(t, protocolsOffSeed)
	pb := storedConfig(t, fs).ToProto()
	pb.Pki.Acme = acmeOn()
	pb.Pki.Acme.Enabled = false
	if _, err := cs.Apply(ctx, pb); err != nil {
		t.Fatalf("Apply (ACME settings, off): %v", err)
	}
	sp, err := NewStatusProvider(StatusConfig{
		Store:           s,
		Role:            nodev1.NodeRole_NODE_ROLE_ISSUING,
		BootConfig:      storedConfig(t, fs),
		ConfigFile:      fs,
		ProtocolRunning: func(nodev1.ServiceProtocol) bool { return false },
	})
	if err != nil {
		t.Fatalf("NewStatusProvider: %v", err)
	}
	st, err := sp.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if acme := protocolState(t, st, nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME); acme.GetConfigured() || acme.GetRebootPending() {
		t.Errorf("an off ACME block with settings reports %v, want not configured and nothing pending", acme)
	}
}
