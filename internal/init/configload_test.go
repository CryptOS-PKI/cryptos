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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// validConfigYAMLForInit returns a minimal valid Phase 1 MachineConfig YAML
// suitable for use in the init package tests. It mirrors the helper in
// internal/config/config_test.go but lives here because test helpers are not
// exported across packages.
func validConfigYAMLForInit(t *testing.T) []byte {
	t.Helper()
	pemCert := selfSignedCertPEMForInit(t)
	var b bytes.Buffer
	b.WriteString(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata:
  name: ca-east-1
role:
  kind: root
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
bootstrap:
  admin_cert_pem: |
`)
	for _, line := range strings.Split(strings.TrimRight(pemCert, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	b.WriteString(`pki:
  root_key_alg: ECDSA-P384
  root_subject:
    common_name: "CryptOS Root CA — Acme Corp"
    organization: "Acme Corp"
    country: "US"
  root_validity_years: 20
  path_len_constraint: 2
`)
	return b.Bytes()
}

func selfSignedCertPEMForInit(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// noStage is a convenience zero-value espStageAccessors used by tests that do
// not exercise the ESP-stage path.
var noStage = espStageAccessors{}

func TestLoadOrSeedConfig_SeedsOnFirstBoot(t *testing.T) {
	dir := t.TempDir()
	baked := filepath.Join(t.TempDir(), "machine.yaml")
	raw := validConfigYAMLForInit(t)
	if err := os.WriteFile(baked, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	store := config.NewFileStore(dir)
	cfg, err := loadOrSeedConfig(store, baked, true, noStage)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil cfg")
	}
	if _, _, ok, _ := store.Read(); !ok {
		t.Error("first boot should persist the seed to the store")
	}
}

func TestLoadOrSeedConfig_ReadsPersisted(t *testing.T) {
	dir := t.TempDir()
	store := config.NewFileStore(dir)
	raw := validConfigYAMLForInit(t)
	if _, err := store.Write(raw); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOrSeedConfig(store, "/nonexistent", false, noStage)
	if err != nil || cfg == nil {
		t.Fatalf("read persisted: cfg=%v err=%v", cfg, err)
	}
}

func TestLoadOrSeedConfig_MissingOnInstalled_Maintenance(t *testing.T) {
	store := config.NewFileStore(t.TempDir())
	_, err := loadOrSeedConfig(store, "/nonexistent", false, noStage)
	if !errors.Is(err, errEnterMaintenance) {
		t.Errorf("err = %v, want errEnterMaintenance", err)
	}
}

func TestLoadOrSeedConfig_CorruptPersisted_Maintenance(t *testing.T) {
	dir := t.TempDir()
	// Deliberately bypass FileStore.Write (which validates) to plant a corrupt
	// config on disk. This couples to FileStore's on-disk layout (the
	// machine.yaml + generation filenames); keep in sync if those change.
	if err := os.WriteFile(filepath.Join(dir, "machine.yaml"), []byte("garbage: ["), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "generation"), []byte("1\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	_, err := loadOrSeedConfig(config.NewFileStore(dir), "/nonexistent", false, noStage)
	if !errors.Is(err, errEnterMaintenance) {
		t.Errorf("err = %v, want errEnterMaintenance", err)
	}
}

// --- ESP stage tests --------------------------------------------------------

// fakeESPStage returns an espStageAccessors backed by a fake in-memory stage.
// The stageRaw bytes are returned as present when non-nil; deleted is set to
// true when stageDeleter is called. Pass nil stageRaw to simulate no stage.
func fakeESPStage(t *testing.T, stageRaw []byte) (espStageAccessors, *bool) {
	t.Helper()
	deleted := new(bool)
	return espStageAccessors{
		stageReader: func() ([]byte, bool, error) {
			if stageRaw == nil {
				return nil, false, nil
			}
			return stageRaw, true, nil
		},
		stageDeleter: func() error {
			*deleted = true
			return nil
		},
	}, deleted
}

// TestLoadOrSeedConfig_StagePresent_NoPersisted verifies that when no persisted
// config exists and an ESP stage is present, loadOrSeedConfig persists it to the
// store, returns the parsed config, and calls the deleter.
func TestLoadOrSeedConfig_StagePresent_NoPersisted(t *testing.T) {
	raw := validConfigYAMLForInit(t)
	store := config.NewFileStore(t.TempDir())
	stage, deleted := fakeESPStage(t, raw)

	cfg, err := loadOrSeedConfig(store, "/nonexistent", false, stage)
	if err != nil {
		t.Fatalf("stage seed: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil cfg")
	}
	if !*deleted {
		t.Error("stage deleter was not called after successful persist")
	}
	if _, _, ok, _ := store.Read(); !ok {
		t.Error("ESP stage config was not persisted to the store")
	}
}

// TestLoadOrSeedConfig_StagePresent_NotFirstBoot verifies the crash-safe path:
// a node that has been installed (firstBoot=false) but lost its persisted config
// (crash between format and persist) re-seeds from the ESP stage, not
// errEnterMaintenance.
func TestLoadOrSeedConfig_StagePresent_NotFirstBoot(t *testing.T) {
	raw := validConfigYAMLForInit(t)
	store := config.NewFileStore(t.TempDir())
	stage, deleted := fakeESPStage(t, raw)

	cfg, err := loadOrSeedConfig(store, "/nonexistent", false, stage)
	if err != nil {
		t.Fatalf("crash-retry seed: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil cfg")
	}
	if !*deleted {
		t.Error("stage deleter was not called")
	}
}

// TestLoadOrSeedConfig_StageAbsent_FirstBoot_BakedFallback confirms that when
// no ESP stage is present but firstBoot is true, the baked-file fallback still
// seeds correctly (backward compatibility until Task 8 removes it).
func TestLoadOrSeedConfig_StageAbsent_FirstBoot_BakedFallback(t *testing.T) {
	raw := validConfigYAMLForInit(t)
	baked := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(baked, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	store := config.NewFileStore(t.TempDir())
	stage, _ := fakeESPStage(t, nil) // no stage

	cfg, err := loadOrSeedConfig(store, baked, true, stage)
	if err != nil {
		t.Fatalf("baked fallback: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil cfg")
	}
	if _, _, ok, _ := store.Read(); !ok {
		t.Error("baked config was not persisted to the store")
	}
}

// TestLoadOrSeedConfig_StageAbsent_NotFirstBoot_Maintenance confirms that when
// there is no stage and no persisted config on an installed node,
// errEnterMaintenance is returned.
func TestLoadOrSeedConfig_StageAbsent_NotFirstBoot_Maintenance(t *testing.T) {
	store := config.NewFileStore(t.TempDir())
	stage, _ := fakeESPStage(t, nil) // no stage

	_, err := loadOrSeedConfig(store, "/nonexistent", false, stage)
	if !errors.Is(err, errEnterMaintenance) {
		t.Errorf("err = %v, want errEnterMaintenance", err)
	}
}
