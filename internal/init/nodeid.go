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
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
)

// productUUIDPath is the sysfs DMI node exposing the platform (SMBIOS) UUID.
// CONFIG_DMI + CONFIG_DMIID create it; it is root-readable only.
const productUUIDPath = "/sys/class/dmi/id/product_uuid"

// zeroUUID is the all-zeros SMBIOS UUID some firmware reports when unset; it is
// not node-unique, so it must be rejected as a key source.
const zeroUUID = "00000000-0000-0000-0000-000000000000"

// nodeIDInfo binds the derived key to this purpose and version. Changing it
// would change every derived key (a deliberate, breaking migration).
const nodeIDInfo = "cryptos-state-nodeid-v1"

// readProductUUID returns the trimmed platform UUID from sysfs.
func readProductUUID() (string, error) {
	b, err := os.ReadFile(productUUIDPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", productUUIDPath, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// nodeIDProtector derives the LUKS key deterministically from the node's SMBIOS
// UUID (Talos-style nodeID). No TPM, no token, no persisted key material for
// the state key. Dev tier: a UUID is not secret, so this binds state to the
// node, not confidentiality against a determined attacker.
type nodeIDProtector struct {
	readUUID func() (string, error)
	label    string
}

func newNodeIDProtector(readUUID func() (string, error), label string) *nodeIDProtector {
	return &nodeIDProtector{readUUID: readUUID, label: label}
}

func (p *nodeIDProtector) Name() string        { return "nodeid" }
func (p *nodeIDProtector) PersistsToken() bool { return false }

// deriveKey computes the 32-byte LUKS key: HMAC-SHA256 keyed by the UUID over
// the info + partition label. Deterministic across boots and upgrades because
// the UUID is stable.
func (p *nodeIDProtector) deriveKey() ([]byte, error) {
	uuid, err := p.readUUID()
	if err != nil {
		return nil, fmt.Errorf("nodeid: %w", err)
	}
	if uuid == "" || strings.EqualFold(uuid, zeroUUID) {
		return nil, errors.New("nodeid: platform UUID is empty or all-zeros; cannot derive a state key")
	}
	mac := hmac.New(sha256.New, []byte(uuid))
	mac.Write([]byte(nodeIDInfo + ":" + p.label))
	return mac.Sum(nil), nil // 32 bytes (stateKeyBytes)
}

func (p *nodeIDProtector) ProvisionKey(_ context.Context) (key, token []byte, err error) {
	key, err = p.deriveKey()
	if err != nil {
		return nil, nil, err
	}
	return key, nil, nil
}

func (p *nodeIDProtector) RecoverKey(_ context.Context, _ []byte) ([]byte, error) {
	return p.deriveKey()
}
