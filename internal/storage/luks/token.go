package luks

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
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// TPM2TokenType is the LUKS2 token type string for the CryptOS-native
// TPM-sealed-key token. CryptOS writes and reads this token with its own
// TPM unseal path (internal/tpm) and never invokes systemd-cryptsetup, so
// it deliberately does NOT claim the systemd-tpm2 type — see the design
// notes. byte-level systemd interop can be added later if needed.
const TPM2TokenType = "cryptos-tpm2"

// PCRBankSHA256 is the only PCR bank Phase 1 uses.
const PCRBankSHA256 = "sha256"

// TPM2Token is the JSON token stored in the LUKS2 header that records the
// TPM-sealed volume key. The sealed material is recovered by
// tpm.UnsealWithPCR, not by any third-party tool.
type TPM2Token struct {
	// Type is always TPM2TokenType.
	Type string `json:"type"`
	// Keyslots lists the LUKS keyslots this token unlocks (LUKS2 requires
	// keyslot references to be decimal strings).
	Keyslots []string `json:"keyslots"`
	// Blob is the base64 of the TPM2B-framed sealed private||public blobs.
	Blob string `json:"tpm-blob"`
	// PCRs is the PCR set the key is sealed to (e.g. [7, 11]).
	PCRs []int `json:"tpm-pcrs"`
	// PCRBank is the PCR bank hash algorithm (Phase 1: "sha256").
	PCRBank string `json:"tpm-pcr-bank"`
	// PolicyHash is the hex PolicyPCR digest, informational; unseal
	// recomputes the policy from current PCRs. Omitted when unknown.
	PolicyHash string `json:"tpm-policy-hash,omitempty"`
}

// BuildTPM2Token assembles a token from the sealed blobs produced by
// tpm.SealToPCR. private and public must be the TPM2B-framed marshalings
// (each prefixed by its own 2-byte size), so the concatenation can be
// split again by SealedBlobs. policyHash may be nil.
func BuildTPM2Token(private, public []byte, keyslot int, pcrs []int, policyHash []byte) (*TPM2Token, error) {
	if len(private) < 2 {
		return nil, errors.New("luks: BuildTPM2Token: private blob is empty or unframed")
	}
	if len(public) == 0 {
		return nil, errors.New("luks: BuildTPM2Token: public blob is empty")
	}
	if keyslot < 0 {
		return nil, fmt.Errorf("luks: BuildTPM2Token: keyslot must be >= 0, got %d", keyslot)
	}
	if len(pcrs) == 0 {
		return nil, errors.New("luks: BuildTPM2Token: no PCRs")
	}
	blob := make([]byte, 0, len(private)+len(public))
	blob = append(blob, private...)
	blob = append(blob, public...)

	t := &TPM2Token{
		Type:     TPM2TokenType,
		Keyslots: []string{strconv.Itoa(keyslot)},
		Blob:     base64.StdEncoding.EncodeToString(blob),
		PCRs:     append([]int(nil), pcrs...),
		PCRBank:  PCRBankSHA256,
	}
	if len(policyHash) > 0 {
		t.PolicyHash = hex.EncodeToString(policyHash)
	}
	return t, nil
}

// SealedBlobs splits the token's blob back into the TPM2B-framed private
// and public blobs for tpm.UnsealWithPCR. It reads the 2-byte big-endian
// size word that prefixes the private TPM2B to find the boundary.
func (t *TPM2Token) SealedBlobs() (private, public []byte, err error) {
	raw, err := base64.StdEncoding.DecodeString(t.Blob)
	if err != nil {
		return nil, nil, fmt.Errorf("luks: SealedBlobs: base64: %w", err)
	}
	if len(raw) < 2 {
		return nil, nil, errors.New("luks: SealedBlobs: blob too short")
	}
	privLen := int(binary.BigEndian.Uint16(raw[:2]))
	end := 2 + privLen
	if end > len(raw) {
		return nil, nil, fmt.Errorf("luks: SealedBlobs: private size %d exceeds blob length %d", privLen, len(raw))
	}
	if end == len(raw) {
		return nil, nil, errors.New("luks: SealedBlobs: no public blob after private")
	}
	private = append([]byte(nil), raw[:end]...)
	public = append([]byte(nil), raw[end:]...)
	return private, public, nil
}

// MarshalJSON ensures the Type is always set correctly on output.
func (t *TPM2Token) MarshalJSON() ([]byte, error) {
	type alias TPM2Token
	c := alias(*t)
	c.Type = TPM2TokenType
	return json.Marshal(c)
}

// ParseTPM2Token parses a token JSON and validates its type.
func ParseTPM2Token(data []byte) (*TPM2Token, error) {
	var t TPM2Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("luks: ParseTPM2Token: %w", err)
	}
	if t.Type != TPM2TokenType {
		return nil, fmt.Errorf("luks: ParseTPM2Token: type %q, want %q", t.Type, TPM2TokenType)
	}
	if t.Blob == "" {
		return nil, errors.New("luks: ParseTPM2Token: empty tpm-blob")
	}
	return &t, nil
}

// ImportToken writes a token JSON into the LUKS2 header at the given token
// id via `cryptsetup token import`. The JSON is passed on stdin.
func (d *Device) ImportToken(ctx context.Context, tokenID int, tokenJSON []byte) error {
	if d == nil || d.Path == "" {
		return errors.New("luks: ImportToken: device path is required")
	}
	if d.Runner == nil {
		return errors.New("luks: ImportToken: Runner is required")
	}
	if len(tokenJSON) == 0 {
		return errors.New("luks: ImportToken: empty token JSON")
	}
	args := []string{"token", "import", "--token-id", strconv.Itoa(tokenID), d.Path}
	_, stderr, err := d.Runner.Run(ctx, bytes.NewReader(tokenJSON), args...)
	if err != nil {
		return fmt.Errorf("luks: ImportToken: cryptsetup failed: %w (stderr: %s)", err, bytes.TrimSpace(stderr))
	}
	return nil
}

// ExportToken reads token <id> from the LUKS2 header via `cryptsetup
// token export`, returning the token JSON.
func (d *Device) ExportToken(ctx context.Context, tokenID int) ([]byte, error) {
	if d == nil || d.Path == "" {
		return nil, errors.New("luks: ExportToken: device path is required")
	}
	if d.Runner == nil {
		return nil, errors.New("luks: ExportToken: Runner is required")
	}
	args := []string{"token", "export", "--token-id", strconv.Itoa(tokenID), d.Path}
	stdout, stderr, err := d.Runner.Run(ctx, nil, args...)
	if err != nil {
		return nil, fmt.Errorf("luks: ExportToken: cryptsetup failed: %w (stderr: %s)", err, bytes.TrimSpace(stderr))
	}
	return stdout, nil
}
