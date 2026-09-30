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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/kms"
	"github.com/CryptOS-PKI/cryptos/internal/storage/luks"
)

const testKMSEndpoint = "https://kms.example"

// headerRunner is an in-memory LUKS2 device: it answers the cryptsetup
// subcommands the state-volume code issues, keeping the key and the token set
// the way a real header would.
type headerRunner struct {
	formatted bool
	key       []byte
	tokens    map[int][]byte
}

func (r *headerRunner) Run(_ context.Context, stdin io.Reader, args ...string) ([]byte, []byte, error) {
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	tokenID := func() int {
		for i, a := range args {
			if a == "--token-id" && i+1 < len(args) {
				id, _ := strconv.Atoi(args[i+1])
				return id
			}
		}
		return -1
	}
	switch {
	case args[0] == "isLuks":
		if !r.formatted {
			return nil, nil, errors.New("not a LUKS device")
		}
		return nil, nil, nil
	case args[0] == "luksFormat":
		r.formatted, r.key, r.tokens = true, in, map[int][]byte{}
		return nil, nil, nil
	case args[0] == "luksOpen":
		if !r.formatted || !bytes.Equal(in, r.key) {
			return nil, []byte("No key available with this passphrase."), errors.New("exit status 2")
		}
		return nil, nil, nil
	case args[0] == "luksDump":
		meta := map[string]map[string]json.RawMessage{"tokens": {}}
		for id, tok := range r.tokens {
			meta["tokens"][strconv.Itoa(id)] = tok
		}
		out, _ := json.Marshal(meta)
		return out, nil, nil
	case args[0] == "token" && args[1] == "import":
		var t struct {
			Type     string   `json:"type"`
			Keyslots []string `json:"keyslots"`
		}
		if json.Unmarshal(in, &t) != nil || t.Type == "" || t.Keyslots == nil {
			return nil, []byte("Failed to import token from file."), errors.New("exit status 1")
		}
		r.tokens[tokenID()] = in
		return nil, nil, nil
	case args[0] == "token" && args[1] == "export":
		tok, ok := r.tokens[tokenID()]
		if !ok {
			return nil, []byte("Token is not in use."), errors.New("exit status 1")
		}
		return tok, nil, nil
	}
	return nil, nil, fmt.Errorf("headerRunner: unexpected cryptsetup %v", args)
}

// testRunner rewrites the production cryptsetup calls so a real LUKS2 header
// in a plain file can stand in for the state partition without root: Format
// uses a cheap PBKDF, and Open only tests the key instead of mapping a device.
type testRunner struct{ exec *luks.ExecRunner }

func (r testRunner) Run(ctx context.Context, stdin io.Reader, args ...string) ([]byte, []byte, error) {
	switch args[0] {
	case "luksFormat":
		out := []string{"luksFormat", "--type", "luks2", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
			"--batch-mode", "--key-file", "-", args[len(args)-1]}
		return r.exec.Run(ctx, stdin, out...)
	case "luksOpen":
		return r.exec.Run(ctx, stdin, "luksOpen", "--test-passphrase", "--key-file", "-", args[len(args)-2])
	}
	return r.exec.Run(ctx, stdin, args...)
}

// memSealer is a TPM stand-in that seals by remembering: the private blob is a
// handle for the sealed data.
type memSealer struct{ sealed map[string][]byte }

func (m *memSealer) ProvisionSRK() error { return nil }

func (m *memSealer) SealToPCR(data []byte, _ []int) ([]byte, []byte, error) {
	if m.sealed == nil {
		m.sealed = map[string][]byte{}
	}
	id := []byte(fmt.Sprintf("sealed-%d", len(m.sealed)))
	priv := append([]byte{0, byte(len(id))}, id...)
	m.sealed[string(priv)] = append([]byte(nil), data...)
	return priv, []byte("public"), nil
}

func (m *memSealer) UnsealWithPCR(priv, _ []byte, _ []int) ([]byte, error) {
	data, ok := m.sealed[string(priv)]
	if !ok {
		return nil, errors.New("memSealer: unknown blob")
	}
	return append([]byte(nil), data...), nil
}

// testBackends builds each mode's protector over fakes: the node UUID, the TPM
// and the KMS. It records the mode and state-key section each boot asked for.
type testBackends struct {
	sealer memSealer
	modes  []string
	keys   []config.StateKey
}

func (b *testBackends) factory(mode string, sk config.StateKey) (StateKeyProtector, ceremony.RootKeyBackend, func(), cryptosv1.TpmState, error) {
	b.modes = append(b.modes, mode)
	b.keys = append(b.keys, sk)
	switch mode {
	case config.StateKeyModeNodeID:
		return newNodeIDProtector(fixedUUID("4c4c4544-0000-1000-8000-000000000001"), StateLabel), softRootBackend{},
			func() {}, cryptosv1.TpmState_TPM_STATE_UNAVAILABLE, nil
	case config.StateKeyModeKMS:
		p, err := newKMSProtector(sk.KMS)
		if err != nil {
			return nil, nil, func() {}, cryptosv1.TpmState_TPM_STATE_UNAVAILABLE, err
		}
		p.newProvider = func(string, []byte) (kms.Provider, error) { return fakeProvider{pad: 0x5a}, nil }
		return p, softRootBackend{}, func() {}, cryptosv1.TpmState_TPM_STATE_UNAVAILABLE, nil
	}
	return newTPMProtector(&b.sealer, []int{7, 11}), nil, func() {}, cryptosv1.TpmState_TPM_STATE_OK, nil
}

func stageYAML(mode string) []byte {
	switch mode {
	case "":
		return []byte("metadata:\n  name: ca\n")
	case config.StateKeyModeKMS:
		return []byte("state_key:\n  mode: kms\n  kms:\n    endpoint: " + testKMSEndpoint + "\n")
	}
	return []byte("state_key:\n  mode: " + mode + "\n")
}

// realStateDevice returns a device backed by a real LUKS2 header in a file, or
// skips when cryptsetup is not available.
func realStateDevice(t *testing.T) *luks.Device {
	t.Helper()
	bin, err := exec.LookPath("cryptsetup")
	if err != nil {
		t.Skip("cryptsetup not on PATH")
	}
	path := filepath.Join(t.TempDir(), "state.img")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create device file: %v", err)
	}
	if err := os.Truncate(path, 32<<20); err != nil {
		t.Fatalf("size device file: %v", err)
	}
	return &luks.Device{Path: path, Runner: testRunner{exec: &luks.ExecRunner{Binary: bin}}}
}

var modeCases = []struct {
	name, buildDefault, configured, want string
}{
	{"tpm image, nodeid configured", config.StateKeyModeTPM, config.StateKeyModeNodeID, config.StateKeyModeNodeID},
	{"nodeid image, tpm configured", config.StateKeyModeNodeID, config.StateKeyModeTPM, config.StateKeyModeTPM},
	{"tpm image, kms configured", config.StateKeyModeTPM, config.StateKeyModeKMS, config.StateKeyModeKMS},
	{"nodeid image, kms configured", config.StateKeyModeNodeID, config.StateKeyModeKMS, config.StateKeyModeKMS},
	{"tpm image, no mode configured", config.StateKeyModeTPM, "", config.StateKeyModeTPM},
	{"nodeid image, no mode configured", config.StateKeyModeNodeID, "", config.StateKeyModeNodeID},
}

// bootAndReboot runs the first boot with the configured mode on the ESP stage,
// then two later boots after the stage is consumed, and checks that every boot
// opens the volume with the configured mode.
func bootAndReboot(t *testing.T, dev *luks.Device, buildDefault, configured, want string) {
	t.Helper()
	ctx := context.Background()
	b := &testBackends{}
	boot := func(stage []byte) *unlockedState {
		t.Helper()
		st, err := stateUnlocker{
			device: dev, stage: espStage(stage), buildDefault: buildDefault, newBackends: b.factory,
		}.unlock(ctx)
		if err != nil {
			t.Fatalf("boot %d: unlock: %v", len(b.modes), err)
		}
		st.close()
		return st
	}

	if st := boot(stageYAML(configured)); !st.firstBoot || st.mode != want {
		t.Fatalf("first boot: firstBoot=%v mode=%q, want true %q", st.firstBoot, st.mode, want)
	}
	for i := 1; i <= 2; i++ {
		if st := boot(nil); st.firstBoot || st.mode != want || st.protector.Name() != want {
			t.Fatalf("reboot %d: firstBoot=%v mode=%q protector=%q, want false %q", i, st.firstBoot, st.mode, st.protector.Name(), want)
		}
	}
	if want == config.StateKeyModeKMS {
		for i, sk := range b.keys[1:] {
			if sk.KMS == nil || sk.KMS.Endpoint != testKMSEndpoint {
				t.Errorf("reboot %d: kms section %+v, want the endpoint the volume was sealed with", i+1, sk.KMS)
			}
		}
	}
}

func espStage(raw []byte) espStageAccessors {
	return espStageAccessors{stageReader: func() ([]byte, bool, error) { return raw, raw != nil, nil }}
}

// A node's configured state-key mode must survive every reboot after the first,
// when the ESP stage that carried it is gone.
func TestStateUnlock_ConfiguredModeSurvivesReboots(t *testing.T) {
	for _, tc := range modeCases {
		t.Run(tc.name, func(t *testing.T) {
			bootAndReboot(t, &luks.Device{Path: "/dev/state", Runner: &headerRunner{}}, tc.buildDefault, tc.configured, tc.want)
		})
	}
}

// The same boots against a real LUKS2 header, so the token set and the key
// check come from cryptsetup itself.
func TestStateUnlock_ConfiguredModeSurvivesReboots_RealCryptsetup(t *testing.T) {
	for _, tc := range modeCases {
		t.Run(tc.name, func(t *testing.T) {
			bootAndReboot(t, realStateDevice(t), tc.buildDefault, tc.configured, tc.want)
		})
	}
}

// A later boot that finds a stage asking for another mode still opens the
// volume with the mode it was sealed with: the mode is fixed at install.
func TestStateUnlock_LaterStageCannotChangeTheMode(t *testing.T) {
	ctx := context.Background()
	dev := &luks.Device{Path: "/dev/state", Runner: &headerRunner{}}
	b := &testBackends{}
	unlock := func(stage []byte) (*unlockedState, error) {
		return stateUnlocker{device: dev, stage: espStage(stage), buildDefault: config.StateKeyModeTPM, newBackends: b.factory}.unlock(ctx)
	}
	if _, err := unlock(stageYAML(config.StateKeyModeNodeID)); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	st, err := unlock(stageYAML(config.StateKeyModeTPM))
	if err != nil {
		t.Fatalf("later boot with a tpm stage on a nodeid volume: %v", err)
	}
	if st.mode != config.StateKeyModeNodeID {
		t.Errorf("mode = %q, want nodeid (the sealed mode)", st.mode)
	}
}

// After an in-place upgrade a TPM volume carries one token per bootable image;
// it is still a TPM volume, and it opens with whichever copy unseals.
func TestStateUnlock_UpgradedTPMVolume_RealCryptsetup(t *testing.T) {
	ctx := context.Background()
	dev := realStateDevice(t)
	b := &testBackends{}
	unlocker := stateUnlocker{device: dev, stage: espStage(nil), buildDefault: config.StateKeyModeNodeID, newBackends: b.factory}
	unlocker.stage = espStage(stageYAML(config.StateKeyModeTPM))
	st, err := unlocker.unlock(ctx)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	st.close()

	// Reseal a second copy for an incoming image, then make the install-time
	// copy stop unsealing, as a PCR 11 change would.
	install, err := dev.ExportToken(ctx, StateTokenID)
	if err != nil {
		t.Fatalf("export install token: %v", err)
	}
	tok, _ := luks.ParseTPM2Token(install)
	priv, pub, _ := tok.SealedBlobs()
	key, _ := b.sealer.UnsealWithPCR(priv, pub, nil)
	priv2, pub2, _ := b.sealer.SealToPCR(key, []int{7, 11})
	tok2, _ := luks.BuildTPM2Token(priv2, pub2, stateKeyslot, []int{7, 11}, nil)
	tok2.ImageSHA256 = "ab"
	tok2JSON, _ := json.Marshal(tok2)
	if err := dev.ImportToken(ctx, StateTokenID+1, tok2JSON); err != nil {
		t.Fatalf("import upgrade token: %v", err)
	}
	delete(b.sealer.sealed, string(priv))

	unlocker.stage = espStage(nil)
	st, err = unlocker.unlock(ctx)
	if err != nil {
		t.Fatalf("boot after upgrade: %v", err)
	}
	if st.mode != config.StateKeyModeTPM || st.firstBoot {
		t.Errorf("boot after upgrade: mode=%q firstBoot=%v, want tpm false", st.mode, st.firstBoot)
	}
	if !slices.Equal(b.modes, []string{config.StateKeyModeTPM, config.StateKeyModeTPM}) {
		t.Errorf("modes = %v", b.modes)
	}
}

func TestSealedStateKey(t *testing.T) {
	tpmTok := func(image string) []byte {
		tok, _ := luks.BuildTPM2Token([]byte{0, 1, 'p'}, []byte("pub"), 0, []int{7, 11}, nil)
		tok.ImageSHA256 = image
		out, _ := json.Marshal(tok)
		return out
	}
	kmsTok, _ := json.Marshal(kmsToken{Type: kmsTokenType, Keyslots: []string{"0"}, Endpoint: testKMSEndpoint, TrustPEM: "trust"})
	other := []byte(`{"type":"systemd-fido2","keyslots":["1"]}`)

	cases := []struct {
		name    string
		tokens  map[int][]byte
		want    config.StateKey
		wantErr bool
	}{
		{"no tokens is nodeid", nil, config.StateKey{Mode: config.StateKeyModeNodeID}, false},
		{"foreign tokens only is nodeid", map[int][]byte{3: other}, config.StateKey{Mode: config.StateKeyModeNodeID}, false},
		{"install TPM token", map[int][]byte{0: tpmTok("")}, config.StateKey{Mode: config.StateKeyModeTPM}, false},
		{"TPM token per image after an upgrade", map[int][]byte{0: tpmTok(""), 1: tpmTok("ab"), 2: other}, config.StateKey{Mode: config.StateKeyModeTPM}, false},
		{"only an upgrade TPM token after a rollback", map[int][]byte{1: tpmTok("ab")}, config.StateKey{Mode: config.StateKeyModeTPM}, false},
		{"KMS token carries its endpoint", map[int][]byte{0: kmsTok},
			config.StateKey{Mode: config.StateKeyModeKMS, KMS: &config.KmsStateKey{Endpoint: testKMSEndpoint, TrustPEM: "trust"}}, false},
		{"TPM and KMS tokens are ambiguous", map[int][]byte{0: tpmTok(""), 1: kmsTok}, config.StateKey{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sealedStateKey(tc.tokens)
			if (err != nil) != tc.wantErr {
				t.Fatalf("sealedStateKey err = %v, want error %v", err, tc.wantErr)
			}
			if got.Mode != tc.want.Mode || (got.KMS == nil) != (tc.want.KMS == nil) || (got.KMS != nil && *got.KMS != *tc.want.KMS) {
				t.Errorf("sealedStateKey = %+v (kms %+v), want %+v (kms %+v)", got, got.KMS, tc.want, tc.want.KMS)
			}
		})
	}
}
