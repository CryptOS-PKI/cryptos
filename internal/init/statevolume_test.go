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
	"io"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/storage/luks"
)

// fakeSealer is a test double for the Sealer interface.
type fakeSealer struct {
	provisioned   bool
	sealPriv      []byte
	sealPub       []byte
	sealErr       error
	unsealKey     []byte
	unsealErr     error
	gotSealData   []byte
	gotUnsealPriv []byte
	gotUnsealPub  []byte
}

func (f *fakeSealer) ProvisionSRK() error { f.provisioned = true; return nil }

func (f *fakeSealer) SealToPCR(data []byte, _ []int) ([]byte, []byte, error) {
	f.gotSealData = append([]byte(nil), data...)
	return f.sealPriv, f.sealPub, f.sealErr
}

func (f *fakeSealer) UnsealWithPCR(priv, pub []byte, _ []int) ([]byte, error) {
	f.gotUnsealPriv = append([]byte(nil), priv...)
	f.gotUnsealPub = append([]byte(nil), pub...)
	return f.unsealKey, f.unsealErr
}

// dispatchRunner is a luks.Runner that records calls and answers
// `token export` with canned JSON.
type dispatchRunner struct {
	calls      [][]string
	stdins     [][]byte
	exportJSON []byte
	failOn     string
}

func (r *dispatchRunner) Run(_ context.Context, stdin io.Reader, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	r.stdins = append(r.stdins, in)
	if r.failOn != "" && len(args) > 0 && strings.Contains(strings.Join(args, " "), r.failOn) {
		return nil, []byte("boom"), errors.New("cryptsetup failed")
	}
	if len(args) >= 2 && args[0] == "token" && args[1] == "export" {
		return r.exportJSON, nil, nil
	}
	return nil, nil, nil
}

func (r *dispatchRunner) stdinFor(argSubstr string) []byte {
	for i, c := range r.calls {
		if strings.Contains(strings.Join(c, " "), argSubstr) {
			return r.stdins[i]
		}
	}
	return nil
}

func (r *dispatchRunner) order() []string {
	var o []string
	for _, c := range r.calls {
		o = append(o, c[0])
		if c[0] == "token" && len(c) > 1 {
			o[len(o)-1] = "token " + c[1]
		}
	}
	return o
}

// framedPriv is a TPM2B-framed private blob: 2-byte size, then payload.
var framedPriv = []byte{0x00, 0x05, 'p', 'r', 'i', 'v', '!'}
var framedPub = []byte("PUBLIC-PORTION")

func TestOpenStateVolume_FirstBoot(t *testing.T) {
	sealer := &fakeSealer{sealPriv: framedPriv, sealPub: framedPub}
	runner := &dispatchRunner{}
	dev := &luks.Device{Path: "/dev/state", Runner: runner}

	vol, err := OpenStateVolume(context.Background(), StateVolumeConfig{
		Protector: newTPMProtector(sealer, []int{7, 11}), Device: dev, MappedName: "cryptos-state",
		TokenID: 0, FirstBoot: true,
	})
	if err != nil {
		t.Fatalf("OpenStateVolume: %v", err)
	}
	if vol.Name != "cryptos-state" {
		t.Errorf("vol.Name = %q", vol.Name)
	}
	if !sealer.provisioned {
		t.Error("SRK not provisioned")
	}

	// The freshly generated key is what got formatted, sealed, and opened.
	formatKey := runner.stdinFor("luksFormat")
	openKey := runner.stdinFor("luksOpen")
	if len(formatKey) != stateKeyBytes {
		t.Errorf("format key len = %d, want %d", len(formatKey), stateKeyBytes)
	}
	if !bytes.Equal(formatKey, sealer.gotSealData) {
		t.Error("sealed key differs from the formatted key")
	}
	if !bytes.Equal(formatKey, openKey) {
		t.Error("opened key differs from the formatted key")
	}

	// The imported token round-trips back to the sealed blobs.
	tokJSON := runner.stdinFor("token import")
	tok, err := luks.ParseTPM2Token(tokJSON)
	if err != nil {
		t.Fatalf("imported token does not parse: %v", err)
	}
	gotPriv, gotPub, err := tok.SealedBlobs()
	if err != nil {
		t.Fatalf("SealedBlobs: %v", err)
	}
	if !bytes.Equal(gotPriv, framedPriv) || !bytes.Equal(gotPub, framedPub) {
		t.Error("token blobs do not match the sealed blobs")
	}

	// Order: format, then import token, then open.
	want := []string{"luksFormat", "token import", "luksOpen"}
	if strings.Join(runner.order(), ",") != strings.Join(want, ",") {
		t.Errorf("call order = %v, want %v", runner.order(), want)
	}
}

func TestOpenStateVolume_Unseal(t *testing.T) {
	tok, err := luks.BuildTPM2Token(framedPriv, framedPub, 0, []int{7, 11}, nil)
	if err != nil {
		t.Fatalf("BuildTPM2Token: %v", err)
	}
	tokJSON, _ := json.Marshal(tok)

	// The fake's key shares no backing with wantKey: OpenStateVolume wipes
	// the key it receives after use, which would otherwise zero wantKey.
	wantKey := bytes.Repeat([]byte{0xab}, stateKeyBytes)
	sealer := &fakeSealer{unsealKey: bytes.Repeat([]byte{0xab}, stateKeyBytes)}
	runner := &dispatchRunner{exportJSON: tokJSON}
	dev := &luks.Device{Path: "/dev/state", Runner: runner}

	vol, err := OpenStateVolume(context.Background(), StateVolumeConfig{
		Protector: newTPMProtector(sealer, []int{7, 11}), Device: dev, MappedName: "cryptos-state",
		TokenID: 0, FirstBoot: false,
	})
	if err != nil {
		t.Fatalf("OpenStateVolume: %v", err)
	}
	if vol.Name != "cryptos-state" {
		t.Errorf("vol.Name = %q", vol.Name)
	}
	// The token blobs were handed to the TPM for unsealing.
	if !bytes.Equal(sealer.gotUnsealPriv, framedPriv) || !bytes.Equal(sealer.gotUnsealPub, framedPub) {
		t.Error("unseal received wrong blobs")
	}
	// The unsealed key is what opened the volume.
	if !bytes.Equal(runner.stdinFor("luksOpen"), wantKey) {
		t.Error("volume opened with a key other than the unsealed key")
	}
	want := []string{"token export", "luksOpen"}
	if strings.Join(runner.order(), ",") != strings.Join(want, ",") {
		t.Errorf("call order = %v, want %v", runner.order(), want)
	}
}

func TestOpenStateVolume_Errors(t *testing.T) {
	mkCfg := func(s Sealer, r luks.Runner, firstBoot bool) StateVolumeConfig {
		return StateVolumeConfig{Protector: newTPMProtector(s, []int{7, 11}),
			Device:     &luks.Device{Path: "/dev/state", Runner: r},
			MappedName: "cryptos-state", FirstBoot: firstBoot}
	}

	t.Run("validation", func(t *testing.T) {
		if _, err := OpenStateVolume(context.Background(), StateVolumeConfig{}); err == nil {
			t.Error("empty config = nil error, want error")
		}
	})
	t.Run("format fails", func(t *testing.T) {
		_, err := OpenStateVolume(context.Background(),
			mkCfg(&fakeSealer{sealPriv: framedPriv, sealPub: framedPub}, &dispatchRunner{failOn: "luksFormat"}, true))
		if err == nil {
			t.Error("want error on format failure")
		}
	})
	t.Run("seal fails", func(t *testing.T) {
		_, err := OpenStateVolume(context.Background(),
			mkCfg(&fakeSealer{sealErr: errors.New("seal boom")}, &dispatchRunner{}, true))
		if err == nil {
			t.Error("want error on seal failure")
		}
	})
	t.Run("unseal fails", func(t *testing.T) {
		tok, _ := luks.BuildTPM2Token(framedPriv, framedPub, 0, []int{7, 11}, nil)
		js, _ := json.Marshal(tok)
		_, err := OpenStateVolume(context.Background(),
			mkCfg(&fakeSealer{unsealErr: errors.New("pcr drift")}, &dispatchRunner{exportJSON: js}, false))
		if err == nil {
			t.Error("want error on unseal failure")
		}
	})
	t.Run("bad token export", func(t *testing.T) {
		_, err := OpenStateVolume(context.Background(),
			mkCfg(&fakeSealer{unsealKey: make([]byte, 32)}, &dispatchRunner{exportJSON: []byte("not json")}, false))
		if err == nil {
			t.Error("want error on unparseable token")
		}
	})
}
