package init

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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/storage/luks"
	"github.com/CryptOS-PKI/cryptos-node/internal/ukipcr"
)

// policyTPM is a TPM fake that enforces the one property the reseal depends
// on: a blob unseals only while every PCR it was sealed to holds the value it
// was sealed against. The real TPM's side of that is covered in internal/tpm.
type policyTPM struct {
	live    map[int][]byte
	objects map[string]sealedObject
	n       int
	opens   int
	closes  int
}

type sealedObject struct {
	values map[int][]byte
	data   []byte
}

func newPolicyTPM() *policyTPM {
	return &policyTPM{
		live:    map[int][]byte{7: bytes.Repeat([]byte{7}, 32), 11: make([]byte, 32)},
		objects: map[string]sealedObject{},
	}
}

// boot puts PCR 11 where the stub leaves it for image.
func (p *policyTPM) boot(image []byte) { p.live[11] = fakePredict(image).Value }

func (p *policyTPM) ReadPCRs(pcrs []int) (map[int][]byte, error) {
	out := map[int][]byte{}
	for _, i := range pcrs {
		out[i] = append([]byte(nil), p.live[i]...)
	}
	return out, nil
}

func (p *policyTPM) SealToPCRValues(data []byte, values map[int][]byte) ([]byte, []byte, error) {
	p.n++
	name := fmt.Sprintf("obj%02d", p.n)
	vals := map[int][]byte{}
	for k, v := range values {
		vals[k] = append([]byte(nil), v...)
	}
	p.objects[name] = sealedObject{values: vals, data: append([]byte(nil), data...)}
	return append([]byte{0, byte(len(name))}, name...), []byte("pub-" + name), nil
}

func (p *policyTPM) UnsealWithPCR(priv, _ []byte, pcrs []int) ([]byte, error) {
	obj, ok := p.objects[string(priv[2:])]
	if !ok {
		return nil, errors.New("unknown object")
	}
	for _, i := range pcrs {
		if !bytes.Equal(obj.values[i], p.live[i]) {
			return nil, fmt.Errorf("policy check failed: PCR %d", i)
		}
	}
	return append([]byte(nil), obj.data...), nil
}

// The Sealer half, so the same fake backs the boot-time tpmProtector.
func (p *policyTPM) ProvisionSRK() error { return nil }
func (p *policyTPM) SealToPCR(data []byte, pcrs []int) ([]byte, []byte, error) {
	now, _ := p.ReadPCRs(pcrs)
	return p.SealToPCRValues(data, now)
}
func (p *policyTPM) Close() error { p.closes++; return nil }

// fakePredict stands in for systemd-stub's measurement: a different image,
// a different PCR 11. Images starting with "unpredictable" are refused the
// way ukipcr refuses an image it does not understand.
func fakePredict(image []byte) ukipcr.Prediction {
	sum := sha256.Sum256(append([]byte("pcr11:"), image...))
	return ukipcr.Prediction{Value: sum[:], Sections: []string{".linux"}}
}

func fakePredictor(image []byte) (ukipcr.Prediction, error) {
	if bytes.HasPrefix(image, []byte("unpredictable")) {
		return ukipcr.Prediction{}, fmt.Errorf("%w: test image", ukipcr.ErrUnpredictable)
	}
	return fakePredict(image), nil
}

// fakeHeader is cryptsetup over an in-memory LUKS2 header: the token table
// and the key the volume was formatted with.
type fakeHeader struct {
	key      []byte
	tokens   map[int][]byte
	ops      []string
	failNext map[string]int // op -> fail the Nth such call (1-based)
	counts   map[string]int
}

func newFakeHeader(key []byte) *fakeHeader {
	return &fakeHeader{key: append([]byte(nil), key...), tokens: map[int][]byte{},
		failNext: map[string]int{}, counts: map[string]int{}}
}

func (h *fakeHeader) Run(_ context.Context, stdin io.Reader, args ...string) ([]byte, []byte, error) {
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	op := args[0]
	if op == "token" {
		op = "token " + args[1]
	}
	h.counts[op]++
	if h.failNext[op] != 0 && h.failNext[op] == h.counts[op] {
		return nil, []byte("injected"), errors.New("cryptsetup failed")
	}
	id := -1
	for i, a := range args {
		if a == "--token-id" {
			id, _ = strconv.Atoi(args[i+1])
		}
	}
	switch op {
	case "luksDump":
		m := map[string]json.RawMessage{}
		for k, v := range h.tokens {
			m[strconv.Itoa(k)] = v
		}
		out, _ := json.Marshal(map[string]any{"tokens": m})
		return out, nil, nil
	case "token import":
		if _, taken := h.tokens[id]; taken {
			return nil, []byte("token exists"), errors.New("cryptsetup failed")
		}
		h.tokens[id] = in
		h.ops = append(h.ops, fmt.Sprintf("import %d", id))
	case "token export":
		tok, ok := h.tokens[id]
		if !ok {
			return nil, []byte("no token"), errors.New("cryptsetup failed")
		}
		return tok, nil, nil
	case "token remove":
		if _, ok := h.tokens[id]; !ok {
			return nil, []byte("no token"), errors.New("cryptsetup failed")
		}
		delete(h.tokens, id)
		h.ops = append(h.ops, fmt.Sprintf("remove %d", id))
	case "luksOpen":
		if !bytes.Equal(in, h.key) {
			return nil, []byte("wrong key"), errors.New("cryptsetup failed")
		}
	}
	return nil, nil, nil
}

// imagesCovered returns the image digests the header's TPM tokens carry.
func (h *fakeHeader) imagesCovered(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, tt := range tpmTokensOf(h.tokens) {
		out = append(out, tt.tok.ImageSHA256)
	}
	slices.Sort(out)
	return out
}

// installNode is a first boot on image: format, seal, token 0.
func installNode(t *testing.T, image []byte) (*policyTPM, *fakeHeader, []byte) {
	t.Helper()
	tp := newPolicyTPM()
	tp.boot(image)
	key := bytes.Repeat([]byte{0x5a}, stateKeyBytes)
	hdr := newFakeHeader(key)
	priv, pub, err := tp.SealToPCR(key, []int{7, 11})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	tok, _ := luks.BuildTPM2Token(priv, pub, stateKeyslot, []int{7, 11}, nil)
	js, _ := json.Marshal(tok)
	hdr.tokens[StateTokenID] = js
	return tp, hdr, key
}

func newTestResealer(tp *policyTPM, hdr *fakeHeader) *stateKeyResealer {
	r := newStateKeyResealer(&luks.Device{Path: "/dev/state", Runner: hdr},
		func() (resealTPM, error) { tp.opens++; return tp, nil })
	r.predict = fakePredictor
	return r
}

// bootsOn reports whether a boot of image opens the state volume, going
// through the same OpenStateVolume path PID 1 takes.
func bootsOn(t *testing.T, tp *policyTPM, hdr *fakeHeader, image []byte) bool {
	t.Helper()
	tp.boot(image)
	_, err := OpenStateVolume(context.Background(), StateVolumeConfig{
		Protector:  newTPMProtector(tp, []int{7, 11}),
		Device:     &luks.Device{Path: "/dev/state", Runner: hdr},
		MappedName: StateMappedName, TokenID: StateTokenID,
	})
	return err == nil
}

func TestReseal_KeyFollowsAnUpgradeAndItsRollback(t *testing.T) {
	imgA, imgB, imgC := []byte("image A"), []byte("image B"), []byte("image C")
	tp, hdr, _ := installNode(t, imgA)
	if bootsOn(t, tp, hdr, imgB) {
		t.Fatal("precondition: an unresealed node must not open under a new image")
	}
	tp.boot(imgA)

	// Stage B while running A; A stays on the ESP as the previous image.
	if err := newTestResealer(tp, hdr).Reseal(context.Background(), imgA, imgB, imgA); err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgA, imgB); !slices.Equal(got, want) {
		t.Fatalf("tokens cover %v, want %v", got, want)
	}
	if !bootsOn(t, tp, hdr, imgB) {
		t.Fatal("the upgraded image cannot open the state volume")
	}
	if !bootsOn(t, tp, hdr, imgA) {
		t.Fatal("a rollback to the previous image cannot open the state volume")
	}
	if bootsOn(t, tp, hdr, imgC) {
		t.Fatal("an image that was never staged opened the state volume")
	}

	// The next upgrade, from B to C, drops A: only what the ESP can boot
	// (and the running image) may unseal.
	tp.boot(imgB)
	if err := newTestResealer(tp, hdr).Reseal(context.Background(), imgB, imgC, imgB); err != nil {
		t.Fatalf("second Reseal: %v", err)
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgB, imgC); !slices.Equal(got, want) {
		t.Fatalf("tokens cover %v, want %v", got, want)
	}
	if !bootsOn(t, tp, hdr, imgC) || !bootsOn(t, tp, hdr, imgB) {
		t.Fatal("C or its rollback target B cannot open the state volume")
	}
	if bootsOn(t, tp, hdr, imgA) {
		t.Fatal("an image no longer on the ESP still opens the state volume")
	}
	if tp.opens != tp.closes {
		t.Errorf("TPM opened %d times, closed %d", tp.opens, tp.closes)
	}
}

// New tokens go in before any old one comes out, so a failure part way never
// leaves the header without a token the running image can use.
func TestReseal_AddsBeforeItRemoves(t *testing.T) {
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)

	if err := newTestResealer(tp, hdr).Reseal(context.Background(), imgA, imgB); err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	want := []string{"import 1", "import 2", "remove 0"}
	if !slices.Equal(hdr.ops, want) {
		t.Errorf("header ops = %v, want %v", hdr.ops, want)
	}
}

func TestReseal_RefusesWhenThePredictionMissesTheRunningBoot(t *testing.T) {
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)
	// Something the predictor does not model extended PCR 11 on this boot. The
	// running token still unseals, so only the self-check can catch it.
	tp.live[11] = bytes.Repeat([]byte{0xee}, 32)
	priv, pub, _ := tp.SealToPCR(hdr.key, []int{7, 11})
	tok, _ := luks.BuildTPM2Token(priv, pub, stateKeyslot, []int{7, 11}, nil)
	hdr.tokens[StateTokenID], _ = json.Marshal(tok)

	err := newTestResealer(tp, hdr).Reseal(context.Background(), imgA, imgB)
	if !errors.Is(err, errResealRefused) {
		t.Fatalf("Reseal error = %v, want errResealRefused", err)
	}
	if len(hdr.ops) != 0 {
		t.Errorf("the header was changed on a refused reseal: %v", hdr.ops)
	}
}

func TestReseal_RefusesAnImageItCannotPredict(t *testing.T) {
	imgA := []byte("image A")
	tp, hdr, _ := installNode(t, imgA)

	err := newTestResealer(tp, hdr).Reseal(context.Background(), imgA, []byte("unpredictable image"))
	if !errors.Is(err, errResealRefused) || !errors.Is(err, ukipcr.ErrUnpredictable) {
		t.Fatalf("Reseal error = %v, want errResealRefused wrapping ErrUnpredictable", err)
	}
	if len(hdr.ops) != 0 {
		t.Errorf("the header was changed on a refused reseal: %v", hdr.ops)
	}
}

func TestReseal_UndoesItsTokensWhenAnImportFails(t *testing.T) {
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)
	hdr.failNext["token import"] = 2

	if err := newTestResealer(tp, hdr).Reseal(context.Background(), imgA, imgB); err == nil {
		t.Fatal("Reseal succeeded though an import failed")
	}
	if len(hdr.tokens) != 1 || hdr.tokens[StateTokenID] == nil {
		t.Fatalf("header tokens after a failed reseal = %v, want only the original", hdr.tokens)
	}
	if !bootsOn(t, tp, hdr, imgA) {
		t.Fatal("the running image no longer opens after a failed reseal")
	}
}

func TestReseal_LeavesOtherTokenTypesAlone(t *testing.T) {
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)
	other := []byte(`{"type":"systemd-recovery","keyslots":["1"]}`)
	hdr.tokens[1] = other

	if err := newTestResealer(tp, hdr).Reseal(context.Background(), imgA, imgB); err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	if !bytes.Equal(hdr.tokens[1], other) {
		t.Errorf("token 1 of another type was changed: %q", hdr.tokens[1])
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgA, imgB); !slices.Equal(got, want) {
		t.Fatalf("tokens cover %v, want %v", got, want)
	}
}

func TestReseal_NeedsATokenThatUnseals(t *testing.T) {
	imgA := []byte("image A")
	tp, hdr, _ := installNode(t, imgA)
	tp.live[7] = bytes.Repeat([]byte{0x01}, 32) // Secure Boot state changed.

	if err := newTestResealer(tp, hdr).Reseal(context.Background(), imgA, []byte("image B")); err == nil {
		t.Fatal("Reseal succeeded with no token the running boot can unseal")
	}
	if len(hdr.ops) != 0 {
		t.Errorf("the header was changed: %v", hdr.ops)
	}
}

func sortedDigests(images ...[]byte) []string {
	var out []string
	for _, img := range images {
		out = append(out, imageDigest(img))
	}
	slices.Sort(out)
	return out
}

// After an upgrade the install-time token no longer matches, and the boot
// has to find the copy sealed for the image it is running.
func TestOpenStateVolume_FindsTheTokenForTheBootedImage(t *testing.T) {
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)
	tp.boot(imgB)
	priv, pub, _ := tp.SealToPCR(hdr.key, []int{7, 11})
	tok, _ := luks.BuildTPM2Token(priv, pub, stateKeyslot, []int{7, 11}, nil)
	hdr.tokens[3], _ = json.Marshal(tok)
	hdr.tokens[1] = []byte(`{"type":"systemd-recovery"}`)

	if !bootsOn(t, tp, hdr, imgB) {
		t.Fatal("the boot did not fall back to token 3")
	}
	tp.boot([]byte("image C"))
	_, err := OpenStateVolume(context.Background(), StateVolumeConfig{
		Protector:  newTPMProtector(tp, []int{7, 11}),
		Device:     &luks.Device{Path: "/dev/state", Runner: hdr},
		MappedName: StateMappedName, TokenID: StateTokenID,
	})
	if err == nil {
		t.Fatal("an image with no token opened the state volume")
	}
	if !strings.Contains(err.Error(), "token 3") {
		t.Errorf("error %q does not report the tokens tried", err)
	}
}

// A rollback leaves only the rollback target on the ESP. Retarget seals a
// fresh copy for it and drops every other copy, including the one for the
// image that is running and about to be rolled back from.
func TestRetarget_LeavesOnlyTheRollbackTarget(t *testing.T) {
	imgA, imgB := []byte("image A"), []byte("image B")
	tp, hdr, _ := installNode(t, imgA)
	if err := newTestResealer(tp, hdr).Reseal(context.Background(), imgA, imgB, imgA); err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	tp.boot(imgB)
	hdr.ops = nil

	if err := newTestResealer(tp, hdr).Retarget(context.Background(), imgB, imgA); err != nil {
		t.Fatalf("Retarget: %v", err)
	}
	if got, want := hdr.imagesCovered(t), sortedDigests(imgA); !slices.Equal(got, want) {
		t.Fatalf("tokens cover %v, want %v", got, want)
	}
	if len(hdr.ops) != 3 || !strings.HasPrefix(hdr.ops[0], "import ") ||
		!strings.HasPrefix(hdr.ops[1], "remove ") || !strings.HasPrefix(hdr.ops[2], "remove ") {
		t.Errorf("header ops = %v, want one import before two removes", hdr.ops)
	}
	if !bootsOn(t, tp, hdr, imgA) {
		t.Fatal("the rollback target cannot open the state volume")
	}
	if bootsOn(t, tp, hdr, imgB) {
		t.Fatal("the rolled-back-from image still opens the state volume")
	}
}

// With nothing to keep, Retarget would strip every token; it refuses instead.
func TestRetarget_RefusesAnEmptyTargetSet(t *testing.T) {
	imgA := []byte("image A")
	tp, hdr, _ := installNode(t, imgA)

	if err := newTestResealer(tp, hdr).Retarget(context.Background(), imgA); err == nil {
		t.Fatal("Retarget with no target succeeded")
	}
	if len(hdr.ops) != 0 {
		t.Errorf("the header was changed: %v", hdr.ops)
	}
}
