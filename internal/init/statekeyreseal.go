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

// Keeping a TPM-sealed state key reachable across an in-place image upgrade.
//
// The state key is sealed to PCR 7 and PCR 11, and PCR 11 measures the UKI,
// so every new image changes it. Before a new image is written to the ESP the
// node seals a fresh copy of the key for every image that will be bootable
// afterwards -- the one running, the one being staged, and the one retained
// for rollback -- each to the PCR 11 value that image will measure. Then it
// drops every older copy, so the set of images that can open the state
// partition is exactly the set the ESP can boot. Nothing about the LUKS
// keyslot changes: every copy is the same key, in its own header token.
//
// The prediction is only trusted after it has been checked against this boot:
// predicting the running image must give the PCR 11 value the TPM holds right
// now. If it does not, the stub measures something the predictor does not
// know about, and the stage is refused before the ESP is touched, because a
// wrong prediction would leave the node unable to unseal on the next boot.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"

	"github.com/CryptOS-PKI/cryptos/internal/storage/luks"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
	"github.com/CryptOS-PKI/cryptos/internal/ukipcr"
)

// luksMaxTokens is the LUKS2 token limit; ids run 0 through 31.
const luksMaxTokens = 32

// errResealRefused marks a reseal the node declined because it could not be
// sure the staged image would unseal, as opposed to an I/O failure. The
// upgrader reports it as a precondition failure: nothing is broken, but the
// image cannot be staged on this node.
var errResealRefused = errors.New("the state key cannot be resealed for this image")

// resealTPM is the TPM surface a reseal needs.
type resealTPM interface {
	ReadPCRs(pcrs []int) (map[int][]byte, error)
	UnsealWithPCR(private, public []byte, pcrs []int) ([]byte, error)
	SealToPCRValues(data []byte, values map[int][]byte) (private, public []byte, err error)
	Close() error
}

// tokenStore is the LUKS2 header surface a reseal needs; *luks.Device.
type tokenStore interface {
	Tokens(ctx context.Context) (map[int][]byte, error)
	ImportToken(ctx context.Context, tokenID int, tokenJSON []byte) error
	RemoveToken(ctx context.Context, tokenID int) error
}

// stateKeyResealer reseals the TPM-protected state key for a set of images.
type stateKeyResealer struct {
	tokens tokenStore
	// openTPM opens a TPM connection for one reseal. It is a fresh connection
	// rather than the one PID 1 holds, so a stage cannot interleave commands
	// with a signing operation on the same file descriptor.
	openTPM func() (resealTPM, error)
	predict func(image []byte) (ukipcr.Prediction, error)
}

func newStateKeyResealer(tokens tokenStore, openTPM func() (resealTPM, error)) *stateKeyResealer {
	return &stateKeyResealer{tokens: tokens, openTPM: openTPM, predict: ukipcr.Predict}
}

// tpmToken is one cryptos-tpm2 token found in the header.
type tpmToken struct {
	id  int
	tok *luks.TPM2Token
}

// Reseal leaves the header with one token per image in {running} plus
// bootable, each sealed to that image's PCR 11, and no other cryptos-tpm2
// tokens. Tokens of any other type are left alone.
//
// On failure before the old tokens are removed, the header is as it was, so
// the running image still boots.
func (r *stateKeyResealer) Reseal(ctx context.Context, running []byte, bootable ...[]byte) error {
	runningDigest := imageDigest(running)
	log.Printf("state key reseal: start (running image %s, %d more to cover)", shortDigest(runningDigest), len(bootable))

	predRunning, err := r.predict(running)
	if err != nil {
		return fmt.Errorf("%w: predict PCR 11 for the running image: %w", errResealRefused, err)
	}
	log.Printf("state key reseal: running image predicts PCR 11 %x over %v", predRunning.Value, predRunning.Sections)

	t, err := r.openTPM()
	if err != nil {
		return fmt.Errorf("state key reseal: open TPM: %w", err)
	}
	defer func() { _ = t.Close() }()

	all, err := r.tokens.Tokens(ctx)
	if err != nil {
		return fmt.Errorf("state key reseal: list tokens: %w", err)
	}
	existing := tpmTokensOf(all)
	if len(existing) == 0 {
		return errors.New("state key reseal: the state partition has no TPM token")
	}
	key, working, err := unsealAny(t, existing, runningDigest)
	if err != nil {
		return err
	}
	defer wipe(key)

	pcrs := working.tok.PCRs
	if len(pcrs) == 0 {
		pcrs = tpm.DefaultSealPCRs
	}
	if !slices.Contains(pcrs, ukipcr.PCR) {
		// Nothing in the seal measures the image, so every image unseals.
		log.Printf("state key reseal: token %d is sealed to %v, which does not include PCR %d; nothing to reseal", working.id, pcrs, ukipcr.PCR)
		return nil
	}
	live, err := t.ReadPCRs(pcrs)
	if err != nil {
		return fmt.Errorf("state key reseal: read PCRs: %w", err)
	}
	if !bytes.Equal(live[ukipcr.PCR], predRunning.Value) {
		log.Printf("state key reseal: REFUSED: PCR 11 is %x but the running image predicts %x", live[ukipcr.PCR], predRunning.Value)
		return fmt.Errorf("%w: the PCR 11 prediction for the running image (%x) does not match the TPM (%x), so a prediction for a new image cannot be trusted",
			errResealRefused, predRunning.Value, live[ukipcr.PCR])
	}
	log.Printf("state key reseal: prediction for the running image matches the TPM")

	keyslot, err := tokenKeyslot(working.tok)
	if err != nil {
		return err
	}
	targets, err := r.targets(running, predRunning, bootable)
	if err != nil {
		return err
	}

	// Every id in use, whatever the token type, so a new token never lands on
	// one.
	used := make(map[int]bool, len(all))
	for id := range all {
		used[id] = true
	}
	var added []int
	for _, tg := range targets {
		values := make(map[int][]byte, len(live))
		for p, v := range live {
			values[p] = v
		}
		values[ukipcr.PCR] = tg.pcr11

		id, idErr := freeTokenID(used)
		if idErr == nil {
			idErr = r.sealInto(ctx, t, key, values, keyslot, pcrs, tg.digest, id)
		}
		if idErr != nil {
			r.rollback(ctx, added)
			return idErr
		}
		used[id] = true
		added = append(added, id)
		log.Printf("state key reseal: token %d sealed for image %s (PCR 11 %x)", id, shortDigest(tg.digest), tg.pcr11)
	}

	for _, old := range existing {
		if err := r.tokens.RemoveToken(ctx, old.id); err != nil {
			// Every image that will be bootable already has its own token, so
			// staging is safe; the stale one is dropped by the next reseal.
			log.Printf("state key reseal: warn: remove stale token %d: %v", old.id, err)
			continue
		}
		log.Printf("state key reseal: removed token %d (image %s)", old.id, shortDigest(old.tok.ImageSHA256))
	}
	log.Printf("state key reseal: done (tokens %v)", added)

	return nil
}

// resealTarget is one image to seal a copy of the key for.
type resealTarget struct {
	digest string
	pcr11  []byte
}

// targets returns the running image first, then each distinct other image.
func (r *stateKeyResealer) targets(running []byte, predRunning ukipcr.Prediction, bootable [][]byte) ([]resealTarget, error) {
	out := []resealTarget{{digest: imageDigest(running), pcr11: predRunning.Value}}
	seen := map[string]bool{out[0].digest: true}
	for _, img := range bootable {
		d := imageDigest(img)
		if seen[d] {
			continue
		}
		seen[d] = true
		p, err := r.predict(img)
		if err != nil {
			return nil, fmt.Errorf("%w: predict PCR 11 for image %s: %w", errResealRefused, shortDigest(d), err)
		}
		log.Printf("state key reseal: image %s predicts PCR 11 %x over %v", shortDigest(d), p.Value, p.Sections)
		out = append(out, resealTarget{digest: d, pcr11: p.Value})
	}

	return out, nil
}

func (r *stateKeyResealer) sealInto(ctx context.Context, t resealTPM, key []byte, values map[int][]byte, keyslot int, pcrs []int, digest string, id int) error {
	priv, pub, err := t.SealToPCRValues(key, values)
	if err != nil {
		return fmt.Errorf("state key reseal: seal for image %s: %w", shortDigest(digest), err)
	}
	tok, err := luks.BuildTPM2Token(priv, pub, keyslot, pcrs, nil)
	if err != nil {
		return fmt.Errorf("state key reseal: build token: %w", err)
	}
	tok.ImageSHA256 = digest
	tokJSON, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("state key reseal: marshal token: %w", err)
	}
	if err := r.tokens.ImportToken(ctx, id, tokJSON); err != nil {
		return fmt.Errorf("state key reseal: import token %d: %w", id, err)
	}

	return nil
}

// rollback removes tokens this reseal added, leaving the header as it was.
func (r *stateKeyResealer) rollback(ctx context.Context, added []int) {
	for _, id := range added {
		if err := r.tokens.RemoveToken(ctx, id); err != nil {
			log.Printf("state key reseal: warn: undo token %d: %v", id, err)
		}
	}
}

// tpmTokensOf picks the cryptos-tpm2 tokens out of a header listing, in id
// order.
func tpmTokensOf(all map[int][]byte) []tpmToken {
	ids := make([]int, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []tpmToken
	for _, id := range ids {
		tok, err := luks.ParseTPM2Token(all[id])
		if err != nil {
			continue
		}
		out = append(out, tpmToken{id: id, tok: tok})
	}

	return out
}

// unsealAny recovers the state key from whichever token the running boot
// satisfies, trying the one stamped for the running image first.
func unsealAny(t resealTPM, tokens []tpmToken, runningDigest string) ([]byte, tpmToken, error) {
	ordered := slices.Clone(tokens)
	slices.SortStableFunc(ordered, func(a, b tpmToken) int {
		am, bm := a.tok.ImageSHA256 == runningDigest, b.tok.ImageSHA256 == runningDigest
		switch {
		case am && !bm:
			return -1
		case bm && !am:
			return 1
		}
		return 0
	})
	var errs []error
	for _, c := range ordered {
		priv, pub, err := c.tok.SealedBlobs()
		if err != nil {
			errs = append(errs, fmt.Errorf("token %d: %w", c.id, err))
			continue
		}
		pcrs := c.tok.PCRs
		if len(pcrs) == 0 {
			pcrs = tpm.DefaultSealPCRs
		}
		key, err := t.UnsealWithPCR(priv, pub, pcrs)
		if err != nil {
			log.Printf("state key reseal: token %d does not unseal under this boot: %v", c.id, err)
			errs = append(errs, fmt.Errorf("token %d: %w", c.id, err))
			continue
		}
		log.Printf("state key reseal: unsealed with token %d", c.id)
		return key, c, nil
	}

	return nil, tpmToken{}, fmt.Errorf("state key reseal: no token unseals under the running image: %w", errors.Join(errs...))
}

func tokenKeyslot(tok *luks.TPM2Token) (int, error) {
	if len(tok.Keyslots) == 0 {
		return stateKeyslot, nil
	}
	ks, err := strconv.Atoi(tok.Keyslots[0])
	if err != nil {
		return 0, fmt.Errorf("state key reseal: token keyslot %q: %w", tok.Keyslots[0], err)
	}

	return ks, nil
}

func freeTokenID(used map[int]bool) (int, error) {
	for id := 0; id < luksMaxTokens; id++ {
		if !used[id] {
			return id, nil
		}
	}

	return 0, errors.New("state key reseal: the LUKS header has no free token slot")
}

func imageDigest(image []byte) string {
	sum := sha256.Sum256(image)
	return hex.EncodeToString(sum[:])
}

// shortDigest abbreviates a digest for log lines.
func shortDigest(d string) string {
	if d == "" {
		return "(unrecorded)"
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
