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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// nodeKeyRSABits is the size of every RSA key a node mints for itself (the
// delegated OCSP responder, the EST listener certificate, the management
// listener certificate).
//
// It is a fixed 3072 rather than the CA key's size, deliberately. 3072 is the
// floor ca.ValidateSubjectKey enforces on any subject key this CA certifies,
// so it is the cheapest size that can actually be signed, and these are
// short-lived end-entity keys sitting behind a CA key that may well be larger.
// Tracking the CA would mean an RSA-4096 CA doubled the cost of every lazy
// mint -- keygen is roughly 0.9s at 4096 against 0.45s at 3072 on a developer
// workstation, and materially worse on node hardware -- for an end-entity key
// that is replaced weekly.
const nodeKeyRSABits = 3072

// newNodeKey generates a fresh end-entity key for a node-held credential,
// following the algorithm of the CA key that will sign it: an RSA CA gets an
// RSA node key, an ECDSA CA an ECDSA P-384 one.
//
// The CA key is the authority here rather than the configured algorithm,
// because the signature a relying party ends up verifying is a property of the
// key actually on disk.
func newNodeKey(caPub crypto.PublicKey) (crypto.Signer, error) {
	switch caPub.(type) {
	case *rsa.PublicKey:
		return newNodeRSAKey()
	case *ecdsa.PublicKey:
		return newNodeECDSAKey()
	default:
		return nil, fmt.Errorf("init: newNodeKey: cannot mint a node key to match a CA key of type %T", caPub)
	}
}

func newNodeRSAKey() (crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, nodeKeyRSABits)
	if err != nil {
		return nil, fmt.Errorf("init: generate node RSA key: %w", err)
	}
	return key, nil
}

func newNodeECDSAKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("init: generate node ECDSA key: %w", err)
	}
	return key, nil
}

// nodeKeyMatches reports whether key is of the algorithm a CA key of caPub's
// type demands.
func nodeKeyMatches(key crypto.Signer, caPub crypto.PublicKey) bool {
	switch caPub.(type) {
	case *rsa.PublicKey:
		_, ok := key.Public().(*rsa.PublicKey)
		return ok
	case *ecdsa.PublicKey:
		_, ok := key.Public().(*ecdsa.PublicKey)
		return ok
	default:
		return false
	}
}

// marshalNodeKey encodes a node-held private key for persistence. ECDSA keys
// keep their SEC1 encoding so blobs written before RSA support keep loading
// unchanged; everything else is PKCS#8, which is the same split
// softRootBackend uses for the CA key.
func marshalNodeKey(key crypto.Signer) ([]byte, error) {
	if ec, ok := key.(*ecdsa.PrivateKey); ok {
		der, err := x509.MarshalECPrivateKey(ec)
		if err != nil {
			return nil, fmt.Errorf("init: marshal node key: %w", err)
		}
		return der, nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("init: marshal node key: %w", err)
	}
	return der, nil
}

// parseNodeKey parses a blob written by marshalNodeKey. SEC1 is tried first so
// the ECDSA keys already on disk load without a format marker; PKCS#8 covers
// the RSA ones.
func parseNodeKey(blob []byte) (crypto.Signer, error) {
	if key, err := x509.ParseECPrivateKey(blob); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blob)
	if err != nil {
		return nil, fmt.Errorf("init: parse node key: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("init: parse node key: key of type %T cannot sign", parsed)
	}
	return key, nil
}

// nodeKeyWarmer pre-generates one node key off the serving path, so a
// credential minted lazily inside a TLS handshake does not pay for an RSA
// keygen while a client waits.
//
// Pre-generation works from the configured algorithm, which is all that is
// known before the CA key is loaded. take still checks the warm key against
// the CA key it is handed and discards it on a mismatch, so a config that has
// drifted from the key on disk costs a keygen rather than the wrong algorithm.
type nodeKeyWarmer struct {
	mu  sync.Mutex
	key crypto.Signer

	// done is closed when the pre-generation attempt has finished, whether or
	// not it produced a key.
	done chan struct{}
}

// warmNodeKey starts pre-generating a node key for the configured CA key
// algorithm and returns immediately. An algorithm it cannot act on (including
// the zero value, which is what the pre-ceremony paths have) simply yields no
// warm key, leaving take to generate one.
func warmNodeKey(alg config.RootKeyAlg) *nodeKeyWarmer {
	w := &nodeKeyWarmer{done: make(chan struct{})}
	go func() {
		defer close(w.done)
		key, err := newNodeKeyForAlg(alg)
		if err != nil {
			return
		}
		w.mu.Lock()
		w.key = key
		w.mu.Unlock()
	}()
	return w
}

// take returns a node key matching caPub, using the pre-generated one when it
// is ready and of the right algorithm. The warm key is handed out at most
// once.
func (w *nodeKeyWarmer) take(caPub crypto.PublicKey) (crypto.Signer, error) {
	w.mu.Lock()
	key := w.key
	w.key = nil
	w.mu.Unlock()

	if key != nil && nodeKeyMatches(key, caPub) {
		return key, nil
	}
	return newNodeKey(caPub)
}

// newNodeKeyForAlg generates a node key for a configured CA key algorithm,
// rather than for a loaded CA key.
func newNodeKeyForAlg(alg config.RootKeyAlg) (crypto.Signer, error) {
	keyAlg, err := alg.KeyAlgorithm()
	if err != nil {
		return nil, fmt.Errorf("init: node key algorithm: %w", err)
	}
	if _, isRSA := tpm.RSAKeyBits(keyAlg); isRSA {
		return newNodeRSAKey()
	}
	if keyAlg == tpm.AlgorithmECDSAP384 {
		return newNodeECDSAKey()
	}
	return nil, fmt.Errorf("init: node key algorithm: unsupported CA key algorithm %d", keyAlg)
}

// newBootKey generates the key for the pre-ceremony management listener
// certificate, following the configured CA key algorithm: an RSA-configured
// node presents an RSA handshake signature, which is what an RSA-only admin
// client needs (#200).
//
// The configured algorithm is the only signal available here -- this
// certificate is self-signed and minted before the node has a CA identity at
// all. The zero value means no config has been applied yet (maintenance mode),
// and keeps the ECDSA P-256 key this certificate has always used.
//
// ECDSA stays on P-256 rather than following the CA's P-384: the requirement is
// that ECDSA behaviour is unchanged, and this throwaway, operator-pinned,
// regenerated-every-boot certificate gains nothing from the larger curve.
func newBootKey(alg config.RootKeyAlg) (crypto.Signer, error) {
	if alg == "" {
		return newBootECDSAKey()
	}
	keyAlg, err := alg.KeyAlgorithm()
	if err != nil {
		return nil, fmt.Errorf("init: boot key algorithm: %w", err)
	}
	if _, isRSA := tpm.RSAKeyBits(keyAlg); isRSA {
		return newNodeRSAKey()
	}
	return newBootECDSAKey()
}

func newBootECDSAKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("init: generate boot ECDSA key: %w", err)
	}
	return key, nil
}
