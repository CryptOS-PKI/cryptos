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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// rsaCAPublic returns the public half of an RSA CA key. 2048 is the issuer
// floor (ca.MinRSAIssuerKeyBits) and the cheapest key that stands in for a
// real RSA CA here; the node key size is fixed, so it does not track this.
func rsaCAPublic(t *testing.T) *rsa.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, ca.MinRSAIssuerKeyBits)
	if err != nil {
		t.Fatalf("GenerateKey RSA CA: %v", err)
	}
	return &key.PublicKey
}

func ecdsaCAPublic(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey ECDSA CA: %v", err)
	}
	return &key.PublicKey
}

// TestNewNodeKeyFollowsAnRSACA is the whole point of #200: on an RSA CA the
// keys the node mints for itself must be RSA too, or it holds credentials an
// RSA-only relying party cannot verify even though the chain checks out.
func TestNewNodeKeyFollowsAnRSACA(t *testing.T) {
	key, err := newNodeKey(rsaCAPublic(t))
	if err != nil {
		t.Fatalf("newNodeKey: %v", err)
	}
	pub, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("key type = %T, want *rsa.PrivateKey", key)
	}
	if bits := pub.N.BitLen(); bits != nodeKeyRSABits {
		t.Errorf("key size = %d bits, want %d", bits, nodeKeyRSABits)
	}
}

func TestNewNodeKeyFollowsAnECDSACA(t *testing.T) {
	key, err := newNodeKey(ecdsaCAPublic(t))
	if err != nil {
		t.Fatalf("newNodeKey: %v", err)
	}
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("key type = %T, want *ecdsa.PrivateKey", key)
	}
	if pub.Curve != elliptic.P384() {
		t.Errorf("curve = %v, want P-384", pub.Curve.Params().Name)
	}
}

// TestNewNodeKeyIsCertifiable guards the interaction with the CA's own subject
// floor: a node key the CA would refuse to sign is useless, so the fixed RSA
// size has to sit at or above ca.MinRSASubjectKeyBits.
func TestNewNodeKeyIsCertifiable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		caPub any
	}{
		{"rsa CA", rsaCAPublic(t)},
		{"ecdsa CA", ecdsaCAPublic(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := newNodeKey(tc.caPub)
			if err != nil {
				t.Fatalf("newNodeKey: %v", err)
			}
			if err := ca.ValidateSubjectKey(key.Public()); err != nil {
				t.Errorf("ValidateSubjectKey: %v", err)
			}
		})
	}
}

func TestNewNodeKeyRejectsAnUnusableCAKey(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey ed25519: %v", err)
	}
	for _, tc := range []struct {
		name  string
		caPub any
	}{
		{"nil", nil},
		{"ed25519", edPub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newNodeKey(tc.caPub); err == nil {
				t.Error("newNodeKey should reject a CA key it cannot mirror")
			}
		})
	}
}

// TestNodeKeyBlobRoundTrips covers the persistence half: a stored node key has
// to come back as the same key after a restart, for both algorithms.
func TestNodeKeyBlobRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name  string
		caPub any
	}{
		{"rsa", rsaCAPublic(t)},
		{"ecdsa", ecdsaCAPublic(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := newNodeKey(tc.caPub)
			if err != nil {
				t.Fatalf("newNodeKey: %v", err)
			}
			blob, err := marshalNodeKey(key)
			if err != nil {
				t.Fatalf("marshalNodeKey: %v", err)
			}
			got, err := parseNodeKey(blob)
			if err != nil {
				t.Fatalf("parseNodeKey: %v", err)
			}
			equal, ok := key.Public().(interface {
				Equal(crypto.PublicKey) bool
			})
			if !ok {
				t.Fatalf("key type %T has no Equal method", key.Public())
			}
			if !equal.Equal(got.Public()) {
				t.Error("parsed key does not match the key that was marshalled")
			}
		})
	}
}

// TestParseNodeKeyReadsLegacySEC1 is the compatibility guarantee: responder
// keys already on disk were written with x509.MarshalECPrivateKey before any
// of this existed, and they must keep loading untouched.
func TestParseNodeKeyReadsLegacySEC1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	legacy, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	got, err := parseNodeKey(legacy)
	if err != nil {
		t.Fatalf("parseNodeKey: %v", err)
	}
	if !key.PublicKey.Equal(got.Public()) {
		t.Error("parsed key does not match the legacy SEC1 blob")
	}
}

func TestParseNodeKeyRejectsGarbage(t *testing.T) {
	if _, err := parseNodeKey([]byte("not a key")); err == nil {
		t.Error("parseNodeKey should reject a blob that is not a private key")
	}
}

// TestWarmNodeKeyIsReusedWhenItMatches proves the pre-generation actually
// saves the work: the key handed out is the one generated ahead of time, not a
// fresh one, so the first EST handshake does not pay for an RSA keygen.
func TestWarmNodeKeyIsReusedWhenItMatches(t *testing.T) {
	caPub := rsaCAPublic(t)
	w := warmNodeKey(config.RootKeyRSA3072)
	<-w.done

	w.mu.Lock()
	pre := w.key
	w.mu.Unlock()
	if pre == nil {
		t.Fatal("no key was pre-generated")
	}

	got, err := w.take(caPub)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if got != pre {
		t.Error("take returned a freshly generated key, not the pre-generated one")
	}
}

// TestWarmNodeKeyIsConsumedOnce makes sure the warm key is not handed to two
// credentials: a second caller must get its own key.
func TestWarmNodeKeyIsConsumedOnce(t *testing.T) {
	caPub := rsaCAPublic(t)
	w := warmNodeKey(config.RootKeyRSA3072)
	<-w.done

	first, err := w.take(caPub)
	if err != nil {
		t.Fatalf("take first: %v", err)
	}
	second, err := w.take(caPub)
	if err != nil {
		t.Fatalf("take second: %v", err)
	}
	if first == second {
		t.Error("the same key was handed out twice")
	}
}

// TestWarmNodeKeyIsDiscardedOnMismatch covers config drifting from the CA key
// actually on disk (a rekey, a hand-edited config): the CA key wins, because
// it is what determines the signature the relying party sees.
func TestWarmNodeKeyIsDiscardedOnMismatch(t *testing.T) {
	w := warmNodeKey(config.RootKeyECDSAP384)
	<-w.done

	got, err := w.take(rsaCAPublic(t))
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if _, ok := got.Public().(*rsa.PublicKey); !ok {
		t.Errorf("key type = %T, want an RSA key to match the RSA CA", got)
	}
}

// TestWarmNodeKeyWithoutAConfiguredAlgStillServes: maintenance mode and the
// pre-ceremony paths have no configured algorithm, and take must still work.
func TestWarmNodeKeyWithoutAConfiguredAlgStillServes(t *testing.T) {
	w := warmNodeKey("")
	<-w.done

	got, err := w.take(ecdsaCAPublic(t))
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if _, ok := got.Public().(*ecdsa.PublicKey); !ok {
		t.Errorf("key type = %T, want an ECDSA key to match the ECDSA CA", got)
	}
}
