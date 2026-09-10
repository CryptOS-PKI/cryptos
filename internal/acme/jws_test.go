package acme

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
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// testKey is a signing key plus the JOSE alg it is used with.
type testKey struct {
	signer crypto.Signer
	alg    string
	jwk    *JWK
}

func newECTestKey(t *testing.T, curve elliptic.Curve, alg string) *testKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwk, err := JWKFromPublic(&k.PublicKey)
	if err != nil {
		t.Fatalf("JWKFromPublic: %v", err)
	}
	return &testKey{signer: k, alg: alg, jwk: jwk}
}

func newRSATestKey(t *testing.T, bits int, alg string) *testKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk, err := JWKFromPublic(&k.PublicKey)
	if err != nil {
		t.Fatalf("JWKFromPublic: %v", err)
	}
	return &testKey{signer: k, alg: alg, jwk: jwk}
}

// signJWS builds a flattened JSON JWS over payload with the given protected
// header members. payload nil produces the POST-as-GET empty payload.
func (k *testKey) signJWS(t *testing.T, header map[string]any, payload []byte) []byte {
	t.Helper()
	if header["alg"] == nil {
		header["alg"] = k.alg
	}
	hdrJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	protected := b64.EncodeToString(hdrJSON)
	encodedPayload := ""
	if payload != nil {
		encodedPayload = b64.EncodeToString(payload)
	}
	sig := k.rawSign(t, []byte(protected+"."+encodedPayload))

	body, err := json.Marshal(flattenedJWS{
		Protected: protected,
		Payload:   encodedPayload,
		Signature: b64.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("marshal jws: %v", err)
	}
	return body
}

// rawSign produces the JOSE signature over signingInput for k.alg.
func (k *testKey) rawSign(t *testing.T, signingInput []byte) []byte {
	t.Helper()
	spec, ok := jwsAlgs[k.alg]
	if !ok {
		t.Fatalf("test uses an alg the server does not implement: %s", k.alg)
	}
	digest := hashBytes(spec.hash, signingInput)

	switch key := k.signer.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			t.Fatalf("ecdsa.Sign: %v", err)
		}
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*byteLen)
		r.FillBytes(out[:byteLen])
		s.FillBytes(out[byteLen:])
		return out
	case *rsa.PrivateKey:
		if spec.pss {
			sig, err := rsa.SignPSS(rand.Reader, key, spec.hash, digest,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash})
			if err != nil {
				t.Fatalf("rsa.SignPSS: %v", err)
			}
			return sig
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, spec.hash, digest)
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		return sig
	default:
		t.Fatalf("unsupported test key %T", key)
		return nil
	}
}

// TestThumbprintRFC7638Vector checks the canonicalization against the worked
// example in RFC 7638 section 3.1. Getting this wrong would not fail any
// round-trip test -- the server would agree with itself -- but every real
// client computes the same thumbprint from the spec, and a mismatch would
// make every key authorization fail.
func TestThumbprintRFC7638Vector(t *testing.T) {
	jwk := &JWK{
		Kty: "RSA",
		N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3okn" +
			"jhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQ" +
			"vRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKn" +
			"qDKgw",
		E: "AQAB",
	}
	got, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

func TestVerifyJWSRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  *testKey
	}{
		{"ES256", newECTestKey(t, elliptic.P256(), "ES256")},
		{"ES384", newECTestKey(t, elliptic.P384(), "ES384")},
		{"RS256", newRSATestKey(t, 2048, "RS256")},
		{"PS256", newRSATestKey(t, 2048, "PS256")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.key.signJWS(t, map[string]any{
				"nonce": "n", "url": "https://ca.example/acme/new-order", "jwk": tc.key.jwk,
			}, []byte(`{"hello":"world"}`))

			jws, hdr, payload, err := parseJWS(body)
			if err != nil {
				t.Fatalf("parseJWS: %v", err)
			}
			if string(payload) != `{"hello":"world"}` {
				t.Fatalf("payload = %q", payload)
			}
			pub, err := hdr.JWK.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			if err := verifyJWS(jws, hdr.Alg, pub); err != nil {
				t.Fatalf("verifyJWS: %v", err)
			}
		})
	}
}

// TestVerifyJWSRejectsTamperedPayload is the property the whole protocol rests
// on: a payload changed after signing must not verify.
func TestVerifyJWSRejectsTamperedPayload(t *testing.T) {
	key := newECTestKey(t, elliptic.P256(), "ES256")
	body := key.signJWS(t, map[string]any{
		"nonce": "n", "url": "https://ca.example/acme/new-order", "jwk": key.jwk,
	}, []byte(`{"identifiers":[{"type":"dns","value":"mine.example"}]}`))

	var env flattenedJWS
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Payload = b64.EncodeToString([]byte(`{"identifiers":[{"type":"dns","value":"yours.example"}]}`))
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	jws, hdr, _, err := parseJWS(tampered)
	if err != nil {
		t.Fatalf("parseJWS: %v", err)
	}
	pub, err := hdr.JWK.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if err := verifyJWS(jws, hdr.Alg, pub); err == nil {
		t.Fatal("a tampered payload verified")
	}
}

// TestVerifyJWSAlgorithmConfusion covers the classic JOSE attack surface: a
// header naming an algorithm that does not belong to the key must be refused
// before any verification is attempted, and "none" must not exist at all.
func TestVerifyJWSAlgorithmConfusion(t *testing.T) {
	ec := newECTestKey(t, elliptic.P256(), "ES256")
	rsaKey := newRSATestKey(t, 2048, "RS256")

	for _, tc := range []struct {
		name string
		key  *testKey
		alg  string
	}{
		{"rsa alg with an ec key", ec, "RS256"},
		{"ec alg with an rsa key", rsaKey, "ES256"},
		{"ES256 header over a P-384 key", newECTestKey(t, elliptic.P384(), "ES384"), "ES256"},
		{"none", ec, "none"},
		{"HS256 on the outer JWS", ec, "HS256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.key.signJWS(t, map[string]any{
				"nonce": "n", "url": "https://ca.example/acme/new-order", "jwk": tc.key.jwk,
			}, []byte(`{}`))
			jws, _, _, err := parseJWS(body)
			if err != nil {
				t.Fatalf("parseJWS: %v", err)
			}
			pub, err := tc.key.jwk.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			if err := verifyJWS(jws, tc.alg, pub); err == nil {
				t.Fatalf("alg %q verified against a %s key", tc.alg, tc.key.alg)
			}
		})
	}
}

func TestVerifyJWSRejectsSmallRSAKey(t *testing.T) {
	key := newRSATestKey(t, 1024, "RS256")
	body := key.signJWS(t, map[string]any{
		"nonce": "n", "url": "https://ca.example/acme/new-account", "jwk": key.jwk,
	}, []byte(`{}`))
	jws, _, _, err := parseJWS(body)
	if err != nil {
		t.Fatalf("parseJWS: %v", err)
	}
	pub, err := key.jwk.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	err = verifyJWS(jws, "RS256", pub)
	var prob *Problem
	if !errors.As(err, &prob) || prob.Type != ErrBadPublicKey {
		t.Fatalf("err = %v, want a badPublicKey problem", err)
	}
}

func TestParseJWSStructuralRules(t *testing.T) {
	key := newECTestKey(t, elliptic.P256(), "ES256")
	const url = "https://ca.example/acme/new-order"

	for _, tc := range []struct {
		name   string
		body   []byte
		expect string
	}{
		{
			name:   "neither jwk nor kid",
			body:   key.signJWS(t, map[string]any{"nonce": "n", "url": url}, []byte(`{}`)),
			expect: "exactly one of jwk or kid",
		},
		{
			name: "both jwk and kid",
			body: key.signJWS(t, map[string]any{
				"nonce": "n", "url": url, "jwk": key.jwk, "kid": "https://ca.example/acme/account/x",
			}, []byte(`{}`)),
			expect: "exactly one of jwk or kid",
		},
		{
			name:   "no url",
			body:   key.signJWS(t, map[string]any{"nonce": "n", "jwk": key.jwk}, []byte(`{}`)),
			expect: "omits url",
		},
		{
			name: "crit",
			body: key.signJWS(t, map[string]any{
				"nonce": "n", "url": url, "jwk": key.jwk, "crit": []string{"exp"},
			}, []byte(`{}`)),
			expect: "crit",
		},
		{
			name:   "not json",
			body:   []byte("not json"),
			expect: "flattened JSON JWS",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseJWS(tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.expect)
			}
		})
	}
}

// TestParseJWSRejectsUnprotectedHeader guards the case where a member the
// signature does not cover could otherwise influence a decision.
func TestParseJWSRejectsUnprotectedHeader(t *testing.T) {
	key := newECTestKey(t, elliptic.P256(), "ES256")
	body := key.signJWS(t, map[string]any{
		"nonce": "n", "url": "https://ca.example/acme/new-order", "jwk": key.jwk,
	}, []byte(`{}`))
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env["header"] = map[string]any{"kid": "someone-else"}
	withHeader, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, _, _, err := parseJWS(withHeader); err == nil {
		t.Fatal("a JWS with an unprotected header parsed")
	}
}

func TestJWKPublicKeyRejectsBadKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		jwk  *JWK
	}{
		{"unknown kty", &JWK{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(make([]byte, 32))}},
		{"unsupported curve", &JWK{Kty: "EC", Crv: "P-521", X: "AA", Y: "AA"}},
		{"short coordinate", &JWK{Kty: "EC", Crv: "P-256", X: "AA", Y: "AA"}},
		{"point off curve", &JWK{
			Kty: "EC", Crv: "P-256",
			X: b64.EncodeToString(big.NewInt(1).FillBytes(make([]byte, 32))),
			Y: b64.EncodeToString(big.NewInt(1).FillBytes(make([]byte, 32))),
		}},
		{"even rsa exponent", &JWK{Kty: "RSA", N: b64.EncodeToString(make([]byte, 256)), E: b64.EncodeToString([]byte{0x04})}},
		{"empty rsa modulus", &JWK{Kty: "RSA", N: "", E: "AQAB"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.jwk.PublicKey(); err == nil {
				t.Fatal("a malformed JWK produced a public key")
			}
		})
	}
}

// signEAB builds an external account binding over accountKey.
func signEAB(t *testing.T, keyID string, macKey []byte, alg, url string, accountKey *JWK) *flattenedJWS {
	t.Helper()
	hdr, err := json.Marshal(map[string]any{"alg": alg, "kid": keyID, "url": url})
	if err != nil {
		t.Fatalf("marshal eab header: %v", err)
	}
	payload, err := json.Marshal(accountKey)
	if err != nil {
		t.Fatalf("marshal account key: %v", err)
	}
	protected := b64.EncodeToString(hdr)
	encoded := b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(protected + "." + encoded))
	return &flattenedJWS{
		Protected: protected,
		Payload:   encoded,
		Signature: b64.EncodeToString(mac.Sum(nil)),
	}
}

func TestVerifyExternalAccountBinding(t *testing.T) {
	const keyID = "ops-team"
	const url = "https://ca.example/acme/new-account"
	macKey := []byte("0123456789abcdef0123456789abcdef")
	lookup := StaticEABKeys(map[string][]byte{keyID: macKey})
	account := newECTestKey(t, elliptic.P256(), "ES256")

	t.Run("accepts a well-formed binding", func(t *testing.T) {
		eab := signEAB(t, keyID, macKey, "HS256", url, account.jwk)
		got, err := verifyExternalAccountBinding(eab, url, account.jwk, lookup)
		if err != nil {
			t.Fatalf("verifyExternalAccountBinding: %v", err)
		}
		if got != keyID {
			t.Fatalf("key id = %q, want %q", got, keyID)
		}
	})

	t.Run("rejects a wrong mac key", func(t *testing.T) {
		eab := signEAB(t, keyID, []byte("ffffffffffffffffffffffffffffffff"), "HS256", url, account.jwk)
		if _, err := verifyExternalAccountBinding(eab, url, account.jwk, lookup); err == nil {
			t.Fatal("a binding with the wrong MAC key was accepted")
		}
	})

	t.Run("rejects an unknown key id", func(t *testing.T) {
		eab := signEAB(t, "who", macKey, "HS256", url, account.jwk)
		if _, err := verifyExternalAccountBinding(eab, url, account.jwk, lookup); err == nil {
			t.Fatal("a binding naming an unprovisioned key id was accepted")
		}
	})

	// A binding captured from one account must not be reusable to register a
	// different key: the inner payload is the account key precisely so it
	// cannot be re-pointed.
	t.Run("rejects a binding for a different key", func(t *testing.T) {
		other := newECTestKey(t, elliptic.P256(), "ES256")
		eab := signEAB(t, keyID, macKey, "HS256", url, other.jwk)
		if _, err := verifyExternalAccountBinding(eab, url, account.jwk, lookup); err == nil {
			t.Fatal("a binding for another key was accepted")
		}
	})

	t.Run("rejects a binding for a different url", func(t *testing.T) {
		eab := signEAB(t, keyID, macKey, "HS256", "https://ca.example/acme/new-order", account.jwk)
		if _, err := verifyExternalAccountBinding(eab, url, account.jwk, lookup); err == nil {
			t.Fatal("a binding bound to another url was accepted")
		}
	})

	t.Run("rejects a missing binding", func(t *testing.T) {
		_, err := verifyExternalAccountBinding(nil, url, account.jwk, lookup)
		var prob *Problem
		if !errors.As(err, &prob) || prob.Type != ErrExternalAccountRequired {
			t.Fatalf("err = %v, want an externalAccountRequired problem", err)
		}
	})
}

func TestKeyAuthorization(t *testing.T) {
	if got := KeyAuthorization("tok", "thumb"); got != "tok.thumb" {
		t.Fatalf("KeyAuthorization = %q", got)
	}
}
