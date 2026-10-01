package main

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
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// nodeCert returns the certificate the test node presents, as PEM and DER.
func nodeCert(t *testing.T, ts *testServer) ([]byte, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(ts.dir, "trust.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	return data, block.Bytes
}

// The node's listener demands a client certificate, but it sends its own
// first, so fetch has to work with no identity at all.
func TestTrustFetch_SavesTheNodeCertWithoutAnIdentity(t *testing.T) {
	ts := startTestServer(t)
	_, der := nodeCert(t, ts)
	out := filepath.Join(t.TempDir(), "sub", "node-trust.pem")

	stdout, err := ts.run(t, "--identity", filepath.Join(ts.dir, "absent.crt"), "--trust", out, "trust", "fetch")
	if err != nil {
		t.Fatalf("trust fetch: %v (out=%s)", err, stdout)
	}

	saved, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read saved pin: %v", err)
	}
	block, _ := pem.Decode(saved)
	if block == nil || !bytes.Equal(block.Bytes, der) {
		t.Fatalf("saved pin is not the node certificate:\n%s", saved)
	}
	if !strings.Contains(stdout, console.Fingerprint(der)) {
		t.Errorf("output does not show the SHA-256 in the console's form:\n%s", stdout)
	}
	if !strings.Contains(stdout, "not verified") {
		t.Errorf("an unchecked fetch must say it is not verified:\n%s", stdout)
	}
}

func TestTrustFetch_AcceptsAMatchingFingerprintInAnyCommonForm(t *testing.T) {
	ts := startTestServer(t)
	_, der := nodeCert(t, ts)
	grouped := console.Fingerprint(der)
	// openssl prints AB:CD:..., the console prints "ABCD EF01 ...".
	colon := strings.ToLower(strings.Join(splitPairs(strings.ReplaceAll(grouped, " ", "")), ":"))

	for _, want := range []string{grouped, colon} {
		out := filepath.Join(t.TempDir(), "node-trust.pem")
		stdout, err := ts.run(t, "--trust", out, "trust", "fetch", "--expect-sha256", want)
		if err != nil {
			t.Fatalf("trust fetch --expect-sha256 %q: %v (out=%s)", want, err, stdout)
		}
		if !strings.Contains(stdout, "verified") || strings.Contains(stdout, "not verified") {
			t.Errorf("a matched fetch must say it is verified:\n%s", stdout)
		}
		if _, err := os.Stat(out); err != nil {
			t.Errorf("matched fetch saved nothing: %v", err)
		}
	}
}

func TestTrustFetch_RefusesAMismatchAndSavesNothing(t *testing.T) {
	ts := startTestServer(t)
	out := filepath.Join(t.TempDir(), "node-trust.pem")
	wrong := strings.Repeat("AB", 32)

	stdout, err := ts.run(t, "--trust", out, "trust", "fetch", "--expect-sha256", wrong)
	if err == nil {
		t.Fatalf("trust fetch accepted a wrong fingerprint (out=%s)", stdout)
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error %q does not say the fingerprint did not match", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a mismatched certificate was saved (stat err %v)", err)
	}
}

func TestTrustFetch_RejectsAMalformedExpectedFingerprint(t *testing.T) {
	ts := startTestServer(t)
	out := filepath.Join(t.TempDir(), "node-trust.pem")

	if _, err := ts.run(t, "--trust", out, "trust", "fetch", "--expect-sha256", "ABCD"); err == nil {
		t.Fatal("trust fetch accepted a fingerprint that is not 32 bytes of hex")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a file was written despite the bad flag (stat err %v)", err)
	}
}

func splitPairs(s string) []string {
	var out []string
	for i := 0; i < len(s); i += 2 {
		out = append(out, s[i:i+2])
	}
	return out
}
