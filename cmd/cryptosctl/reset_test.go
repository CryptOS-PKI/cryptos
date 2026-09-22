package main

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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

// recordingResetter stands in for the node's resetter. It records the
// confirmation it was handed, so the tests can assert the destructive call is
// never reached when the operator has not confirmed.
type recordingResetter struct {
	err error

	called bool
	lastCN string
}

func (r *recordingResetter) Reset(_ context.Context, confirmCommonName string) error {
	r.called = true
	r.lastCN = confirmCommonName

	return r.err
}

func startResetServer(t *testing.T, rst cgrpc.Resetter) *testServer {
	t.Helper()

	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.RemoteResetter = rst

		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

// The verb #216 is for: an operator can re-provision an established node
// without writing a gRPC client.
func TestReset_DrivesRemoteResetWithTheConfirmation(t *testing.T) {
	rst := &recordingResetter{}
	ts := startResetServer(t, rst)

	out, err := ts.run(t, "reset", "--confirm", "Interborough Root CA G1", "--yes")
	if err != nil {
		t.Fatalf("reset: %v (out=%s)", err, out)
	}
	if !rst.called {
		t.Fatal("the node's resetter was never called")
	}
	if rst.lastCN != "Interborough Root CA G1" {
		t.Errorf("confirm CN = %q, want it passed through for the constant-time compare", rst.lastCN)
	}
}

// Erasing a CA's key material on a typo is not recoverable, so the flag is
// required and its absence must stop the command before it dials.
func TestReset_RefusesWithoutAConfirmation(t *testing.T) {
	rst := &recordingResetter{}
	ts := startResetServer(t, rst)

	if _, err := ts.run(t, "reset", "--yes"); err == nil {
		t.Fatal("reset proceeded with no --confirm")
	}
	if rst.called {
		t.Error("the node was contacted despite a missing confirmation")
	}
}

// A wrong CN is refused by the node. The operator must see that as a failure,
// not as a reset that quietly did nothing.
func TestReset_ReportsAMismatchedConfirmation(t *testing.T) {
	rst := &recordingResetter{err: reset.ErrConfirmMismatch}
	ts := startResetServer(t, rst)

	out, err := ts.run(t, "reset", "--confirm", "Wrong CA", "--yes")
	if err == nil {
		t.Fatalf("reset reported success on a mismatched confirmation (out=%s)", out)
	}
	if !rst.called {
		t.Error("the node should still be consulted; it owns the constant-time compare")
	}
}

// Without --yes the operator has to type the CN, and anything else aborts
// before the node is contacted.
func TestReset_InteractiveConfirmationMustMatch(t *testing.T) {
	rst := &recordingResetter{}
	ts := startResetServer(t, rst)

	out, err := ts.runWithStdin(t, "not the ca name\n", "reset", "--confirm", "Interborough Root CA G1")
	if err == nil {
		t.Fatalf("reset proceeded on a mistyped confirmation (out=%s)", out)
	}
	if rst.called {
		t.Error("the node was contacted despite a mistyped confirmation")
	}
}

func TestReset_InteractiveConfirmationAccepted(t *testing.T) {
	rst := &recordingResetter{}
	ts := startResetServer(t, rst)

	out, err := ts.runWithStdin(t, "Interborough Root CA G1\n", "reset", "--confirm", "Interborough Root CA G1")
	if err != nil {
		t.Fatalf("reset: %v (out=%s)", err, out)
	}
	if !rst.called {
		t.Error("the node's resetter was never called")
	}
	if !strings.Contains(out, "WARNING") {
		t.Errorf("no warning shown before a destructive reset:\n%s", out)
	}
}
