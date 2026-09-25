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

// recordingRebooter stands in for the node's rebooter.
type recordingRebooter struct {
	err      error
	called   bool
	cn       string
	powerOff bool
}

func (r *recordingRebooter) Reboot(_ context.Context, confirmCommonName string, powerOff bool) error {
	r.called = true
	r.cn = confirmCommonName
	r.powerOff = powerOff

	return r.err
}

func startRebootServer(t *testing.T, rb cgrpc.Rebooter) *testServer {
	t.Helper()

	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.Rebooter = rb

		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

// Rebooting an issuing CA is an outage, so the CLI must not let it happen
// without the operator naming the CA.
func TestReboot_RequiresTheConfirmation(t *testing.T) {
	rb := &recordingRebooter{}
	ts := startRebootServer(t, rb)

	if _, err := ts.run(t, "reboot"); err == nil {
		t.Fatal("reboot succeeded with no confirmation")
	}
	if rb.called {
		t.Error("the node was contacted despite a missing confirmation")
	}
}

func TestReboot_RestartsByDefault(t *testing.T) {
	rb := &recordingRebooter{}
	ts := startRebootServer(t, rb)

	out, err := ts.run(t, "reboot", "--confirm", "Interborough Root CA G1")
	if err != nil {
		t.Fatalf("reboot: %v", err)
	}
	if rb.cn != "Interborough Root CA G1" || rb.powerOff {
		t.Errorf("rebooter got cn=%q powerOff=%t", rb.cn, rb.powerOff)
	}
	if !strings.Contains(out, "rebooting") {
		t.Errorf("output %q does not say the node is rebooting", out)
	}
}

func TestReboot_PowerOff(t *testing.T) {
	rb := &recordingRebooter{}
	ts := startRebootServer(t, rb)

	out, err := ts.run(t, "reboot", "--confirm", "Interborough Root CA G1", "--power-off")
	if err != nil {
		t.Fatalf("reboot --power-off: %v", err)
	}
	if !rb.powerOff {
		t.Error("--power-off was not passed to the node")
	}
	if !strings.Contains(out, "powering off") {
		t.Errorf("output %q does not say the node is powering off", out)
	}
}

// A wrong confirmation must surface as a refusal, not as a success the
// operator then waits on a reboot for.
func TestReboot_ReportsAMismatchedConfirmation(t *testing.T) {
	ts := startRebootServer(t, &recordingRebooter{err: reset.ErrConfirmMismatch})

	if _, err := ts.run(t, "reboot", "--confirm", "Wrong CA"); err == nil {
		t.Fatal("reboot reported success on a mismatched confirmation")
	}
}
