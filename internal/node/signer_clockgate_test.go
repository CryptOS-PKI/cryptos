package node

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
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// A configured time source that has not synced yet closes the gate: every
// signing path refuses with FailedPrecondition, before the CA key is loaded.
func TestClockGateRefusesSigningWhileUnsynced(t *testing.T) {
	f := newSignerFixture(t)
	cfg := caProfileConfig(config.RoleIssuing)
	loaded := false
	load, issuer, get := f.loaders(cfg, new(bool))
	wrapped := func(ctx context.Context) (crypto.Signer, func(), error) {
		loaded = true
		return load(ctx)
	}
	s := NewCASigner(wrapped, issuer, get).WithClockGate(func() bool { return false })

	_, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server")
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(status.Convert(err).Message(), "allow_unsynced_clock") {
		t.Fatalf("refusal %q does not name the override", err)
	}
	_, _, err = s.IssueLeafForNames(context.Background(), makeCSR(t, "node.example"), "leaf-server", []string{"node.example"})
	wantCode(t, err, codes.FailedPrecondition)
	_, _, err = s.IssueLeafWithRequestSANs(context.Background(), makeCSR(t, "node.example"), "leaf-server", nil)
	wantCode(t, err, codes.FailedPrecondition)

	sub := NewCASigner(wrapped, issuer, func(context.Context) (*config.Config, error) {
		return caProfileConfig(config.RoleIntermediate), nil
	}).WithClockGate(func() bool { return false })
	_, _, _, err = sub.SignSubordinate(context.Background(), makeCSR(t, "Child CA"), "sub-ca")
	wantCode(t, err, codes.FailedPrecondition)

	if loaded {
		t.Fatal("the CA key was loaded although the clock gate refused")
	}
}

func TestClockGateAllowsSigningOnceSynced(t *testing.T) {
	f := newSignerFixture(t)
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), new(bool))
	s := NewCASigner(load, issuer, get).WithClockGate(func() bool { return true })
	if _, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server"); err != nil {
		t.Fatalf("IssueLeaf with a synced clock: %v", err)
	}
}

func TestClockGateOverrideAllowsSigningWhileUnsynced(t *testing.T) {
	f := newSignerFixture(t)
	cfg := caProfileConfig(config.RoleIntermediate)
	cfg.PKI.AllowUnsyncedClock = true
	load, issuer, get := f.loaders(cfg, new(bool))
	s := NewCASigner(load, issuer, get).WithClockGate(func() bool { return false })
	if _, _, _, err := s.SignSubordinate(context.Background(), makeCSR(t, "Child CA"), "sub-ca"); err != nil {
		t.Fatalf("SignSubordinate with allow_unsynced_clock: %v", err)
	}
}

// With no time source the node wires no gate (or one that always passes), so
// signing is never gated.
func TestNoClockGateNeverGates(t *testing.T) {
	f := newSignerFixture(t)
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), new(bool))
	s := NewCASigner(load, issuer, get)
	if _, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server"); err != nil {
		t.Fatalf("IssueLeaf with no clock gate: %v", err)
	}
}

// Every certificate the signer returns reports its notBefore, so the clock
// floor can be raised past it.
func TestIssuedHookSeesEveryNotBefore(t *testing.T) {
	f := newSignerFixture(t)
	load, issuer, get := f.loaders(caProfileConfig(config.RoleIssuing), new(bool))
	var seen []time.Time
	s := NewCASigner(load, issuer, get).WithIssuedHook(func(nb time.Time) { seen = append(seen, nb) })
	before := time.Now().Add(-time.Second)
	if _, err := s.IssueLeaf(context.Background(), makeCSR(t, "node.example"), "leaf-server"); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Before(before) {
		t.Fatalf("issued hook saw %v", seen)
	}
}
