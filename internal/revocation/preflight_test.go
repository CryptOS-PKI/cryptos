package revocation

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
	"errors"
	"testing"
)

func TestPreflightFailsOnUnresolvableHost(t *testing.T) {
	p := NewPreflight("http://pki.acme.example",
		func(host string) error { return errors.New("no such host") },
		func(url string) error { return nil })
	if err := p.Check(context.Background()); err == nil || p.OK() {
		t.Fatal("expected preflight failure on DNS error")
	}
}

func TestPreflightPassesWhenResolvableAndReachable(t *testing.T) {
	p := NewPreflight("http://pki.acme.example",
		func(host string) error { return nil },
		func(url string) error { return nil })
	if err := p.Check(context.Background()); err != nil || !p.OK() {
		t.Fatalf("expected pass, err=%v ok=%v", err, p.OK())
	}
}

// Ensure re-checks on demand when the cached result is not OK, so a
// subordinate's first issuance after establishment self-heals instead of
// waiting for the next periodic tick. Once OK, Ensure does not re-probe.
func TestPreflightEnsureRechecksWhenNotOK(t *testing.T) {
	reachable := false
	probes := 0
	p := NewPreflight("http://pki.acme.example",
		func(host string) error { return nil },
		func(url string) error {
			probes++
			if !reachable {
				return errors.New("connection refused")
			}
			return nil
		})
	// Not OK yet, and no Check has run.
	if p.Ensure(context.Background()) {
		t.Fatal("Ensure returned true before any successful check")
	}
	reachable = true
	if !p.Ensure(context.Background()) {
		t.Fatal("Ensure did not re-check and recover once the endpoint was reachable")
	}
	probesAfterOK := probes
	if p.Ensure(context.Background()); probes != probesAfterOK {
		t.Fatal("Ensure re-probed even though the cached result was already OK")
	}
}

// The node's own /crl endpoint is not listening when the first preflight runs,
// so OK() must recover on a later re-check once the probe starts succeeding.
// This is why run.go re-checks periodically instead of probing once.
func TestPreflightRecoversOnRecheck(t *testing.T) {
	reachable := false
	p := NewPreflight("http://pki.acme.example",
		func(host string) error { return nil },
		func(url string) error {
			if !reachable {
				return errors.New("connection refused")
			}
			return nil
		})
	if err := p.Check(context.Background()); err == nil || p.OK() {
		t.Fatal("expected initial preflight failure while endpoint is down")
	}
	reachable = true
	if err := p.Check(context.Background()); err != nil || !p.OK() {
		t.Fatalf("expected recovery on re-check, err=%v ok=%v", err, p.OK())
	}
}
