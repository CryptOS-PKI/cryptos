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
	"strings"
	"testing"
	"time"
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

// The preflight probes every path the signer stamps: the CRL, the OCSP
// responder and the AIA caIssuers certificate. A base URL whose /ca.cer does
// not answer must fail, since relying parties would chase a dead pointer.
func TestPreflightProbesEveryStampedPath(t *testing.T) {
	var probed []string
	p := NewPreflight("http://pki.acme.example/",
		func(host string) error { return nil },
		func(url string) error { probed = append(probed, url); return nil })
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	want := []string{"http://pki.acme.example/crl", "http://pki.acme.example/ocsp", "http://pki.acme.example/ca.cer"}
	if len(probed) != len(want) {
		t.Fatalf("probed %v, want %v", probed, want)
	}
	for i := range want {
		if probed[i] != want[i] {
			t.Fatalf("probed %v, want %v", probed, want)
		}
	}

	p = NewPreflight("http://pki.acme.example",
		func(host string) error { return nil },
		func(url string) error {
			if url == "http://pki.acme.example/ca.cer" {
				return errors.New("404 is fine but connection refused is not")
			}
			return nil
		})
	if err := p.Check(context.Background()); !errors.Is(err, ErrPreflightFailed) || p.OK() {
		t.Fatalf("an unreachable /ca.cer must fail the preflight, err=%v ok=%v", err, p.OK())
	}
}

// Result exposes the latest check so the status surface can report it: not
// checked yet, then the failure and when it happened, then the recovery.
func TestPreflightResultReportsTheLatestCheck(t *testing.T) {
	reachable := false
	p := NewPreflight("http://pki.acme.example",
		func(host string) error { return nil },
		func(url string) error {
			if !reachable {
				return errors.New("connection refused")
			}
			return nil
		})

	if r := p.Result(); r.Checked || r.OK || r.Err != "" || !r.CheckedAt.IsZero() {
		t.Fatalf("before any check: %+v, want the zero result", r)
	}

	before := time.Now()
	_ = p.Check(context.Background())
	r := p.Result()
	if !r.Checked || r.OK {
		t.Fatalf("after a failing check: %+v, want checked and not OK", r)
	}
	if !strings.Contains(r.Err, "connection refused") {
		t.Errorf("Err = %q, want the probe failure", r.Err)
	}
	if r.CheckedAt.Before(before) {
		t.Errorf("CheckedAt = %v, want at or after %v", r.CheckedAt, before)
	}

	reachable = true
	_ = p.Check(context.Background())
	if r := p.Result(); !r.Checked || !r.OK || r.Err != "" {
		t.Fatalf("after a passing check: %+v, want OK with no error", r)
	}
}
