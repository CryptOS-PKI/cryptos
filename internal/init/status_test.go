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
	"context"
	"errors"
	"strings"
	"testing"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/revocation"
)

func TestRevocationPreflightStatus(t *testing.T) {
	const base = "http://pki.example.org"
	ok := func(string) error { return nil }
	fail := func(string) error { return errors.New("no such host") }

	t.Run("not configured", func(t *testing.T) {
		got := revocationPreflightStatus("", revocation.NewPreflight("", ok, ok))
		if got.GetState() != cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_NOT_CONFIGURED || got.GetBaseUrl() != "" {
			t.Fatalf("got %v, want NOT_CONFIGURED with no base URL", got)
		}
	})

	t.Run("pending", func(t *testing.T) {
		got := revocationPreflightStatus(base, revocation.NewPreflight(base, ok, ok))
		if got.GetState() != cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_PENDING || got.GetCheckedAt() != nil {
			t.Fatalf("got %v, want PENDING with no checked_at", got)
		}
		if got.GetBaseUrl() != base {
			t.Errorf("base_url = %q, want %q", got.GetBaseUrl(), base)
		}
	})

	t.Run("failing", func(t *testing.T) {
		p := revocation.NewPreflight(base, fail, ok)
		_ = p.Check(context.Background())
		got := revocationPreflightStatus(base, p)
		if got.GetState() != cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_FAILING {
			t.Fatalf("state = %v, want FAILING", got.GetState())
		}
		if !strings.Contains(got.GetLastError(), "no such host") {
			t.Errorf("last_error = %q, want the resolver failure", got.GetLastError())
		}
		if got.GetCheckedAt() == nil {
			t.Error("checked_at unset after a check")
		}
	})

	// The preflight probes /ca.cer as well as /crl and /ocsp, since the signer
	// stamps an AIA caIssuers pointer at it. A dead /ca.cer reads as FAILING,
	// with the path in the error so the operator knows which endpoint to fix.
	t.Run("failing on ca.cer", func(t *testing.T) {
		p := revocation.NewPreflight(base, ok, func(url string) error {
			if strings.HasSuffix(url, "/ca.cer") {
				return errors.New("connection refused")
			}
			return nil
		})
		_ = p.Check(context.Background())
		got := revocationPreflightStatus(base, p)
		if got.GetState() != cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_FAILING {
			t.Fatalf("state = %v, want FAILING", got.GetState())
		}
		if !strings.Contains(got.GetLastError(), base+"/ca.cer") {
			t.Errorf("last_error = %q, want it to name %s/ca.cer", got.GetLastError(), base)
		}
	})

	t.Run("ok", func(t *testing.T) {
		p := revocation.NewPreflight(base, ok, ok)
		_ = p.Check(context.Background())
		got := revocationPreflightStatus(base, p)
		if got.GetState() != cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_OK || got.GetLastError() != "" || got.GetCheckedAt() == nil {
			t.Fatalf("got %v, want OK with checked_at and no error", got)
		}
	})
}
