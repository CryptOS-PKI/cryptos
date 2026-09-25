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
	"google.golang.org/protobuf/types/known/timestamppb"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/revocation"
)

// revocationPreflightStatus reports p's latest check for GetStatus: whether the
// base URL host resolves and /crl, /ocsp and /ca.cer answer. baseURL is the
// configured pki.revocation_base_url; when it is empty the preflight never
// runs and the state is NOT_CONFIGURED. Before the first check finishes the
// state is PENDING.
func revocationPreflightStatus(baseURL string, p *revocation.Preflight) *cryptosv1.RevocationPreflight {
	if baseURL == "" {
		return &cryptosv1.RevocationPreflight{State: cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_NOT_CONFIGURED}
	}
	r := p.Result()
	if !r.Checked {
		return &cryptosv1.RevocationPreflight{State: cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_PENDING, BaseUrl: baseURL}
	}
	st := &cryptosv1.RevocationPreflight{
		State:     cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_OK,
		BaseUrl:   baseURL,
		CheckedAt: timestamppb.New(r.CheckedAt),
	}
	if !r.OK {
		st.State = cryptosv1.RevocationPreflightState_REVOCATION_PREFLIGHT_STATE_FAILING
		st.LastError = r.Err
	}
	return st
}
