package config

/*
Apache License 2.0

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
	"crypto/x509"
	"fmt"
	"time"
)

// ValidityPolicy decides what issuance does when a profile's validity_days
// would run past the issuing CA's own notAfter.
type ValidityPolicy string

const (
	// ValidityPolicyCap ends the certificate at the issuer's notAfter. It is
	// the default, and an empty value means the same.
	ValidityPolicyCap ValidityPolicy = "cap"
	// ValidityPolicyReject refuses to issue.
	ValidityPolicyReject ValidityPolicy = "reject"
)

// Valid reports whether v is empty or a known policy.
func (v ValidityPolicy) Valid() bool {
	return v == "" || v == ValidityPolicyCap || v == ValidityPolicyReject
}

// ProfileValidityWarnings returns one warning per profile whose validity_days,
// counted from now, already runs past issuer's notAfter. It is advisory, not a
// validation error: the CA's remaining lifetime shrinks every day, so every
// profile eventually crosses it. A nil issuer (a node with no CA certificate
// yet) yields none.
func (c *Config) ProfileValidityWarnings(issuer *x509.Certificate, now time.Time) []string {
	if issuer == nil {
		return nil
	}
	var out []string
	for _, p := range c.PKI.Profiles {
		end := now.Add(time.Duration(p.ValidityDays) * 24 * time.Hour)
		if !end.After(issuer.NotAfter) {
			continue
		}
		outcome := "its certificates will be capped to that date"
		if p.ValidityPolicy == ValidityPolicyReject {
			outcome = "issuance from it will be refused while validity_policy is reject"
		}
		out = append(out, fmt.Sprintf("profile %q: validity_days %d runs past this CA's notAfter %s; %s",
			p.Name, p.ValidityDays, issuer.NotAfter.UTC().Format(time.DateOnly), outcome))
	}
	return out
}
