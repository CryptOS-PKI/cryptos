package config

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

	"gopkg.in/yaml.v3"
)

// NeedsReboot reports whether applying newCfg over oldCfg on a running node
// requires a reboot for the change to take effect.
//
// The CA signer reads the live config on every operation, so a change limited
// to the cert profiles (pki.profiles), the irreversible root-leaf-issuance
// acknowledgement (pki.root_leaf_issuance), the revocation preflight override
// (pki.allow_unverified_revocation_url) or the clock-gate override
// (pki.allow_unsynced_clock) takes effect immediately for signing — no reboot. Every other field (network, install disk, role, state key, the
// revocation endpoint that gates the boot-time CRL/OCSP listener, hostname,
// management link) is consumed at boot, so a change there still needs a
// reboot. This is deliberately conservative: only the proven-hot fields are
// treated as hot; anything else falls through to "reboot".
func NeedsReboot(oldCfg, newCfg *Config) bool {
	if oldCfg == nil || newCfg == nil {
		return true
	}
	return !Equivalent(hotNormalized(oldCfg), hotNormalized(newCfg))
}

// Equivalent reports whether a and b store as the same YAML. It is the
// comparison for "would this change what the node boots from": a config that
// crossed the wire has nil where the stored YAML parsed an empty list, and
// reflect.DeepEqual calls those different, so an unchanged re-apply read as a
// reboot-required change. A value that fails to marshal compares unequal,
// which errs toward a reboot.
func Equivalent(a, b any) bool {
	ra, err := yaml.Marshal(a)
	if err != nil {
		return false
	}
	rb, err := yaml.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ra, rb)
}

// hotNormalized returns a copy of c with the hot-reconfigurable fields blanked,
// so two normalized configs are Equivalent exactly when the only differences
// are hot fields.
func hotNormalized(c *Config) Config {
	n := *c
	n.PKI.Profiles = nil
	n.PKI.RootLeafIssuance = ""
	n.PKI.AllowUnverifiedRevocationURL = false
	n.PKI.AllowUnsyncedClock = false
	return n
}
