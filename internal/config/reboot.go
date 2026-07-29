package config

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

import "reflect"

// NeedsReboot reports whether applying newCfg over oldCfg on a running node
// requires a reboot for the change to take effect.
//
// The CA signer reads the live config on every operation, so a change limited
// to the cert profiles (pki.profiles) or the irreversible root-leaf-issuance
// acknowledgement (pki.root_leaf_issuance) takes effect immediately for
// signing — no reboot. Every other field (network, install disk, role, state
// key, the revocation endpoint that gates the boot-time CRL/OCSP listener,
// hostname, management link) is consumed at boot, so a change there still needs
// a reboot. This is deliberately conservative: only the two proven-hot fields
// are treated as hot; anything else falls through to "reboot".
func NeedsReboot(oldCfg, newCfg *Config) bool {
	if oldCfg == nil || newCfg == nil {
		return true
	}
	return !reflect.DeepEqual(hotNormalized(oldCfg), hotNormalized(newCfg))
}

// hotNormalized returns a copy of c with the hot-reconfigurable fields blanked,
// so DeepEqual on two normalized configs is true exactly when the only
// differences are hot fields.
func hotNormalized(c *Config) Config {
	n := *c
	n.PKI.Profiles = nil
	n.PKI.RootLeafIssuance = ""
	return n
}
