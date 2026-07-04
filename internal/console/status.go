package console

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
	"crypto/x509"
	"encoding/pem"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// RootCN parses the leaf certificate of id.ChainPem (PEM, leaf-first) and
// returns its Subject CommonName. It returns "" when id is nil or the first
// PEM block cannot be parsed.
func RootCN(id *cryptosv1.Identity) string {
	if id == nil || id.ChainPem == "" {
		return ""
	}
	block, _ := pem.Decode([]byte(id.ChainPem))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

// roleLabel maps a NodeRole enum to its short display string.
func roleLabel(r cryptosv1.NodeRole) string {
	switch r {
	case cryptosv1.NodeRole_NODE_ROLE_ROOT:
		return "ROOT"
	case cryptosv1.NodeRole_NODE_ROLE_INTERMEDIATE:
		return "INTERMEDIATE"
	case cryptosv1.NodeRole_NODE_ROLE_ISSUING:
		return "ISSUING"
	default:
		return "UNKNOWN"
	}
}

// identityLabel maps an IdentityState enum to its short display string.
func identityLabel(s cryptosv1.IdentityState) string {
	switch s {
	case cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED:
		return "ESTABLISHED"
	case cryptosv1.IdentityState_IDENTITY_STATE_CEREMONY_IN_PROGRESS:
		return "establishing"
	default:
		return "maintenance"
	}
}

// tpmLabel maps a TpmState enum to its short display string. Only the OK state
// reports a sealed identity; every other state is surfaced as UNAVAILABLE.
func tpmLabel(s cryptosv1.TpmState) string {
	if s == cryptosv1.TpmState_TPM_STATE_OK {
		return "SEALED"
	}
	return "UNAVAILABLE"
}

// ViewFromAPI maps the node status, identity, and a measured uptime into the
// dashboard View. Fleet defaults to FleetNotEnrolled in M2; M4 wires the real
// value. Maintenance is set whenever the identity is not established.
func ViewFromAPI(st *cryptosv1.NodeStatus, id *cryptosv1.Identity, uptime time.Duration) View {
	v := View{
		RootCN: RootCN(id),
		Uptime: uptime,
		Fleet:  FleetNotEnrolled,
	}
	if st != nil {
		v.Role = roleLabel(st.Role)
		v.NodeStatus = identityLabel(st.IdentityState)
		v.TPM = tpmLabel(st.TpmState)
		v.Version = st.SoftwareVersion
		v.Maintenance = st.IdentityState != cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED
	}
	return v
}
