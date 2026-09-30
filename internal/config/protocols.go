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

import (
	"errors"
	"fmt"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// The enrolment protocol blocks (pki.acme, pki.est, pki.scep) travel in MachineConfig
// under one set of rules, shared by every protocol that gains a block:
//
//   - In the proto, a block carries an explicit enabled flag. ToProto always
//     sends one, so a whole config is explicit about every protocol, and an off
//     protocol goes out as enabled=false. FromProto turns enabled=false, or a
//     missing block, into nil, which is how this package spells "off".
//   - Applied over a stored config (FromProtoOver), a missing block keeps the
//     stored one. A client that predates a block therefore cannot switch a
//     protocol off by leaving it out.
//   - Secrets are write-only. ToProtoRedacted blanks them for GetConfig, and
//     FromProtoOver fills an empty secret from the stored entry with the same
//     identifier, so a read, edit, apply cycle keeps them. An empty secret for
//     an identifier the node does not know is refused.
//   - A Root serves no enrolment protocol (Root Mode closes the service-plane
//     listeners), so Validate refuses a Root with either block set.
//   - Every protocol field is read at boot, so NeedsReboot classifies any
//     change to a block, including the switch itself, as reboot-required.

// validateProtocolRole refuses an enrolment protocol on a Root.
func validateProtocolRole(role RoleKind, p PKI) error {
	if role != RoleRoot {
		return nil
	}
	if p.ACME != nil {
		return errors.New("config: pki.acme: must not be set on a root node; a root serves no " +
			"enrolment protocol, so serve ACME from an intermediate or issuing node")
	}
	if p.EST != nil {
		return errors.New("config: pki.est: must not be set on a root node; a root serves no " +
			"enrolment protocol, so serve EST from an intermediate or issuing node")
	}
	return nil
}

// ToProtoRedacted is ToProto with the protocol secrets blanked, for handing a
// config to a reader. The credential identifiers stay, so a caller can see
// which credentials exist and send the config back unchanged.
func (c *Config) ToProtoRedacted() *cryptosv1.MachineConfig {
	pb := c.ToProto()
	for _, k := range pb.GetPki().GetAcme().GetExternalAccountKeys() {
		k.HmacKeyBase64 = ""
	}
	for _, cred := range pb.GetPki().GetEst().GetEnrollCredentials() {
		cred.PasswordSha256 = ""
	}
	return pb
}

// FromProtoOver converts an applied proto into the config to store over prev,
// the config the node holds now (nil when it holds none, as in a maintenance
// install). It is FromProto plus the protocol-block rules above: a missing
// block keeps prev's, and an empty secret is taken from prev's entry with the
// same identifier. The result still has to pass Validate.
func FromProtoOver(pb *cryptosv1.MachineConfig, prev *Config) (*Config, error) {
	c, err := FromProto(pb)
	if err != nil {
		return nil, err
	}
	var prevACME *ACME
	var prevEST *EST
	if prev != nil {
		prevACME, prevEST = prev.PKI.ACME, prev.PKI.EST
	}

	if pb.GetPki().GetAcme() == nil {
		c.PKI.ACME = prevACME
	} else if c.PKI.ACME != nil {
		if err := keepACMESecrets(c.PKI.ACME, prevACME); err != nil {
			return nil, err
		}
	}
	if pb.GetPki().GetEst() == nil {
		c.PKI.EST = prevEST
	} else if c.PKI.EST != nil {
		if err := keepESTSecrets(c.PKI.EST, prevEST); err != nil {
			return nil, err
		}
	}
	c.KeepStoredSCEPWhenAbsent(pb, prev)
	return c, nil
}

func keepACMESecrets(next, prev *ACME) error {
	stored := map[string]string{}
	if prev != nil {
		for _, k := range prev.ExternalAccountKeys {
			stored[k.KeyID] = k.HMACKeyBase64
		}
	}
	for i := range next.ExternalAccountKeys {
		k := &next.ExternalAccountKeys[i]
		if k.HMACKeyBase64 != "" {
			continue
		}
		secret, ok := stored[k.KeyID]
		if !ok {
			return fmt.Errorf("config: pki.acme.external_account_keys[%d].hmac_key_base64: empty, and the node "+
				"has no stored key for key_id %q to keep; send the secret for a new key", i, k.KeyID)
		}
		k.HMACKeyBase64 = secret
	}
	return nil
}

func keepESTSecrets(next, prev *EST) error {
	stored := map[string]string{}
	if prev != nil {
		for _, cred := range prev.EnrollCredentials {
			stored[cred.Username] = cred.PasswordSHA256
		}
	}
	for i := range next.EnrollCredentials {
		cred := &next.EnrollCredentials[i]
		if cred.PasswordSHA256 != "" {
			continue
		}
		digest, ok := stored[cred.Username]
		if !ok {
			return fmt.Errorf("config: pki.est.enroll_credentials[%d].password_sha256: empty, and the node "+
				"has no stored credential for username %q to keep; send the digest for a new credential", i, cred.Username)
		}
		cred.PasswordSHA256 = digest
	}
	return nil
}

func acmeToProto(a *ACME) *cryptosv1.Acme {
	if a == nil {
		return &cryptosv1.Acme{Enabled: false}
	}
	pb := &cryptosv1.Acme{
		Enabled:                   true,
		BaseUrl:                   a.BaseURL,
		HttpPort:                  a.HTTPPort,
		Profile:                   a.Profile,
		TermsOfService:            a.TermsOfService,
		Website:                   a.Website,
		AllowAnonymousAccounts:    a.AllowAnonymousAccounts,
		AllowedIdentifierSuffixes: a.AllowedIdentifierSuffixes,
		OrderTtlHours:             a.OrderTTLHours,
	}
	for _, k := range a.ExternalAccountKeys {
		pb.ExternalAccountKeys = append(pb.ExternalAccountKeys, &cryptosv1.AcmeExternalAccountKey{
			KeyId:         k.KeyID,
			HmacKeyBase64: k.HMACKeyBase64,
		})
	}
	return pb
}

func acmeFromProto(pb *cryptosv1.Acme) *ACME {
	if !pb.GetEnabled() {
		return nil
	}
	a := &ACME{
		BaseURL:                   pb.GetBaseUrl(),
		HTTPPort:                  pb.GetHttpPort(),
		Profile:                   pb.GetProfile(),
		TermsOfService:            pb.GetTermsOfService(),
		Website:                   pb.GetWebsite(),
		AllowAnonymousAccounts:    pb.GetAllowAnonymousAccounts(),
		AllowedIdentifierSuffixes: pb.GetAllowedIdentifierSuffixes(),
		OrderTTLHours:             pb.GetOrderTtlHours(),
	}
	for _, k := range pb.GetExternalAccountKeys() {
		a.ExternalAccountKeys = append(a.ExternalAccountKeys, ExternalAccountKey{
			KeyID:         k.GetKeyId(),
			HMACKeyBase64: k.GetHmacKeyBase64(),
		})
	}
	return a
}

func estToProto(e *EST) *cryptosv1.Est {
	if e == nil {
		return &cryptosv1.Est{Enabled: false}
	}
	pb := &cryptosv1.Est{
		Enabled:                   true,
		Hostnames:                 e.Hostnames,
		HttpPort:                  e.HTTPPort,
		Profile:                   e.Profile,
		Label:                     e.Label,
		Realm:                     e.Realm,
		AllowedIdentifierSuffixes: e.AllowedIdentifierSuffixes,
		AllowAnyIdentifier:        e.AllowAnyIdentifier,
	}
	for _, cred := range e.EnrollCredentials {
		pb.EnrollCredentials = append(pb.EnrollCredentials, &cryptosv1.EstEnrollCredential{
			Username:       cred.Username,
			PasswordSha256: cred.PasswordSHA256,
		})
	}
	return pb
}

func estFromProto(pb *cryptosv1.Est) *EST {
	if !pb.GetEnabled() {
		return nil
	}
	e := &EST{
		Hostnames:                 pb.GetHostnames(),
		HTTPPort:                  pb.GetHttpPort(),
		Profile:                   pb.GetProfile(),
		Label:                     pb.GetLabel(),
		Realm:                     pb.GetRealm(),
		AllowedIdentifierSuffixes: pb.GetAllowedIdentifierSuffixes(),
		AllowAnyIdentifier:        pb.GetAllowAnyIdentifier(),
	}
	for _, cred := range pb.GetEnrollCredentials() {
		e.EnrollCredentials = append(e.EnrollCredentials, ESTEnrollCredential{
			Username:       cred.GetUsername(),
			PasswordSHA256: cred.GetPasswordSha256(),
		})
	}
	return e
}
