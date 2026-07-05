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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"

	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

// buildSubordinateCSR builds the DER-encoded PKCS#10 certificate signing
// request a subordinate CA presents to its parent. The request is signed by
// the node's freshly generated CA key with ECDSAWithSHA384 (the Phase 1/2
// P-384 profile). It is pure and testable with any ecdsa.PrivateKey.
func buildSubordinateCSR(signer crypto.Signer, subject pkix.Name) (csrDER []byte, err error) {
	if signer == nil {
		return nil, errors.New("init: buildSubordinateCSR: nil signer")
	}
	tmpl := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return nil, fmt.Errorf("init: buildSubordinateCSR: %w", err)
	}
	return der, nil
}

// subordinateSubject builds the subordinate CA's pkix.Name from the node's
// configured PKI subject, omitting empty RDNs. It mirrors the Root ceremony's
// subjectFromConfig so a subordinate names its own CA the same way the Root
// names itself.
func subordinateSubject(cfg *config.Config) pkix.Name {
	n := pkix.Name{CommonName: cfg.PKI.RootSubject.CommonName}
	if o := cfg.PKI.RootSubject.Organization; o != "" {
		n.Organization = []string{o}
	}
	if c := cfg.PKI.RootSubject.Country; c != "" {
		n.Country = []string{c}
	}
	return n
}

// stageSubordinateIfNeeded runs the subordinate first-boot key generation.
// On a subordinate (intermediate/issuing) node with no identity yet, it
// creates the CA key through the same RootKeyBackend the ceremony would use,
// builds the CSR, and stages both under PhaseAwaitingCert via the store. It
// is a no-op for a Root (that runs the self-signing ceremony instead) and for
// a subordinate that has already staged its CSR (PhaseAwaitingCert) or
// committed its chain (PhaseIdentityEstablished): those boots load normally.
//
// It fails closed: any error from key creation, CSR building, or staging is
// returned so PID 1 reboots rather than serve a half-provisioned subordinate.
func stageSubordinateIfNeeded(ctx context.Context, cfg *config.Config, store *node.Store, backend ceremony.RootKeyBackend) error {
	if cfg.Role.Kind == config.RoleRoot {
		return nil
	}

	// Already committed a chain: steady state, load normally.
	hasIdentity, err := store.HasIdentity(ctx)
	if err != nil {
		return fmt.Errorf("init: subordinate boot: check identity: %w", err)
	}
	if hasIdentity {
		return nil
	}

	// Already staged a CSR on a prior boot: wait for the signed chain.
	phase, err := store.Phase(ctx)
	if err != nil {
		return fmt.Errorf("init: subordinate boot: read phase: %w", err)
	}
	if phase == node.PhaseAwaitingCert {
		return nil
	}

	// First boot for this subordinate: create the CA key and stage the CSR.
	if err := backend.ProvisionSRK(); err != nil {
		return fmt.Errorf("init: subordinate boot: provision SRK: %w", err)
	}
	created, err := backend.CreateKey(tpm.AlgorithmECDSAP384)
	if err != nil {
		return fmt.Errorf("init: subordinate boot: create key: %w", err)
	}
	signer, err := backend.LoadKey(created.Private, created.Public)
	if err != nil {
		return fmt.Errorf("init: subordinate boot: load key: %w", err)
	}
	defer func() { _ = signer.Close() }()

	csrDER, err := buildSubordinateCSR(signer, subordinateSubject(cfg))
	if err != nil {
		return err
	}
	if err := store.StageSubordinate(ctx, csrDER, created.Private, created.Public); err != nil {
		return fmt.Errorf("init: subordinate boot: stage: %w", err)
	}
	return nil
}
