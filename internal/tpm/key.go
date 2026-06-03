package tpm

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// KeyAlgorithm selects the curve + hash for a created signing key.
type KeyAlgorithm int

const (
	// AlgorithmECDSAP384 is the algorithm used for Root CA keys in Phase 1.
	// It pairs ECDSA on NIST P-384 with SHA-384.
	AlgorithmECDSAP384 KeyAlgorithm = iota + 1
)

// Key is a signing key resident in the TPM and currently loaded under
// the SRK. Implements crypto.Signer.
//
// Key is not safe for concurrent use. Callers must Close exactly once
// to release the transient handle inside the TPM.
type Key struct {
	tpm    *TPM
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pub    *ecdsa.PublicKey
	alg    KeyAlgorithm
}

// CreatedKey holds the artifacts returned by CreateKey. Private and
// Public are the TPM-wrapped key blobs the caller persists and later
// restores with LoadKey. CreationData and CreationTicket are the TPM
// creation evidence recorded in the Ceremony Manifest's
// key_creation_attestation (RFC-agnostic TPM 2.0 structures, marshaled).
type CreatedKey struct {
	// Private is the marshaled TPM2B_PRIVATE blob (wrapped private key).
	Private []byte
	// Public is the marshaled TPM2B_PUBLIC blob.
	Public []byte
	// CreationData is the marshaled TPM2B_CREATION_DATA.
	CreationData []byte
	// CreationTicket is the marshaled TPMT_TK_CREATION ticket.
	CreationTicket []byte
}

// CreateKey creates a new signing key under the persisted SRK and
// returns the wrapped key blobs plus the TPM creation evidence. The
// plaintext private key never leaves the TPM. Callers persist
// Private/Public (typically to the encrypted state partition) and later
// restore them with LoadKey.
//
// ProvisionSRK must have run successfully (in this boot or a previous
// one) before calling CreateKey.
func (t *TPM) CreateKey(alg KeyAlgorithm) (*CreatedKey, error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, err
	}
	template, err := publicTemplate(alg)
	if err != nil {
		return nil, err
	}
	srkName, err := readSRKName(rwc)
	if err != nil {
		return nil, err
	}

	resp, err := (tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(SRKPersistentHandle),
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(template),
	}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: CreateKey: Create: %w", err)
	}

	return &CreatedKey{
		Private:        tpm2.Marshal(resp.OutPrivate),
		Public:         tpm2.Marshal(resp.OutPublic),
		CreationData:   tpm2.Marshal(resp.CreationData),
		CreationTicket: tpm2.Marshal(resp.CreationTicket),
	}, nil
}

// LoadKey loads a previously-created signing key into the TPM as a
// transient object under the SRK and returns a Key implementing
// crypto.Signer. The caller is responsible for Close().
func (t *TPM) LoadKey(private, public []byte) (*Key, error) {
	rwc, err := t.transport()
	if err != nil {
		return nil, err
	}

	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](private)
	if err != nil {
		return nil, fmt.Errorf("tpm: LoadKey: unmarshal private: %w", err)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](public)
	if err != nil {
		return nil, fmt.Errorf("tpm: LoadKey: unmarshal public: %w", err)
	}

	srkName, err := readSRKName(rwc)
	if err != nil {
		return nil, err
	}

	loaded, err := (tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(SRKPersistentHandle),
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: *priv,
		InPublic:  *pub,
	}).Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("tpm: LoadKey: Load: %w", err)
	}

	publicTemplate, err := pub.Contents()
	if err != nil {
		_, _ = (tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(rwc))
		return nil, fmt.Errorf("tpm: LoadKey: public contents: %w", err)
	}
	ecdsaPub, alg, err := parseECDSAPublic(publicTemplate)
	if err != nil {
		_, _ = (tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(rwc))
		return nil, err
	}

	return &Key{
		tpm:    t,
		handle: loaded.ObjectHandle,
		name:   loaded.Name,
		pub:    ecdsaPub,
		alg:    alg,
	}, nil
}

// Close flushes the loaded key from the TPM. Calling Close twice or
// after the parent TPM has closed is a safe no-op.
func (k *Key) Close() error {
	if k == nil || k.tpm == nil || k.tpm.rwc == nil {
		return nil
	}
	if _, err := (tpm2.FlushContext{FlushHandle: k.handle}.Execute(k.tpm.rwc)); err != nil {
		return fmt.Errorf("tpm: Key.Close: FlushContext: %w", err)
	}
	k.tpm = nil
	return nil
}

// publicTemplate builds the TPMTPublic template for the requested
// algorithm. ECDSA P-384 is the only Phase 1 option.
func publicTemplate(alg KeyAlgorithm) (tpm2.TPMTPublic, error) {
	if alg != AlgorithmECDSAP384 {
		return tpm2.TPMTPublic{}, fmt.Errorf("tpm: unsupported KeyAlgorithm %d", alg)
	}
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA384,
				}),
			},
			CurveID: tpm2.TPMECCNistP384,
		}),
	}, nil
}

// parseECDSAPublic extracts a crypto/ecdsa.PublicKey from the TPM-returned
// public template.
func parseECDSAPublic(t *tpm2.TPMTPublic) (*ecdsa.PublicKey, KeyAlgorithm, error) {
	if t.Type != tpm2.TPMAlgECC {
		return nil, 0, fmt.Errorf("tpm: parseECDSAPublic: not an ECC key (type=0x%x)", t.Type)
	}
	parms, err := t.Parameters.ECCDetail()
	if err != nil {
		return nil, 0, fmt.Errorf("tpm: parseECDSAPublic: ECC parameters: %w", err)
	}
	if parms.CurveID != tpm2.TPMECCNistP384 {
		return nil, 0, fmt.Errorf("tpm: parseECDSAPublic: unexpected curve 0x%x", parms.CurveID)
	}
	point, err := t.Unique.ECC()
	if err != nil {
		return nil, 0, fmt.Errorf("tpm: parseECDSAPublic: ECC point: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     new(big.Int).SetBytes(point.X.Buffer),
		Y:     new(big.Int).SetBytes(point.Y.Buffer),
	}
	// The TPM generated this point and the curve check it ran is
	// authoritative; the stdlib IsOnCurve API is deprecated, so we
	// don't re-validate on this side.
	return pub, AlgorithmECDSAP384, nil
}

// readSRKName reads the public Name of the persistent SRK so that it
// can be used in AuthHandle for subsequent commands.
func readSRKName(rwc transport.TPM) (tpm2.TPM2BName, error) {
	pub, err := (tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(SRKPersistentHandle),
	}).Execute(rwc)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("tpm: readSRKName: %w", err)
	}
	return pub.Name, nil
}
