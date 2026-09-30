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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CryptOS-PKI/cryptos/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

func TestCAKeyExportableOnlyOffTPM(t *testing.T) {
	for mode, want := range map[string]bool{
		config.StateKeyModeTPM:    false,
		config.StateKeyModeNodeID: true,
		config.StateKeyModeKMS:    true,
	} {
		if got := caKeyExportable(mode); got != want {
			t.Errorf("caKeyExportable(%q) = %v, want %v", mode, got, want)
		}
	}
}

// TestExportRefusedForTPMRSACA pins that an RSA CA on a TPM node is as
// non-exportable as the ECDSA one: the refusal follows the state-key mode, not
// the key algorithm.
func TestExportRefusedForTPMRSACA(t *testing.T) {
	s, ctx := newEscrowStore(t)
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "RSA TPM Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	// On a TPM node the stored blobs are the TPM-wrapped key, which escrow
	// never gets as far as reading; opaque bytes stand in for them here.
	commitCA(t, s, ctx, []byte("tpm-wrapped-private"), []byte("tpm-public"), [][]byte{der})

	exp := newCAEscrow(s, caKeyExportable(config.StateKeyModeTPM))
	if _, err := exp.ExportCAKey(ctx, []byte("operator-passphrase")); !errors.Is(err, cgrpc.ErrNotExportable) {
		t.Fatalf("ExportCAKey for a TPM-held RSA CA = %v, want ErrNotExportable", err)
	}
}

// TestBeginRotation_RSAOnTPMWithoutSize_FailsPrecondition: CA-key rotation
// creates a new key through the same backend as the ceremony, so on a TPM
// without the configured RSA size (the in-process simulator implements
// RSA-2048 only) it must refuse the same way, and stage nothing.
func TestBeginRotation_RSAOnTPMWithoutSize_FailsPrecondition(t *testing.T) {
	s, ctx := newRekeyStore(t)
	keyBlob, keyPub, chain := makeSoftCA(t, "Child Issuing CA")
	commitCA(t, s, ctx, keyBlob, keyPub, chain)

	parent := newRekeyParent(t)
	trust, err := bootstrap.LoadTrust(certPEM(parent.der), "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	enr, err := node.NewSubordinateEnroller(s, trust)
	if err != nil {
		t.Fatalf("NewSubordinateEnroller: %v", err)
	}
	sim, err := tpm.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })

	cfg := rekeyConfig()
	cfg.PKI.RootKeyAlg = config.RootKeyRSA3072
	r, err := newRekeyer(s, NewTPMRootBackend(sim), cfg, enr)
	if err != nil {
		t.Fatalf("newRekeyer: %v", err)
	}
	_, err = r.BeginRotation(ctx)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("BeginRotation(RSA-3072 on a TPM without it) code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "RSA-3072") {
		t.Errorf("error %q does not name RSA-3072", err)
	}
	if _, ok, _ := s.RotationCSR(ctx); ok {
		t.Error("BeginRotation staged a rotation despite the TPM lacking RSA-3072")
	}
}
