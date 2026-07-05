package bootstrap

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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCert mints a self-signed ECDSA P-256 certificate for tests and
// returns its DER and PEM forms.
func testCert(t *testing.T, cn string, notAfter time.Time) (der []byte, pemStr string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Acme Admins"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return der, pemStr
}

func TestLoadTrust(t *testing.T) {
	der, pemStr := testCert(t, "bootstrap-admin", time.Now().Add(24*time.Hour))
	wantFP := sha256.Sum256(der)

	tests := []struct {
		name    string
		pemArg  string
		shaArg  string
		wantErr string
		check   func(t *testing.T, tr *Trust)
	}{
		{
			name:   "pem path",
			pemArg: pemStr,
			check: func(t *testing.T, tr *Trust) {
				if !tr.HasCertificate() {
					t.Error("HasCertificate = false, want true")
				}
				if tr.Fingerprint() != wantFP {
					t.Errorf("Fingerprint = %x, want %x", tr.Fingerprint(), wantFP)
				}
				if _, ok := tr.ClientCAPool(); !ok {
					t.Error("ClientCAPool ok = false, want true for PEM path")
				}
			},
		},
		{
			name:   "fingerprint path",
			shaArg: hex.EncodeToString(wantFP[:]),
			check: func(t *testing.T, tr *Trust) {
				if tr.HasCertificate() {
					t.Error("HasCertificate = true, want false")
				}
				if tr.Fingerprint() != wantFP {
					t.Errorf("Fingerprint = %x, want %x", tr.Fingerprint(), wantFP)
				}
				if _, ok := tr.ClientCAPool(); ok {
					t.Error("ClientCAPool ok = true, want false for fingerprint path")
				}
				if _, ok := tr.Admin(); ok {
					t.Error("Admin ok = true, want false for fingerprint path")
				}
			},
		},
		{
			name:    "both set",
			pemArg:  pemStr,
			shaArg:  hex.EncodeToString(wantFP[:]),
			wantErr: "exactly one",
		},
		{
			name:    "neither set",
			wantErr: "no bootstrap admin credential",
		},
		{
			name:    "bad hex fingerprint",
			shaArg:  "zz" + strings.Repeat("0", 62),
			wantErr: "not hex",
		},
		{
			name:    "short fingerprint",
			shaArg:  "abcd",
			wantErr: "must be 32 bytes",
		},
		{
			name:    "not a cert pem",
			pemArg:  "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
			wantErr: "want CERTIFICATE",
		},
		{
			name:    "garbage pem",
			pemArg:  "not pem at all",
			wantErr: "no PEM block",
		},
		{
			name:    "two cert blocks",
			pemArg:  pemStr + pemStr,
			wantErr: "exactly one PEM block",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := LoadTrust(tc.pemArg, tc.shaArg)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadTrust err = nil, want substring %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadTrust err = %q, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadTrust err = %v, want nil", err)
			}
			if tc.check != nil {
				tc.check(t, tr)
			}
		})
	}
}

func TestVerifyPeerCertificate(t *testing.T) {
	der, pemStr := testCert(t, "admin", time.Now().Add(24*time.Hour))
	otherDER, _ := testCert(t, "intruder", time.Now().Add(24*time.Hour))

	for _, mode := range []string{"pem", "fingerprint"} {
		t.Run(mode, func(t *testing.T) {
			var pemArg, shaArg string
			if mode == "pem" {
				pemArg = pemStr
			} else {
				fp := sha256.Sum256(der)
				shaArg = hex.EncodeToString(fp[:])
			}
			tr, err := LoadTrust(pemArg, shaArg)
			if err != nil {
				t.Fatalf("LoadTrust: %v", err)
			}

			if err := tr.VerifyPeerCertificate([][]byte{der}, nil); err != nil {
				t.Errorf("VerifyPeerCertificate(match) = %v, want nil", err)
			}
			if err := tr.VerifyPeerCertificate([][]byte{otherDER}, nil); err == nil {
				t.Error("VerifyPeerCertificate(mismatch) = nil, want error")
			}
			if err := tr.VerifyPeerCertificate(nil, nil); err == nil {
				t.Error("VerifyPeerCertificate(empty) = nil, want error")
			}
		})
	}
}

func TestExpired(t *testing.T) {
	_, expiredPEM := testCert(t, "old-admin", time.Now().Add(-time.Hour))
	tr, err := LoadTrust(expiredPEM, "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	if !tr.Expired(time.Now()) {
		t.Error("Expired(now) = false for an already-expired cert, want true")
	}
	if tr.Expired(time.Now().Add(-2 * time.Hour)) {
		t.Error("Expired(before notAfter) = true, want false")
	}

	// Fingerprint-only trust has no validity window.
	fp := sha256.Sum256([]byte("anything"))
	tfp, err := LoadTrust("", hex.EncodeToString(fp[:]))
	if err != nil {
		t.Fatalf("LoadTrust fingerprint: %v", err)
	}
	if tfp.Expired(time.Now()) {
		t.Error("fingerprint-only Expired = true, want false")
	}
}

func TestAdminRecord(t *testing.T) {
	der, pemStr := testCert(t, "the-admin", time.Now().Add(48*time.Hour))
	tr, err := LoadTrust(pemStr, "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	a, ok := tr.Admin()
	if !ok {
		t.Fatal("Admin ok = false, want true")
	}
	if want := sha256.Sum256(der); a.SHA256 != want {
		t.Errorf("Admin.SHA256 = %x, want %x", a.SHA256, want)
	}
	if !strings.Contains(a.Subject, "the-admin") {
		t.Errorf("Admin.Subject = %q, want it to contain CN", a.Subject)
	}
	if !bytes.Equal(a.CertDER, der) {
		t.Error("Admin.CertDER does not match input DER")
	}
	if !strings.Contains(a.CertPEM, "BEGIN CERTIFICATE") {
		t.Errorf("Admin.CertPEM not PEM: %q", a.CertPEM)
	}

	// AdminFromCertDER yields an equivalent record.
	a2, err := AdminFromCertDER(der)
	if err != nil {
		t.Fatalf("AdminFromCertDER: %v", err)
	}
	if a2.SHA256 != a.SHA256 || a2.Subject != a.Subject {
		t.Error("AdminFromCertDER record differs from Trust.Admin record")
	}
	if _, err := AdminFromCertDER(nil); err == nil {
		t.Error("AdminFromCertDER(nil) = nil error, want error")
	}
	if _, err := AdminFromCertDER([]byte("garbage")); err == nil {
		t.Error("AdminFromCertDER(garbage) = nil error, want error")
	}
}
