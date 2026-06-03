package luks

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
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/tpm"
)

func TestBuildAndSplitBlobs_Synthetic(t *testing.T) {
	// A TPM2B-framed private blob: 2-byte big-endian size, then payload.
	private := []byte{0x00, 0x03, 'a', 'b', 'c'}
	public := []byte("PUBLIC-BLOB-BYTES")

	tok, err := BuildTPM2Token(private, public, 1, []int{7, 11}, []byte{0xde, 0xad})
	if err != nil {
		t.Fatalf("BuildTPM2Token: %v", err)
	}
	if tok.Type != TPM2TokenType {
		t.Errorf("Type = %q, want %q", tok.Type, TPM2TokenType)
	}
	if len(tok.Keyslots) != 1 || tok.Keyslots[0] != "1" {
		t.Errorf("Keyslots = %v, want [\"1\"]", tok.Keyslots)
	}
	if tok.PolicyHash != "dead" {
		t.Errorf("PolicyHash = %q, want dead", tok.PolicyHash)
	}

	gotPriv, gotPub, err := tok.SealedBlobs()
	if err != nil {
		t.Fatalf("SealedBlobs: %v", err)
	}
	if !bytes.Equal(gotPriv, private) {
		t.Errorf("private = %x, want %x", gotPriv, private)
	}
	if !bytes.Equal(gotPub, public) {
		t.Errorf("public = %x, want %x", gotPub, public)
	}
}

func TestSealToTokenToUnseal_RoundTrip(t *testing.T) {
	tp, err := tpm.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	if err := tp.ProvisionSRK(); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	priv, pub, err := tp.SealToPCR(secret, tpm.DefaultSealPCRs)
	if err != nil {
		t.Fatalf("SealToPCR: %v", err)
	}

	// Build the token, round-trip it through JSON, then recover the blobs
	// and unseal — proving the token framing matches what tpm produces.
	tok, err := BuildTPM2Token(priv, pub, 0, tpm.DefaultSealPCRs, nil)
	if err != nil {
		t.Fatalf("BuildTPM2Token: %v", err)
	}
	js, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := ParseTPM2Token(js)
	if err != nil {
		t.Fatalf("ParseTPM2Token: %v", err)
	}
	gotPriv, gotPub, err := parsed.SealedBlobs()
	if err != nil {
		t.Fatalf("SealedBlobs: %v", err)
	}
	got, err := tp.UnsealWithPCR(gotPriv, gotPub, parsed.PCRs)
	if err != nil {
		t.Fatalf("UnsealWithPCR (from token): %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("unsealed-from-token data mismatch")
	}
}

func TestBuildTPM2Token_Validation(t *testing.T) {
	tests := []struct {
		name      string
		priv, pub []byte
		keyslot   int
		pcrs      []int
	}{
		{"unframed private", []byte{0x00}, []byte("p"), 0, []int{7}},
		{"empty public", []byte{0x00, 0x01, 'x'}, nil, 0, []int{7}},
		{"negative keyslot", []byte{0x00, 0x01, 'x'}, []byte("p"), -1, []int{7}},
		{"no pcrs", []byte{0x00, 0x01, 'x'}, []byte("p"), 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildTPM2Token(tc.priv, tc.pub, tc.keyslot, tc.pcrs, nil); err == nil {
				t.Errorf("BuildTPM2Token(%s) = nil error, want error", tc.name)
			}
		})
	}
}

func TestParseTPM2Token_Errors(t *testing.T) {
	if _, err := ParseTPM2Token([]byte("not json")); err == nil {
		t.Error("ParseTPM2Token(garbage) = nil, want error")
	}
	if _, err := ParseTPM2Token([]byte(`{"type":"systemd-tpm2","tpm-blob":"x"}`)); err == nil {
		t.Error("ParseTPM2Token(wrong type) = nil, want error")
	}
	if _, err := ParseTPM2Token([]byte(`{"type":"cryptos-tpm2"}`)); err == nil {
		t.Error("ParseTPM2Token(empty blob) = nil, want error")
	}
}

func TestSealedBlobs_BadFraming(t *testing.T) {
	for _, blob := range []string{
		"",   // empty -> base64 decodes to nothing
		"//", // valid base64, 1 byte, too short
	} {
		tok := &TPM2Token{Type: TPM2TokenType, Blob: blob}
		if _, _, err := tok.SealedBlobs(); err == nil {
			t.Errorf("SealedBlobs(%q) = nil error, want error", blob)
		}
	}
	// Private size word claims more than the blob holds.
	overrun := &TPM2Token{Type: TPM2TokenType, Blob: encodeBlob([]byte{0xff, 0xff, 'a'})}
	if _, _, err := overrun.SealedBlobs(); err == nil {
		t.Error("SealedBlobs(overrun) = nil error, want error")
	}
}

func TestImportToken_Args(t *testing.T) {
	mock := &mockRunner{}
	d := &Device{Path: "/dev/mapper/x", Runner: mock}
	tokenJSON := []byte(`{"type":"cryptos-tpm2","tpm-blob":"AA"}`)
	if err := d.ImportToken(context.Background(), 2, tokenJSON); err != nil {
		t.Fatalf("ImportToken: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(mock.calls))
	}
	call := mock.calls[0]
	wantArgs := []string{"token", "import", "--token-id", "2", "/dev/mapper/x"}
	if strings.Join(call.args, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("args = %v, want %v", call.args, wantArgs)
	}
	if !bytes.Equal(call.stdin, tokenJSON) {
		t.Errorf("stdin = %q, want %q", call.stdin, tokenJSON)
	}
	if err := d.ImportToken(context.Background(), 0, nil); err == nil {
		t.Error("ImportToken(empty json) = nil error, want error")
	}
}

func TestExportToken_Args(t *testing.T) {
	want := []byte(`{"type":"cryptos-tpm2","tpm-blob":"AA"}`)
	mock := &mockRunner{stdout: want}
	d := &Device{Path: "/dev/sdb", Runner: mock}
	got, err := d.ExportToken(context.Background(), 3)
	if err != nil {
		t.Fatalf("ExportToken: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ExportToken returned %q, want %q", got, want)
	}
	call := mock.calls[0]
	wantArgs := []string{"token", "export", "--token-id", "3", "/dev/sdb"}
	if strings.Join(call.args, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("args = %v, want %v", call.args, wantArgs)
	}
}

// encodeBlob base64-encodes raw bytes for token blob test fixtures.
func encodeBlob(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}
