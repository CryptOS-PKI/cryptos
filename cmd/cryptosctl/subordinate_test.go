package main

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
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// runCmd executes the root command with args against no server; it is used
// to exercise the pre-dial argument validation.
func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestSignSubordinateRequiresFlags(t *testing.T) {
	if _, err := runCmd(t, "ca", "sign-subordinate", "--profile", "issuing"); err == nil {
		t.Error("sign-subordinate without --csr = nil, want error")
	}
	if _, err := runCmd(t, "ca", "sign-subordinate", "--csr", "x.csr"); err == nil {
		t.Error("sign-subordinate without --profile = nil, want error")
	}
}

func TestIssueLeafRegistered(t *testing.T) {
	ca := newCACmd(&globalOpts{})
	var found *cobra.Command
	for _, sub := range ca.Commands() {
		if sub.Name() == "issue-leaf" {
			found = sub
			break
		}
	}
	if found == nil {
		t.Fatal("issue-leaf not registered under ca")
	}
	if found.Flags().Lookup("csr") == nil {
		t.Error("issue-leaf missing --csr flag")
	}
	if found.Flags().Lookup("profile") == nil {
		t.Error("issue-leaf missing --profile flag")
	}
}

func TestIssueLeafRequiresFlags(t *testing.T) {
	if _, err := runCmd(t, "ca", "issue-leaf", "--profile", "server"); err == nil {
		t.Error("issue-leaf without --csr = nil, want error")
	}
	if _, err := runCmd(t, "ca", "issue-leaf", "--csr", "x.csr"); err == nil {
		t.Error("issue-leaf without --profile = nil, want error")
	}
}

func TestSubmitSubordinateCertRequiresChain(t *testing.T) {
	if _, err := runCmd(t, "ca", "submit-subordinate-cert"); err == nil {
		t.Error("submit-subordinate-cert without --chain = nil, want error")
	}
}

func TestRotateKeyRegistered(t *testing.T) {
	ca := newCACmd(&globalOpts{})
	names := map[string]bool{}
	for _, sub := range ca.Commands() {
		names[sub.Name()] = true
	}
	if !names["rotate-key"] {
		t.Error("rotate-key not registered under ca")
	}
	if !names["submit-rotation"] {
		t.Error("submit-rotation not registered under ca")
	}
}

func TestSubmitRotationRequiresChain(t *testing.T) {
	if _, err := runCmd(t, "ca", "submit-rotation"); err == nil {
		t.Error("submit-rotation without --chain = nil, want error")
	}
}

func TestReadCertDER(t *testing.T) {
	der := selfSignedCA(t)
	dir := t.TempDir()

	// PEM input.
	pemPath := filepath.Join(dir, "cert.pem")
	writeFile(t, pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	got, err := readCertDER(pemPath, "CERTIFICATE")
	if err != nil {
		t.Fatalf("readCertDER(pem): %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Error("readCertDER(pem) did not return the embedded DER")
	}

	// Raw DER input (no PEM block) falls back to the raw bytes.
	derPath := filepath.Join(dir, "cert.der")
	writeFile(t, derPath, der)
	got, err = readCertDER(derPath, "CERTIFICATE")
	if err != nil {
		t.Fatalf("readCertDER(der): %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Error("readCertDER(der) did not return the raw DER")
	}

	if _, err := readCertDER(filepath.Join(dir, "missing"), "CERTIFICATE"); err == nil {
		t.Error("readCertDER(missing) = nil, want error")
	}
}

func TestChainToDER(t *testing.T) {
	leaf := selfSignedCA(t)
	root := selfSignedCA(t)
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: root})

	chain, err := chainToDER(buf.Bytes())
	if err != nil {
		t.Fatalf("chainToDER: %v", err)
	}
	if len(chain) != 2 || !bytes.Equal(chain[0], leaf) || !bytes.Equal(chain[1], root) {
		t.Errorf("chainToDER returned %d certs, want leaf-first 2", len(chain))
	}

	if _, err := chainToDER(nil); err == nil {
		t.Error("chainToDER(nil) = nil, want error")
	}
}

func TestWriteChainPEM(t *testing.T) {
	// Prefers server PEM when present.
	var buf bytes.Buffer
	if err := writeChainPEM(&buf, "PEM-STRING", [][]byte{[]byte("ignored")}); err != nil {
		t.Fatalf("writeChainPEM(pem): %v", err)
	}
	if buf.String() != "PEM-STRING" {
		t.Errorf("writeChainPEM prefers PEM, got %q", buf.String())
	}

	// Encodes DER when no PEM.
	der := selfSignedCA(t)
	buf.Reset()
	if err := writeChainPEM(&buf, "", [][]byte{der}); err != nil {
		t.Fatalf("writeChainPEM(der): %v", err)
	}
	if !strings.Contains(buf.String(), "BEGIN CERTIFICATE") {
		t.Errorf("writeChainPEM(der) produced no PEM: %q", buf.String())
	}

	if err := writeChainPEM(&buf, "", nil); err == nil {
		t.Error("writeChainPEM(empty) = nil, want error")
	}
}

func TestWritePEMBlock(t *testing.T) {
	der := selfSignedCA(t)
	var buf bytes.Buffer
	if err := writePEMBlock(&buf, "CERTIFICATE REQUEST", der); err != nil {
		t.Fatalf("writePEMBlock: %v", err)
	}
	if !strings.Contains(buf.String(), "BEGIN CERTIFICATE REQUEST") {
		t.Errorf("writePEMBlock produced wrong block: %q", buf.String())
	}
	if err := writePEMBlock(&buf, "CERTIFICATE REQUEST", nil); err == nil {
		t.Error("writePEMBlock(empty) = nil, want error")
	}
}

func TestWriteIdentity(t *testing.T) {
	der := selfSignedCA(t)
	id := &cryptosv1.Identity{
		ChainDer: [][]byte{der},
		ChainPem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
	var buf bytes.Buffer
	if err := writeIdentity(&buf, id, formatPEM); err != nil {
		t.Fatalf("writeIdentity(pem): %v", err)
	}
	if !strings.Contains(buf.String(), "BEGIN CERTIFICATE") {
		t.Errorf("writeIdentity(pem) missing cert: %q", buf.String())
	}

	buf.Reset()
	if err := writeIdentity(&buf, id, formatHuman); err != nil {
		t.Fatalf("writeIdentity(human): %v", err)
	}
	if !strings.Contains(buf.String(), "Subject:") {
		t.Errorf("writeIdentity(human) missing summary: %q", buf.String())
	}
}
