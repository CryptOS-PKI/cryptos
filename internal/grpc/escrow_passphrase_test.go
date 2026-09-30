package grpc

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
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// Passphrases one byte either side of the minimum.
var (
	passphraseAtMin    = []byte("correct-horse-bat1") // 18 bytes
	passphraseBelowMin = []byte("correct-horse-bat")  // 17 bytes
)

func TestExportCAKey_EnforcesTheMinimumPassphraseLength(t *testing.T) {
	if len(passphraseAtMin) != MinPassphraseLen || len(passphraseBelowMin) != MinPassphraseLen-1 {
		t.Fatalf("fixtures are %d and %d bytes, want %d and %d", len(passphraseAtMin), len(passphraseBelowMin), MinPassphraseLen, MinPassphraseLen-1)
	}
	exp := &fakeExporter{envelope: []byte("sealed-envelope")}
	srv, err := NewLocal(ServerConfig{Auditor: &mockAuditor{}, Exporter: exp})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}

	_, err = srv.ExportCAKey(context.Background(), &cryptosv1.ExportCAKeyRequest{Passphrase: passphraseBelowMin})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("short passphrase code = %v, want InvalidArgument", status.Code(err))
	}
	if strings.Contains(err.Error(), string(passphraseBelowMin)) {
		t.Errorf("the rejection echoes the passphrase: %v", err)
	}
	if exp.gotPassphrase != nil {
		t.Error("a short passphrase reached the exporter")
	}

	if _, err := srv.ExportCAKey(context.Background(), &cryptosv1.ExportCAKeyRequest{Passphrase: passphraseAtMin}); err != nil {
		t.Fatalf("passphrase at the minimum: %v", err)
	}
	if string(exp.gotPassphrase) != string(passphraseAtMin) {
		t.Errorf("exporter passphrase = %q, want the 18-byte one", exp.gotPassphrase)
	}
}

func TestImportCAKey_EnforcesTheMinimumPassphraseLength(t *testing.T) {
	imp := &fakeImporter{identity: &cryptosv1.Identity{ChainPem: "PEM"}}
	srv, err := NewLocal(ServerConfig{Auditor: &mockAuditor{}, Importer: imp})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}

	_, err = srv.ImportCAKey(context.Background(), &cryptosv1.ImportCAKeyRequest{Envelope: []byte("env"), Passphrase: passphraseBelowMin})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("short passphrase code = %v, want InvalidArgument", status.Code(err))
	}
	if strings.Contains(err.Error(), string(passphraseBelowMin)) {
		t.Errorf("the rejection echoes the passphrase: %v", err)
	}
	if imp.gotPassphrase != nil {
		t.Error("a short passphrase reached the importer")
	}

	if _, err := srv.ImportCAKey(context.Background(), &cryptosv1.ImportCAKeyRequest{Envelope: []byte("env"), Passphrase: passphraseAtMin}); err != nil {
		t.Fatalf("passphrase at the minimum: %v", err)
	}
	if string(imp.gotPassphrase) != string(passphraseAtMin) {
		t.Errorf("importer passphrase = %q, want the 18-byte one", imp.gotPassphrase)
	}
}
