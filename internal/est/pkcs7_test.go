package est

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
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertsOnlyPKCS7RoundTrip(t *testing.T) {
	ca := newTestCA(t)
	leafDER := ca.issueLeaf(t, "leaf.example.org")

	p7, err := CertsOnlyPKCS7([][]byte{leafDER, ca.certDER})
	if err != nil {
		t.Fatalf("CertsOnlyPKCS7: %v", err)
	}

	got, err := ParseCertsOnlyPKCS7(p7)
	if err != nil {
		t.Fatalf("ParseCertsOnlyPKCS7: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d certificates, want 2", len(got))
	}
	// Order matters: EST clients take the first certificate as the one they
	// were issued and the rest as the chain.
	if !bytes.Equal(got[0], leafDER) {
		t.Fatal("the first certificate is not the leaf")
	}
	if !bytes.Equal(got[1], ca.certDER) {
		t.Fatal("the second certificate is not the CA")
	}
	// The bytes must still be real certificates, not just well-shaped ASN.1.
	for i, der := range got {
		if _, err := x509.ParseCertificate(der); err != nil {
			t.Fatalf("certificate %d does not parse: %v", i, err)
		}
	}
}

func TestCertsOnlyPKCS7Rejects(t *testing.T) {
	if _, err := CertsOnlyPKCS7(nil); err == nil {
		t.Fatal("an empty certificate list was accepted")
	}
	if _, err := CertsOnlyPKCS7([][]byte{{}}); err == nil {
		t.Fatal("an empty certificate was accepted")
	}
}

func TestParseCertsOnlyPKCS7Rejects(t *testing.T) {
	ca := newTestCA(t)
	p7, err := CertsOnlyPKCS7([][]byte{ca.certDER})
	if err != nil {
		t.Fatalf("CertsOnlyPKCS7: %v", err)
	}

	if _, err := ParseCertsOnlyPKCS7([]byte("not asn.1")); err == nil {
		t.Fatal("garbage parsed as a certs-only message")
	}
	if _, err := ParseCertsOnlyPKCS7(append(p7, 0x00)); err == nil {
		t.Fatal("trailing bytes were accepted")
	}
	// A bare certificate is valid ASN.1 but not a ContentInfo.
	if _, err := ParseCertsOnlyPKCS7(ca.certDER); err == nil {
		t.Fatal("a bare certificate parsed as a certs-only message")
	}
}

// TestCertsOnlyPKCS7ReadableByOpenSSL is the check that matters: our own
// parser agreeing with our own writer proves nothing about whether an EST
// client can read the message. OpenSSL is the reference implementation every
// client is ultimately measured against.
//
// It skips where openssl is not installed rather than failing, so the suite
// still runs on a bare builder; the structural tests above always run.
func TestCertsOnlyPKCS7ReadableByOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not on PATH; skipping the interoperability check")
	}

	ca := newTestCA(t)
	leafDER := ca.issueLeaf(t, "leaf.example.org")
	p7, err := CertsOnlyPKCS7([][]byte{leafDER, ca.certDER})
	if err != nil {
		t.Fatalf("CertsOnlyPKCS7: %v", err)
	}

	path := filepath.Join(t.TempDir(), "certs.p7b")
	if err := os.WriteFile(path, p7, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, err := exec.Command(openssl, "pkcs7", "-inform", "DER", "-in", path, "-print_certs", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl could not read the message: %v\n%s", err, out)
	}
	// Match on the common names alone. OpenSSL renders a DN as "CN=x" or
	// "CN = x" depending on the build, and pinning either spelling makes the
	// test fail on a machine whose openssl merely formats differently.
	text := string(out)
	if !strings.Contains(text, "leaf.example.org") {
		t.Fatalf("openssl did not report the leaf subject:\n%s", text)
	}
	if !strings.Contains(text, testCACommonName) {
		t.Fatalf("openssl did not report the CA subject:\n%s", text)
	}
}
