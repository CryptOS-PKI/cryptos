package cms

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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tests in this file check interoperability against OpenSSL, the
// implementation SCEP clients (sscep, the IOS and IOS-XE PKI client) and
// RFC 3161 verifiers are measured against. Our own writer agreeing with our
// own reader proves little; these build messages with one side and read them
// with the other, in both directions.
//
// They need OpenSSL 3 with the cms command. CRYPTOS_TEST_OPENSSL names the
// binary when the one on PATH is something else (macOS ships LibreSSL as
// /usr/bin/openssl). Without a usable OpenSSL they skip locally, but fail
// under CI, so the interoperability check can never silently stop running.

type openssl struct {
	t   *testing.T
	bin string
	dir string
}

func newOpenSSL(t *testing.T) *openssl {
	t.Helper()
	bin := os.Getenv("CRYPTOS_TEST_OPENSSL")
	if bin == "" {
		bin = "openssl"
	}
	unavailable := func(why string) {
		if os.Getenv("CI") != "" {
			t.Fatalf("OpenSSL interoperability tests cannot run under CI: %s", why)
		}
		t.Skipf("skipping OpenSSL interoperability: %s (set CRYPTOS_TEST_OPENSSL)", why)
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		unavailable(bin + " is not on PATH")
	}
	out, err := exec.Command(path, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "OpenSSL 3") {
		unavailable("need OpenSSL 3, have " + strings.TrimSpace(string(out)))
	}
	return &openssl{t: t, bin: path, dir: t.TempDir()}
}

// sub rebinds the helper to a subtest, so a failure stops that subtest rather
// than calling FailNow on its parent.
func (o *openssl) sub(t *testing.T) *openssl {
	c := *o
	c.t = t
	return &c
}

// run executes openssl and returns its combined output, failing the test on
// a non-zero exit.
func (o *openssl) run(args ...string) []byte {
	o.t.Helper()
	out, err := exec.Command(o.bin, args...).CombinedOutput()
	if err != nil {
		o.t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// runErr is run for the cases where OpenSSL is expected to refuse.
func (o *openssl) runErr(args ...string) error {
	o.t.Helper()
	return exec.Command(o.bin, args...).Run()
}

func (o *openssl) write(name string, data []byte) string {
	o.t.Helper()
	p := filepath.Join(o.dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		o.t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func (o *openssl) read(p string) []byte {
	o.t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		o.t.Fatalf("read %s: %v", p, err)
	}
	return b
}

func (o *openssl) certPEM(name string, c *x509.Certificate) string {
	return o.write(name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func (o *openssl) keyPEM(name string, k crypto.PrivateKey) string {
	o.t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		o.t.Fatalf("marshal key: %v", err)
	}
	return o.write(name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

var interopContent = []byte("interoperability payload: a CSR, a CertRep, or a TSTInfo\n")

func TestOpenSSLSignedDataWeVerify(t *testing.T) {
	o := newOpenSSL(t)
	ca := newTestCA(t)
	rsaCert := ca.issue(t, "rsa signer", keys.rsa2048.Public(), true)
	ecCert := ca.issue(t, "ec signer", keys.p384.Public(), true)
	in := o.write("content.bin", interopContent)
	rsaCrt, rsaKey := o.certPEM("rsa.crt", rsaCert), o.keyPEM("rsa.key", keys.rsa2048)
	ecCrt, ecKey := o.certPEM("ec.crt", ecCert), o.keyPEM("ec.key", keys.p384)

	cases := []struct {
		name     string
		args     []string
		cert     *x509.Certificate
		detached bool
		wantSKI  bool
	}{
		{"cms rsa sha256", []string{"cms", "-sign", "-nodetach", "-md", "sha256", "-signer", rsaCrt, "-inkey", rsaKey}, rsaCert, false, false},
		{"cms rsa sha512 keyid", []string{"cms", "-sign", "-nodetach", "-md", "sha512", "-keyid", "-signer", rsaCrt, "-inkey", rsaKey}, rsaCert, false, true},
		{"cms ecdsa sha384", []string{"cms", "-sign", "-nodetach", "-md", "sha384", "-signer", ecCrt, "-inkey", ecKey}, ecCert, false, false},
		// -stream makes OpenSSL emit indefinite-length BER with a chunked
		// eContent, the shape a streaming client sends.
		{"cms stream ber", []string{"cms", "-sign", "-nodetach", "-stream", "-md", "sha256", "-signer", rsaCrt, "-inkey", rsaKey}, rsaCert, false, false},
		{"cms detached", []string{"cms", "-sign", "-md", "sha256", "-signer", ecCrt, "-inkey", ecKey}, ecCert, true, false},
		{"smime rsa sha256", []string{"smime", "-sign", "-nodetach", "-md", "sha256", "-signer", rsaCrt, "-inkey", rsaKey}, rsaCert, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := o.sub(t)
			out := filepath.Join(o.dir, strings.ReplaceAll(tc.name, " ", "_")+".der")
			o.run(append(tc.args, "-binary", "-in", in, "-outform", "DER", "-out", out)...)
			der := o.read(out)

			sd, err := ParseSignedData(der)
			if err != nil {
				t.Fatalf("ParseSignedData: %v", err)
			}
			if !sd.ContentType.Equal(OIDData) {
				t.Fatalf("content type %s", sd.ContentType)
			}
			if (sd.SignerInfos[0].SubjectKeyID != nil) != tc.wantSKI {
				t.Fatalf("signer identified by SKI = %v, want %v", sd.SignerInfos[0].SubjectKeyID != nil, tc.wantSKI)
			}
			opts := VerifyOptions{}
			if tc.detached {
				if sd.Content != nil {
					t.Fatal("detached message carries content")
				}
				opts.Content = interopContent
			} else if !bytes.Equal(sd.Content, interopContent) {
				t.Fatal("content did not come through")
			}
			signers, err := sd.Verify(opts)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !signers[0].Equal(tc.cert) {
				t.Fatal("wrong signer returned")
			}

			// Negative: the same OpenSSL message with its content altered.
			if !tc.detached {
				bad := bytes.Clone(der)
				i := bytes.Index(bad, interopContent[:16])
				if i < 0 {
					t.Fatal("content not found in the message")
				}
				bad[i] ^= 0x01
				sd, err := ParseSignedData(bad)
				if err != nil {
					t.Fatalf("ParseSignedData(tampered): %v", err)
				}
				if _, err := sd.Verify(VerifyOptions{}); !errors.Is(err, ErrVerification) {
					t.Fatalf("tampered OpenSSL message: err = %v, want ErrVerification", err)
				}
			}
		})
	}

	t.Run("sha1 refused", func(t *testing.T) {
		o := o.sub(t)
		out := filepath.Join(o.dir, "sha1.der")
		o.run("cms", "-sign", "-nodetach", "-md", "sha1", "-signer", rsaCrt, "-inkey", rsaKey, "-binary", "-in", in, "-outform", "DER", "-out", out)
		sd, err := ParseSignedData(o.read(out))
		if err != nil {
			t.Fatalf("ParseSignedData: %v", err)
		}
		if _, err := sd.Verify(VerifyOptions{}); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}

func TestOpenSSLVerifiesOurSignedData(t *testing.T) {
	o := newOpenSSL(t)
	ca := newTestCA(t)
	caCrt := o.certPEM("ca.crt", ca.cert)
	rsaCert := ca.issue(t, "rsa signer", keys.rsa3072.Public(), true)
	ecCert := ca.issue(t, "ec signer", keys.p256.Public(), false)
	device := selfSigned(t, "scep device", keys.rsa2048)

	cases := []struct {
		name        string
		tstInfo     bool
		signer      Signer
		chain       [][]byte
		trustDevice bool
	}{
		{"rsa sha256 issuerAndSerial", false, Signer{Certificate: rsaCert, Key: keys.rsa3072}, [][]byte{rsaCert.Raw}, false},
		{"rsa sha384 ski", false, Signer{Certificate: rsaCert, Key: keys.rsa3072, Hash: crypto.SHA384, IdentifyBySKI: true}, [][]byte{rsaCert.Raw}, false},
		{"ecdsa sha512", false, Signer{Certificate: ecCert, Key: keys.p256, Hash: crypto.SHA512}, [][]byte{ecCert.Raw}, false},
		{"self-signed scep device", false, Signer{Certificate: device, Key: keys.rsa2048}, [][]byte{device.Raw}, true},
		{"tstinfo", true, Signer{Certificate: ecCert, Key: keys.p256}, [][]byte{ecCert.Raw}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := o.sub(t)
			ct := OIDData
			if tc.tstInfo {
				ct = OIDTSTInfo
			}
			der, err := Sign(ct, interopContent, []Signer{tc.signer}, SignOptions{Certificates: tc.chain})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			msg := o.write(strings.ReplaceAll(tc.name, " ", "_")+".der", der)
			trust := caCrt
			if tc.trustDevice {
				trust = o.certPEM("device.crt", device)
			}
			out := filepath.Join(o.dir, "verified.bin")
			for _, cmd := range []string{"cms", "smime"} {
				// smime is OpenSSL's PKCS#7 path: id-data only, and signers
				// by issuer and serial only.
				if cmd == "smime" && (tc.tstInfo || tc.signer.IdentifyBySKI) {
					continue
				}
				o.run(cmd, "-verify", "-binary", "-inform", "DER", "-in", msg, "-CAfile", trust, "-purpose", "any", "-out", out)
				if got := o.read(out); !bytes.Equal(got, interopContent) {
					t.Fatalf("openssl %s -verify returned different content", cmd)
				}
			}
			if tc.tstInfo {
				printed := string(o.run("cms", "-cmsout", "-print", "-inform", "DER", "-in", msg))
				if !strings.Contains(printed, "id-smime-ct-TSTInfo") {
					t.Fatalf("eContentType is not id-ct-TSTInfo:\n%s", printed)
				}
			}

			// Negative: OpenSSL must reject our message once altered.
			bad := bytes.Clone(der)
			bad[bytes.Index(bad, interopContent[:16])] ^= 0x01
			badPath := o.write("bad.der", bad)
			if err := o.runErr("cms", "-verify", "-binary", "-inform", "DER", "-in", badPath, "-CAfile", trust, "-purpose", "any", "-out", out); err == nil {
				t.Fatal("openssl verified a tampered message")
			}
		})
	}
}

func TestOpenSSLEnvelopedDataWeDecrypt(t *testing.T) {
	o := newOpenSSL(t)
	ca := newTestCA(t)
	ra := ca.issue(t, "ra", keys.rsa3072.Public(), true)
	stranger := ca.issue(t, "stranger", keys.rsa2048.Public(), false)
	raCrt := o.certPEM("ra.crt", ra)
	in := o.write("content.bin", interopContent)

	cases := []struct {
		name string
		args []string
	}{
		{"cms aes128", []string{"cms", "-encrypt", "-aes128"}},
		{"cms aes256 keyid", []string{"cms", "-encrypt", "-aes256", "-keyid"}},
		{"cms aes256 stream ber", []string{"cms", "-encrypt", "-aes256", "-stream"}},
		{"smime aes256", []string{"smime", "-encrypt", "-aes256"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := o.sub(t)
			out := filepath.Join(o.dir, strings.ReplaceAll(tc.name, " ", "_")+".der")
			o.run(append(tc.args, "-binary", "-in", in, "-outform", "DER", "-out", out, raCrt)...)
			ed, err := ParseEnvelopedData(o.read(out))
			if err != nil {
				t.Fatalf("ParseEnvelopedData: %v", err)
			}
			got, err := ed.Decrypt(ra, decrypterOnly{keys.rsa3072})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, interopContent) {
				t.Fatal("wrong plaintext")
			}
			if _, err := ed.Decrypt(stranger, keys.rsa2048); !errors.Is(err, ErrNoRecipient) {
				t.Fatalf("stranger: err = %v, want ErrNoRecipient", err)
			}
		})
	}
}

func TestOpenSSLDecryptsOurEnvelopedData(t *testing.T) {
	o := newOpenSSL(t)
	ca := newTestCA(t)
	device := ca.issue(t, "device", keys.rsa2048.Public(), true)
	crt, key := o.certPEM("device.crt", device), o.keyPEM("device.key", keys.rsa2048)
	other := ca.issue(t, "other", keys.rsa3072.Public(), false)
	otherCrt, otherKey := o.certPEM("other.crt", other), o.keyPEM("other.key", keys.rsa3072)

	for _, tc := range []struct {
		name string
		alg  ContentEncryption
		ski  bool
	}{
		{"aes128 issuerAndSerial", AES128CBC, false},
		{"aes256 ski", AES256CBC, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := o.sub(t)
			der, err := Encrypt(interopContent, []*x509.Certificate{device}, tc.alg, EncryptOptions{IdentifyBySKI: tc.ski})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			msg := o.write("env.der", der)
			out := filepath.Join(o.dir, "plain.bin")
			for _, cmd := range []string{"cms", "smime"} {
				if cmd == "smime" && tc.ski {
					continue // smime matches recipients by issuer and serial only
				}
				o.run(cmd, "-decrypt", "-binary", "-inform", "DER", "-in", msg, "-recip", crt, "-inkey", key, "-out", out)
				if !bytes.Equal(o.read(out), interopContent) {
					t.Fatalf("openssl %s -decrypt returned different content", cmd)
				}
			}
			// Negative: the wrong recipient cannot open it.
			if err := o.runErr("cms", "-decrypt", "-binary", "-inform", "DER", "-in", msg, "-recip", otherCrt, "-inkey", otherKey, "-out", out); err == nil {
				t.Fatal("openssl decrypted with the wrong recipient")
			}
		})
	}
}

func TestOpenSSLReadsOurDegenerate(t *testing.T) {
	o := newOpenSSL(t)
	ca := newTestCA(t)
	leaf := ca.issue(t, "degenerate leaf", keys.p256.Public(), false)
	der, err := Degenerate([][]byte{leaf.Raw, ca.cert.Raw}, [][]byte{ca.crl(t)})
	if err != nil {
		t.Fatal(err)
	}
	msg := o.write("certs.p7b", der)
	text := string(o.run("pkcs7", "-inform", "DER", "-in", msg, "-print_certs"))
	for _, want := range []string{"degenerate leaf", "CMS Test CA", "Certificate Revocation List"} {
		if !strings.Contains(text, want) {
			t.Fatalf("openssl pkcs7 output lacks %q:\n%s", want, text)
		}
	}
}
