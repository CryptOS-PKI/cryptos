package scep

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
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// These run a real SCEP client, sscep, and OpenSSL 3 (which writes the
// device's key and PKCS#10 request, challengePassword included, the way a
// device would) against the server. Our own client agreeing with our own
// server proves little.
//
// CRYPTOS_TEST_SSCEP and CRYPTOS_TEST_OPENSSL name the binaries when they are
// not sscep and openssl on PATH (macOS ships LibreSSL as /usr/bin/openssl).
// Without them the tests skip locally but fail under CI, so the check cannot
// silently stop running.

type interop struct {
	sscep   string
	openssl string
	dir     string
	url     string
}

func newInterop(t *testing.T, f *fixture) *interop {
	t.Helper()
	unavailable := func(why string) {
		if os.Getenv("CI") != "" {
			t.Fatalf("SCEP interoperability tests cannot run under CI: %s", why)
		}
		t.Skipf("skipping SCEP interoperability: %s (set CRYPTOS_TEST_SSCEP and CRYPTOS_TEST_OPENSSL)", why)
	}
	find := func(env, def string) string {
		bin := os.Getenv(env)
		if bin == "" {
			bin = def
		}
		path, err := exec.LookPath(bin)
		if err != nil {
			unavailable(bin + " is not on PATH")
		}
		return path
	}
	sscep := find("CRYPTOS_TEST_SSCEP", "sscep")
	openssl := find("CRYPTOS_TEST_OPENSSL", "openssl")
	if out, err := exec.Command(openssl, "version").CombinedOutput(); err != nil || !strings.HasPrefix(string(out), "OpenSSL 3") {
		unavailable("need OpenSSL 3, have " + strings.TrimSpace(string(out)))
	}
	return &interop{sscep: sscep, openssl: openssl, dir: t.TempDir(), url: f.http.URL + PathPKIClient}
}

func (i *interop) path(name string) string { return filepath.Join(i.dir, name) }

func (i *interop) run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, out)
	}
	return string(out)
}

// runFail runs a command that must fail and returns its output.
func (i *interop) runFail(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err == nil {
		t.Fatalf("%s %s succeeded, want a failure\n%s", filepath.Base(bin), strings.Join(args, " "), out)
	}
	return string(out)
}

// request writes an RSA key and a PKCS#10 request with OpenSSL, the way a
// device generates them, carrying challenge as its challengePassword.
func (i *interop) request(t *testing.T, name, cn string, bits int, challenge string) (keyFile, reqFile string) {
	t.Helper()
	cnf := i.path(name + ".cnf")
	body := "[req]\nprompt = no\ndistinguished_name = dn\nattributes = attrs\n[dn]\nCN = " + cn + "\n[attrs]\n"
	if challenge != "" {
		body += "challengePassword = " + challenge + "\n"
	}
	if err := os.WriteFile(cnf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile, reqFile = i.path(name+".key"), i.path(name+".csr")
	i.run(t, i.openssl, "req", "-new", "-newkey", "rsa:"+strconv.Itoa(bits), "-nodes", "-sha256",
		"-keyout", keyFile, "-out", reqFile, "-config", cnf)
	return keyFile, reqFile
}

func readPEMCert(t *testing.T, file string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s holds no PEM", file)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSSCEPInterop(t *testing.T) {
	f := newFixture(t)
	i := newInterop(t, f)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server log:\n%s", f.logText())
		}
	})

	caps := i.run(t, i.sscep, "getcaps", "-u", i.url)
	for _, c := range Capabilities {
		if !strings.Contains(caps, c) {
			t.Fatalf("sscep getcaps does not show %s:\n%s", c, caps)
		}
	}

	caFile := i.path("ca.pem")
	i.run(t, i.sscep, "getca", "-u", i.url, "-c", caFile)
	caCert := readPEMCert(t, caFile+"-0")
	raCert := readPEMCert(t, caFile+"-1")
	if !caCert.Equal(f.ca.cert) || !raCert.Equal(f.raCert()) {
		t.Fatal("sscep getca did not receive the CA and the RA")
	}

	// sscep verifies replies with the certificate given as -c, so in RA mode
	// that is the RA, as it is for other RA-mode servers.
	enrol := func(t *testing.T, name, cn, challenge string, extra ...string) (keyFile, certFile, out string) {
		t.Helper()
		keyFile, reqFile := i.request(t, name, cn, 2048, challenge)
		certFile = i.path(name + ".crt")
		args := append([]string{"enroll", "-u", i.url, "-c", caFile + "-1", "-e", caFile + "-1",
			"-k", keyFile, "-r", reqFile, "-l", certFile, "-E", "aes256", "-S", "sha256"}, extra...)
		return keyFile, certFile, i.run(t, i.sscep, args...)
	}

	var keyFile, certFile string
	t.Run("PKCSReq with a one-time challenge", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour)
		keyFile, certFile, _ = enrol(t, "sw1", "sw1.example.com", pw)
		leaf := readPEMCert(t, certFile)
		if leaf.Subject.CommonName != "sw1.example.com" || leaf.CheckSignatureFrom(f.ca.cert) != nil {
			t.Fatalf("sscep enrolled %v", leaf.Subject)
		}
	})
	t.Run("a reused challenge is refused", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour)
		enrol(t, "sw2", "sw2.example.com", pw)
		k, r := i.request(t, "sw3", "sw3.example.com", 2048, pw)
		i.runFail(t, i.sscep, "enroll", "-u", i.url, "-c", caFile+"-1", "-e", caFile+"-1", "-k", k, "-r", r, "-l", i.path("sw3.crt"), "-E", "aes256", "-S", "sha256")
	})
	t.Run("SHA-512 and AES-128", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour)
		k, r := i.request(t, "sw4", "sw4.example.com", 2048, pw)
		i.run(t, i.sscep, "enroll", "-u", i.url, "-c", caFile+"-1", "-e", caFile+"-1", "-k", k, "-r", r, "-l", i.path("sw4.crt"), "-E", "aes128", "-S", "sha512")
	})
	t.Run("SHA-1 and 3DES are refused", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour)
		k, r := i.request(t, "sw5", "sw5.example.com", 2048, pw)
		i.runFail(t, i.sscep, "enroll", "-u", i.url, "-c", caFile+"-1", "-e", caFile+"-1", "-k", k, "-r", r, "-l", i.path("sw5.crt"), "-E", "3des", "-S", "sha1")
	})
	t.Run("GetCert", func(t *testing.T) {
		leaf := readPEMCert(t, certFile)
		out := i.path("got.crt")
		i.run(t, i.sscep, "getcert", "-u", i.url, "-c", caFile+"-1", "-e", caFile+"-1", "-k", keyFile, "-l", certFile,
			"-s", leaf.SerialNumber.String(), "-w", out)
		if !readPEMCert(t, out).Equal(leaf) {
			t.Fatal("sscep getcert returned a different certificate")
		}
	})
	t.Run("GetCRL", func(t *testing.T) {
		out := i.path("crl.pem")
		i.run(t, i.sscep, "getcrl", "-u", i.url, "-c", caFile+"-1", "-e", caFile+"-1", "-k", keyFile, "-l", certFile, "-w", out)
		if st, err := os.Stat(out); err != nil || st.Size() == 0 {
			t.Fatalf("sscep getcrl wrote nothing: %v", err)
		}
	})
	t.Run("renewal signed by the current certificate", func(t *testing.T) {
		newKey, newReq := i.request(t, "sw1-renew", "sw1.example.com", 2048, "")
		out := i.path("sw1-renew.crt")
		i.run(t, i.sscep, "enroll", "-u", i.url, "-c", caFile+"-1", "-e", caFile+"-1", "-k", newKey, "-r", newReq,
			"-K", keyFile, "-O", certFile, "-l", out, "-E", "aes256", "-S", "sha256")
		renewed := readPEMCert(t, out)
		if renewed.Subject.CommonName != "sw1.example.com" || renewed.Equal(readPEMCert(t, certFile)) {
			t.Fatal("sscep renewal did not return a new certificate for the same name")
		}
		// sscep renews with a PKCSReq signed by the current certificate, the
		// pre-RFC 8894 form; it must get the renewal rules, not need a
		// challenge.
		if ev := f.audit.last(); ev.GetDetails()["authorized_by"] != "certificate" || ev.GetDetails()["profile"] != "cisco-device" {
			t.Fatalf("the renewal was not authorized by the current certificate: %v", ev)
		}
	})
	t.Run("PENDING, then approved while sscep polls", func(t *testing.T) {
		pw, _ := f.mint("approved-device", time.Hour)
		k, r := i.request(t, "sw6", "sw6.example.com", 2048, pw)
		out := i.path("sw6.crt")
		cmd := exec.Command(i.sscep, "enroll", "-u", i.url, "-c", caFile+"-1", "-e", caFile+"-1", "-k", k, "-r", r, "-l", out,
			"-E", "aes256", "-S", "sha256", "-t", "1", "-T", "60")
		var buf strings.Builder
		cmd.Stdout, cmd.Stderr = &buf, &buf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var id string
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && id == ""; time.Sleep(200 * time.Millisecond) {
			list, _ := f.srv.ListScepEnrollments(f.ctx, &cryptosv1.ListScepEnrollmentsRequest{})
			if len(list.GetEnrollments()) == 1 {
				id = list.GetEnrollments()[0].GetId()
			}
		}
		if id == "" {
			_ = cmd.Process.Kill()
			t.Fatalf("sscep's request never reached the queue:\n%s", buf.String())
		}
		time.Sleep(1500 * time.Millisecond)
		if _, err := f.srv.ApproveScepEnrollment(f.ctx, &cryptosv1.ApproveScepEnrollmentRequest{Id: id}); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("sscep did not collect the approved certificate: %v\n%s", err, buf.String())
		}
		if readPEMCert(t, out).Subject.CommonName != "sw6.example.com" {
			t.Fatal("the polled certificate is not the approved one")
		}
	})
}
