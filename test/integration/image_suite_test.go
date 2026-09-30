//go:build integration

package integration

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

// The full-image suite: the real CryptOS image, booted in QEMU with swtpm and
// OVMF as a Root and an Intermediate, driven over the mTLS API with cryptosctl
// the way an operator drives it. Each step is a named subtest whose result
// (pass, fail, or skip with the reason) goes into a summary table, and a step
// whose prerequisite failed is skipped rather than failing on top of it.
//
// test/image/run.sh (task e2e:image) stands up what the steps need around the
// VMs (a kind cluster with cert-manager, the nginx image, a
// coverage-instrumented cryptosctl) and sets the E2E_IMAGE_* variables below.
// Without CRYPTOS_E2E_IMAGE=1 the test skips.
//
// Networking: every VM gets its own QEMU user-mode network (10.0.0.0/24, the
// node at 10.0.0.10, the host at 10.0.0.1, QEMU's DNS proxy at 10.0.0.3) and
// host-forwards for the ports a step dials. User networking needs no root and
// no bridge on the runner, and each VM's network is isolated from the others.
// A guest connection to 10.0.0.1 lands on the host's loopback, which is where
// kind maps the cluster ingress, so the node's http-01 fetch reaches the
// cluster without any bypass; its DNS query for the name goes through QEMU's
// proxy to the host resolver, which run.sh points at 10.0.0.1.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	suiteRootCN = "CryptOS E2E Root"
	suiteIntCN  = "CryptOS E2E Issuing G1"

	suiteNodeAddr = "10.0.0.10"

	rootMgmtPort  = "4443"
	intMgmtPort   = "4444"
	spareMgmtPort = "4445"
	intRevPort    = "18080"
	intACMEPort   = "18555"
	intESTPort    = "18443"
	acmeFrontPort = "8443"
	nginxPort     = "9443"

	nginxName       = "nginx.cryptos.test"
	nginxContainer  = "cryptos-e2e-nginx"
	estUser         = "e2e-device"
	estClientName   = "est-client.cryptos.test"
	acmeEABKeyID    = "e2e-image"
	acmeLeafProfile = "acme-leaf"

	kindNS     = "cryptos-e2e"
	kindCert   = "whoami"
	kindSecret = "whoami-tls"
)

// suiteEnv is what run.sh hands the suite.
type suiteEnv struct {
	qemu, swtpm, ovmfCode, ovmfVars    string
	uki, nextUKI, accel, out, coverDir string
	cryptosctl                         string
	hostIP, hostname                   string
	kubeconfig, kubectl, nginx         string
}

func loadSuiteEnv(t *testing.T) suiteEnv {
	t.Helper()
	if os.Getenv("CRYPTOS_E2E_IMAGE") != "1" {
		t.Skip("full-image suite: not requested; run `task e2e:image` on a Linux host")
	}
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }
	e := suiteEnv{
		qemu:       firstNonEmpty(get("QEMU"), "qemu-system-x86_64"),
		swtpm:      firstNonEmpty(get("SWTPM"), "swtpm"),
		ovmfCode:   get("OVMF_CODE"),
		ovmfVars:   get("OVMF_VARS"),
		uki:        get("E2E_IMAGE_UKI"),
		nextUKI:    get("E2E_IMAGE_NEXT_UKI"),
		accel:      firstNonEmpty(get("E2E_IMAGE_ACCEL"), "kvm:tcg"),
		out:        get("E2E_IMAGE_OUT"),
		coverDir:   get("E2E_IMAGE_COVERDIR"),
		cryptosctl: get("CRYPTOSCTL"),
		hostIP:     get("E2E_IMAGE_HOST_IP"),
		hostname:   get("E2E_IMAGE_HOSTNAME"),
		kubeconfig: get("E2E_IMAGE_KUBECONFIG"),
		kubectl:    firstNonEmpty(get("E2E_IMAGE_KUBECTL"), "kubectl"),
		nginx:      get("E2E_IMAGE_NGINX"),
	}
	for k, v := range map[string]string{
		"OVMF_CODE": e.ovmfCode, "OVMF_VARS": e.ovmfVars, "E2E_IMAGE_UKI": e.uki,
		"E2E_IMAGE_OUT": e.out, "CRYPTOSCTL": e.cryptosctl, "E2E_IMAGE_HOST_IP": e.hostIP,
		"E2E_IMAGE_HOSTNAME": e.hostname, "E2E_IMAGE_KUBECONFIG": e.kubeconfig, "E2E_IMAGE_NGINX": e.nginx,
	} {
		if v == "" {
			t.Fatalf("full-image suite: %s must be set (run it through test/image/run.sh)", k)
		}
	}
	if net.ParseIP(e.hostIP) == nil {
		t.Fatalf("full-image suite: E2E_IMAGE_HOST_IP %q is not an IP", e.hostIP)
	}
	return e
}

// ---- the step runner and its summary ----------------------------------------

type stepResult struct {
	name, status, note string
	took               time.Duration
}

type suite struct {
	t       *testing.T
	env     suiteEnv
	mu      sync.Mutex
	results []stepResult
	passed  map[string]bool
	notes   []string
}

// step runs fn as the subtest name, unless a step in needs did not pass, in
// which case it is skipped with that reason.
func (s *suite) step(name string, needs []string, fn func(t *testing.T)) {
	s.t.Run(name, func(t *testing.T) {
		started := time.Now()
		defer func() {
			res := stepResult{name: name, took: time.Since(started)}
			switch {
			case t.Failed():
				res.status = "fail"
			case t.Skipped():
				res.status = "skip"
			default:
				res.status = "pass"
			}
			s.mu.Lock()
			if res.status == "pass" {
				s.passed[name] = true
			}
			if n, ok := stepNotes.LoadAndDelete(t.Name()); ok {
				res.note = n.(string)
			}
			s.results = append(s.results, res)
			s.mu.Unlock()
		}()
		for _, n := range needs {
			if !s.passed[n] {
				note(t, "needs "+n)
				t.Skipf("skipped: needs %s, which did not pass", n)
			}
		}
		fn(t)
	})
}

// skipStep records a step the suite cannot run yet, with the reason.
func (s *suite) skipStep(name, reason string) {
	s.step(name, nil, func(t *testing.T) {
		note(t, reason)
		t.Skip(reason)
	})
}

var stepNotes sync.Map

// note sets the summary note for the running step.
func note(t *testing.T, msg string) {
	stepNotes.Store(t.Name(), msg)
}

func (s *suite) writeSummary() {
	var b strings.Builder
	b.WriteString("## Full-image suite\n\n")
	b.WriteString("Booted image: `" + filepath.Base(s.env.uki) + "`, accelerator `" + s.env.accel + "`.\n\n")
	b.WriteString("| # | Step | Result | Time | Notes |\n|---|---|---|---|---|\n")
	counts := map[string]int{}
	for i, r := range s.results {
		icon := map[string]string{"pass": "pass", "fail": "**FAIL**", "skip": "skip"}[r.status]
		counts[r.status]++
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", i+1, r.name, icon, r.took.Round(time.Second),
			strings.ReplaceAll(r.note, "|", "\\|"))
	}
	fmt.Fprintf(&b, "\n%d passed, %d failed, %d skipped.\n", counts["pass"], counts["fail"], counts["skip"])
	if len(s.notes) > 0 {
		b.WriteString("\n")
		for _, n := range s.notes {
			b.WriteString("- " + n + "\n")
		}
	}
	b.WriteString("\n")
	if err := os.WriteFile(filepath.Join(s.env.out, "summary.md"), []byte(b.String()), 0o644); err != nil {
		s.t.Logf("write summary: %v", err)
	}
	s.t.Log("\n" + b.String())
}

func (s *suite) timing(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notes = append(s.notes, fmt.Sprintf(format, args...))
}

// ---- VMs --------------------------------------------------------------------

// vm is one booted CryptOS node: its disk, TPM, serial line and forwards.
type vm struct {
	s        *suite
	name     string
	dir      string
	uuid     string
	mgmtPort string
	forwards []string
	withTPM  bool
	disk     string
	cover    string
	vars     string
	cmd      *exec.Cmd
	keys     io.WriteCloser
	serial   *serialLog
	trust    string
	admin    admin
	stopped  bool
}

type admin struct{ cert, key string }

func (s *suite) newVM(t *testing.T, name, uuid, mgmtPort string, forwards []string, machineYAML string, a admin) *vm {
	t.Helper()
	dir := filepath.Join(s.env.out, "vm-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("vm dir: %v", err)
	}
	cfg := filepath.Join(dir, "machine.yaml")
	writeFile(t, cfg, []byte(machineYAML))
	v := &vm{s: s, name: name, dir: dir, uuid: uuid, mgmtPort: mgmtPort, forwards: forwards, withTPM: true, admin: a}
	v.disk = makeInstalledDisk(t, dir, cfg)
	// The installer's layout: the UKI at the removable-media path on the
	// disk's own ESP, which OVMF boots and the image upgrader reads back.
	off := v.disk + "@@" + espPartitionOffset(t, v.disk)
	if out, err := exec.Command("mmd", "-i", off, "::/EFI/BOOT").CombinedOutput(); err != nil {
		t.Fatalf("mmd EFI/BOOT: %v\n%s", err, out)
	}
	if out, err := exec.Command("mcopy", "-i", off, s.env.uki, "::/EFI/BOOT/BOOTX64.EFI").CombinedOutput(); err != nil {
		t.Fatalf("mcopy the UKI onto the ESP: %v\n%s", err, out)
	}
	v.cover = filepath.Join(dir, "cover.img")
	if err := exec.Command("truncate", "-s", "128M", v.cover).Run(); err != nil {
		t.Fatalf("create the coverage disk: %v", err)
	}
	if out, err := exec.Command("mformat", "-i", v.cover, "-v", "COVER", "::").CombinedOutput(); err != nil {
		t.Fatalf("mformat the coverage disk: %v\n%s", err, out)
	}
	v.vars = filepath.Join(dir, "OVMF_VARS.fd")
	copyFile(t, s.env.ovmfVars, v.vars)
	return v
}

func (v *vm) boot(t *testing.T) {
	t.Helper()
	e := v.s.env
	args := []string{
		"-machine", "q35,accel=" + e.accel, "-smp", "2", "-m", "2048",
		"-uuid", v.uuid,
		"-display", "none", "-monitor", "none", "-serial", "stdio",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=" + e.ovmfCode,
		"-drive", "if=pflash,format=raw,unit=1,file=" + v.vars,
		"-drive", "if=none,id=disk,format=raw,file=" + v.disk,
		"-device", "virtio-blk-pci,drive=disk,bootindex=1",
		"-drive", "if=none,id=cover,format=raw,file=" + v.cover,
		"-device", "virtio-blk-pci,drive=cover,serial=cryptos-cover",
		"-netdev", "user,id=n0,net=10.0.0.0/24,host=10.0.0.1,dns=10.0.0.3," + strings.Join(append([]string{
			"hostfwd=tcp:127.0.0.1:" + v.mgmtPort + "-" + suiteNodeAddr + ":443"}, v.forwards...), ","),
		"-device", "virtio-net-pci,netdev=n0",
	}
	if strings.HasPrefix(e.accel, "kvm") {
		args = append(args, "-cpu", "host")
	}
	if v.withTPM {
		sock := v.startTPM(t)
		args = append(args,
			"-chardev", "socket,id=chrtpm,path="+sock,
			"-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
			"-device", "tpm-tis,tpmdev=tpm0")
	}
	logf, err := os.Create(filepath.Join(v.dir, "serial.log"))
	if err != nil {
		t.Fatalf("serial log: %v", err)
	}
	v.serial = &serialLog{f: logf}
	keysR, keysW := io.Pipe()
	v.keys = keysW
	v.cmd = exec.Command(e.qemu, args...)
	v.cmd.Stdin = keysR
	v.cmd.Stdout, v.cmd.Stderr = v.serial, v.serial
	started := time.Now()
	if err := v.cmd.Start(); err != nil {
		t.Fatalf("start qemu for %s: %v", v.name, err)
	}
	v.s.t.Cleanup(func() { v.stop() })
	v.waitUp(t, nil, started, "first boot")
}

// startTPM starts the VM's swtpm, tied to the whole suite rather than to the
// step that booted the VM, and waits for its socket.
func (v *vm) startTPM(t *testing.T) string {
	t.Helper()
	state := filepath.Join(v.dir, "swtpm")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatalf("swtpm state dir: %v", err)
	}
	sock := filepath.Join(state, "sock")
	cmd := exec.Command(v.s.env.swtpm, "socket", "--tpm2", "--tpmstate", "dir="+state, "--ctrl", "type=unixio,path="+sock)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	v.s.t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			return sock
		}
		if time.Now().After(deadline) {
			t.Fatalf("swtpm did not create %s", sock)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitUp waits for the management listener after a boot that began at
// started and re-pins the node's server certificate. The node mints a new one
// on every boot, so a certificate other than prev means this boot is serving;
// prev is empty for a first boot. The serial log is not used for this: init
// logs through /dev/kmsg, which the kernel rate-limits, so a line can be lost.
func (v *vm) waitUp(t *testing.T, prev []byte, started time.Time, what string) {
	t.Helper()
	limit := 3 * time.Minute
	if !strings.HasPrefix(v.s.env.accel, "kvm") {
		limit = 15 * time.Minute
	}
	addr := "127.0.0.1:" + v.mgmtPort
	deadline := time.Now().Add(limit)
	var cert []byte
	for {
		cert = probeServerCert(addr)
		if cert != nil && !bytes.Equal(cert, prev) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s did not bring the management API up within %s:\n%s", v.name, what, limit, lastLines(v.serial.String(), 60))
		}
		time.Sleep(time.Second)
	}
	v.trust = filepath.Join(v.dir, "trust.crt")
	writeFile(t, v.trust, cert)
	took := time.Since(started).Round(time.Second)
	t.Logf("%s: %s up in %s", v.name, what, took)
	v.s.timing("%s %s: management API up %s after %s", v.name, what, took, map[bool]string{true: "QEMU start", false: "the reboot request"}[prev == nil])
}

// probeServerCert returns the PEM of the certificate the listener at addr
// presents, or nil while it does not answer.
func probeServerCert(addr string) []byte {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // pinning grab
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})
}

// ctl runs cryptosctl against the node as the bootstrap admin. The binary is
// coverage-instrumented, so each run writes its counters for the report.
func (v *vm) ctl(stdin string, args ...string) (string, error) {
	full := append([]string{
		"--endpoint", "127.0.0.1:" + v.mgmtPort,
		"--identity", v.admin.cert, "--identity-key", v.admin.key,
		"--trust", v.trust, "--server-name", "localhost",
	}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, v.s.env.cryptosctl, full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Env = os.Environ()
	if v.s.env.coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+filepath.Join(v.s.env.coverDir, "cryptosctl"))
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := stdout.String()
	if stderr.Len() > 0 {
		out += stderr.String()
	}
	return out, err
}

func (v *vm) mustCtl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := v.ctl("", args...)
	if err != nil {
		t.Fatalf("%s: cryptosctl %s: %v\n%s", v.name, strings.Join(args, " "), err, out)
	}
	return out
}

func (v *vm) status(t *testing.T) string {
	t.Helper()
	return v.mustCtl(t, "status")
}

// reboot asks the node for a clean reboot over the API and waits for it to
// come back.
func (v *vm) reboot(t *testing.T, cn string) {
	t.Helper()
	prev, err := os.ReadFile(v.trust)
	if err != nil {
		t.Fatalf("%s: read the pinned server certificate: %v", v.name, err)
	}
	bootsBefore := bootCount(v.status(t))
	started := time.Now()
	out := v.mustCtl(t, "reboot", "--confirm", cn)
	if !strings.Contains(out, "reboot accepted") {
		t.Fatalf("%s: reboot: %s", v.name, out)
	}
	v.waitUp(t, prev, started, "reboot")
	if after := bootCount(v.status(t)); after != bootsBefore+1 {
		t.Fatalf("%s: boot count %d after the reboot, want %d", v.name, after, bootsBefore+1)
	}
}

// stop leaves the coverage flusher one more round, stops QEMU and copies the
// counters the node wrote off its coverage disk.
func (v *vm) stop() {
	if v.stopped || v.cmd == nil || v.cmd.Process == nil {
		return
	}
	v.stopped = true
	time.Sleep(5 * time.Second)
	_ = v.keys.Close()
	_ = v.cmd.Process.Kill()
	_, _ = v.cmd.Process.Wait()
	if v.s.env.coverDir == "" {
		return
	}
	dest := filepath.Join(v.s.env.coverDir, "vm-"+v.name)
	_ = os.MkdirAll(dest, 0o755)
	if out, err := exec.Command("mcopy", "-n", "-i", v.cover, "::/*", dest).CombinedOutput(); err != nil {
		v.s.t.Logf("%s: copy coverage counters off the VM: %v\n%s", v.name, err, out)
	}
	_ = os.Remove(filepath.Join(dest, "partial"))
}

func bootCount(status string) int {
	var n int
	for _, l := range strings.Split(status, "\n") {
		if strings.HasPrefix(l, "Boot count:") {
			_, _ = fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(l, "Boot count:")), "%d", &n)
		}
	}
	return n
}

func (s *serialLog) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

func (s *serialLog) since(offset int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buf.Bytes()
	if offset > len(b) {
		return ""
	}
	return string(b[offset:])
}

// ---- machine configs ----------------------------------------------------------

func indentBlock(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// rootYAML is the Root: software CA key (nodeid state key), so its key can be
// escrowed, and one CA profile to sign the Intermediate.
func rootYAML(adminPEM, name string) string {
	return fmt.Sprintf(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: %s}
role: {kind: root}
network: {interface: eth0, address: %s/24, gateway: 10.0.0.1, nameservers: [10.0.0.3]}
state_key: {mode: nodeid}
bootstrap:
  admin_cert_pem: |
%s
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: %q, organization: "CryptOS E2E", country: "US"}
  root_validity_years: 10
  profiles:
    - name: sub-ca
      key_alg: ECDSA-P384
      subject: {common_name: sub-ca}
      validity_days: 1825
      basic_constraints: {is_ca: true, path_len: 0}
      key_usage: [digital_signature, cert_sign, crl_sign]
`, name, suiteNodeAddr, indentBlock(adminPEM, "    "), suiteRootCN)
}

type intProtocols struct {
	acme, est     bool
	eabKeyB64     string
	estPassSHA256 string
}

// intYAML is the Intermediate: TPM-held CA key, the Root pinned as its
// parent, revocation published on the runner-reachable forward, and the
// profiles the steps issue under. ACME and EST are rendered only when on.
func intYAML(adminPEM, rootPEM, hostIP string, p intProtocols) string {
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: e2e-intermediate}
role: {kind: intermediate}
network: {interface: eth0, address: %s/24, gateway: 10.0.0.1, nameservers: [10.0.0.3]}
state_key: {mode: tpm}
bootstrap:
  admin_cert_pem: |
%s
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: %q, organization: "CryptOS E2E", country: "US"}
  root_validity_years: 5
  path_len_constraint: 0
  revocation_base_url: http://%s:%s
  parent:
    ca_cert_pem: |
%s
  profiles:
    - name: tls-server
      key_alg: ECDSA-P384
      subject: {common_name: tls-server}
      validity_days: 30
      basic_constraints: {is_ca: false}
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
      allow_request_sans: true
    - name: %s
      key_alg: ECDSA-P384
      subject: {common_name: acme}
      validity_days: 30
      basic_constraints: {is_ca: false}
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
    - name: acme-front
      key_alg: ECDSA-P384
      subject: {common_name: cryptos-acme-front}
      validity_days: 7
      basic_constraints: {is_ca: false}
      key_usage: [digital_signature]
      ext_key_usage: [server_auth]
      sans: {ip: [%q]}
    - name: est-client
      key_alg: ECDSA-P384
      subject: {common_name: est-client}
      validity_days: 30
      basic_constraints: {is_ca: false}
      key_usage: [digital_signature]
      ext_key_usage: [client_auth, server_auth]
`, suiteNodeAddr, indentBlock(adminPEM, "    "), suiteIntCN, hostIP, intRevPort,
		indentBlock(rootPEM, "      "), acmeLeafProfile, hostIP)
	if p.acme {
		fmt.Fprintf(&b, `  acme:
    base_url: https://%s:%s/acme
    profile: %s
    allowed_identifier_suffixes: [cryptos.test]
    external_account_keys:
      - key_id: %s
        hmac_key_base64: %s
`, hostIP, acmeFrontPort, acmeLeafProfile, acmeEABKeyID, p.eabKeyB64)
	}
	if p.est {
		fmt.Fprintf(&b, `  est:
    hostnames: ["127.0.0.1"]
    profile: est-client
    allowed_identifier_suffixes: [cryptos.test]
    enroll_credentials:
      - username: %s
        password_sha256: %s
`, estUser, p.estPassSHA256)
	}
	return b.String()
}

// ---- keys, CSRs and certificates ------------------------------------------------

func newCSR(t *testing.T, key crypto.Signer, cn string, dns ...string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dns,
	}, key)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	return der
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func keyPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pemBlock("PRIVATE KEY", der)
}

func p384(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("P-384 key: %v", err)
	}
	return k
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("RSA-%d key: %v", bits, err)
	}
	return k
}

func parsePEMCerts(t *testing.T, data []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		t.Fatalf("no certificate in:\n%s", data)
	}
	return out
}

func verifyTo(t *testing.T, leaf *x509.Certificate, root *x509.Certificate, inter []*x509.Certificate, dns string, eku x509.ExtKeyUsage) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	ip := x509.NewCertPool()
	for _, c := range inter {
		ip.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: dns, Roots: roots, Intermediates: ip, KeyUsages: []x509.ExtKeyUsage{eku}}); err != nil {
		t.Fatalf("certificate %s (serial %s) does not verify to the Root: %v", leaf.Subject, leaf.SerialNumber.Text(16), err)
	}
}

func run(t *testing.T, stdin string, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := run(t, "", name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func eventually(t *testing.T, what string, timeout time.Duration, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for {
		ok, state := check()
		if ok {
			return
		}
		last = state
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached within %s; last: %s", what, timeout, last)
		}
		time.Sleep(3 * time.Second)
	}
}

// ---- the suite -------------------------------------------------------------------

// state is what one step hands the next.
type suiteState struct {
	admin     admin
	adminPEM  string
	root      *vm
	inter     *vm
	spare     *vm
	rootCert  *x509.Certificate
	rootPEM   string
	intCert   *x509.Certificate
	intPEM    string
	eabKeyB64 string
	estPass   string
	nginxDir  string
	nginxLeaf *x509.Certificate
	backup    string
	backupPwd string
}

func TestImageSuite(t *testing.T) {
	e := loadSuiteEnv(t)
	s := &suite{t: t, env: e, passed: map[string]bool{}}
	t.Cleanup(s.writeSummary)
	st := &suiteState{}

	certPEM, adminKeyPEM, _ := generateBootstrapAdmin(t)
	st.admin = admin{cert: filepath.Join(e.out, "admin.crt"), key: filepath.Join(e.out, "admin.key")}
	writeFile(t, st.admin.cert, certPEM)
	writeFile(t, st.admin.key, adminKeyPEM)
	st.adminPEM = string(certPEM)

	eab := make([]byte, 32)
	_, _ = rand.Read(eab)
	st.eabKeyB64 = base64.RawURLEncoding.EncodeToString(eab)
	st.estPass = "est-" + hex.EncodeToString(eab[:8])

	s.step("root: boot and first-boot ceremony", nil, func(t *testing.T) { stepRootCeremony(t, s, st) })
	s.step("intermediate: boot, sign-subordinate on the Root, submit", []string{"root: boot and first-boot ceremony"},
		func(t *testing.T) { stepIntermediate(t, s, st) })
	const hier = "intermediate: boot, sign-subordinate on the Root, submit"
	s.step("leaf issuance: ECDSA P-384 and RSA 3072 issue, RSA 2048 refused", []string{hier},
		func(t *testing.T) { stepLeaves(t, s, st) })
	s.step("nginx serves the leaf with a good OCSP staple", []string{hier},
		func(t *testing.T) { stepNginx(t, s, st) })
	s.step("revocation: OCSP and the CRL say revoked, nginx stops stapling good", []string{"nginx serves the leaf with a good OCSP staple"},
		func(t *testing.T) { stepRevocation(t, s, st) })
	s.step("protocol switch: ACME and EST on, reboot pending, reboot, running", []string{hier},
		func(t *testing.T) { stepProtocolsOn(t, s, st) })
	const protoOn = "protocol switch: ACME and EST on, reboot pending, reboot, running"
	s.step("ACME: cert-manager in kind gets and renews a certificate over http-01", []string{protoOn},
		func(t *testing.T) { stepACME(t, s, st) })
	s.step("EST: simpleenroll and simplereenroll with curl", []string{protoOn},
		func(t *testing.T) { stepEST(t, s, st) })
	s.step("re-certify the Intermediate on the same key", []string{hier},
		func(t *testing.T) { stepRecertify(t, s, st) })
	s.step("escrow: export refused on the TPM node, short passphrase refused, export from the Root", []string{hier},
		func(t *testing.T) { stepEscrowExport(t, s, st) })
	s.step("escrow: import the Root backup onto a fresh node", []string{"escrow: export refused on the TPM node, short passphrase refused, export from the Root"},
		func(t *testing.T) { stepEscrowImport(t, s, st) })
	s.skipStep("audit: the audit chain verifies",
		"no RPC or cryptosctl command verifies the audit chain yet; audit.VerifyChain runs only in-process, and the log sits on the encrypted state partition")
	s.skipStep("SNTP: the clock line shows synced against a local NTP server",
		"no SNTP client on main yet (cryptos#249, PR cryptos#271)")
	s.skipStep("SCEP: sscep enrols",
		"no SCEP server on main yet (cryptos#185, PR cryptos#288)")
	s.step("image upgrade in place on the software-key Root, then it still signs", []string{hier},
		func(t *testing.T) { stepUpgrade(t, s, st, st.root, suiteRootCN) })
	s.step("image upgrade in place on the TPM Intermediate, then it still issues", []string{hier},
		func(t *testing.T) { stepUpgrade(t, s, st, st.inter, suiteIntCN) })
	s.step("protocol switch: ACME off, reboot pending, reboot, cleared", []string{protoOn},
		func(t *testing.T) { stepProtocolsOff(t, s, st) })
	s.step("console reset over the serial line, on a throwaway node", []string{"escrow: import the Root backup onto a fresh node"},
		func(t *testing.T) { stepConsoleReset(t, s, st) })

	for _, v := range []*vm{st.spare, st.inter, st.root} {
		if v != nil {
			v.stop()
		}
	}
}

func stepRootCeremony(t *testing.T, s *suite, st *suiteState) {
	st.root = s.newVM(t, "root", "564d0001-0000-0000-0000-00000000e2e1", rootMgmtPort, nil, rootYAML(st.adminPEM, "e2e-root"), st.admin)
	st.root.boot(t)
	out := st.root.mustCtl(t, "ceremony", "start", "--config", filepath.Join(st.root.dir, "machine.yaml"))
	for _, want := range []string{"KEY_CREATED", "CERT_SIGNED", "MANIFEST_WRITTEN", "ADMIN_ROTATED", "COMPLETE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ceremony output missing %q:\n%s", want, out)
		}
	}
	st.rootPEM = st.root.mustCtl(t, "identity", "show", "-o", "pem")
	st.rootCert = parsePEMCerts(t, []byte(st.rootPEM))[0]
	writeFile(t, filepath.Join(s.env.out, "root.pem"), []byte(st.rootPEM))
	if out := st.root.mustCtl(t, "identity", "validate"); !strings.Contains(out, "OK") {
		t.Fatalf("identity validate: %s", out)
	}
	status := st.root.status(t)
	for _, want := range []string{"Role:            ROOT", "Identity:        ESTABLISHED", "TPM:             UNAVAILABLE"} {
		if !strings.Contains(status, want) {
			t.Fatalf("root status missing %q:\n%s", want, status)
		}
	}
	if st.rootCert.Subject.CommonName != suiteRootCN || !st.rootCert.IsCA {
		t.Fatalf("root certificate: CN %q CA %t", st.rootCert.Subject.CommonName, st.rootCert.IsCA)
	}
	note(t, "software (nodeid) Root, ECDSA P-384")
}

func stepIntermediate(t *testing.T, s *suite, st *suiteState) {
	cfg := intYAML(st.adminPEM, st.rootPEM, s.env.hostIP, intProtocols{})
	st.inter = s.newVM(t, "intermediate", "564d0002-0000-0000-0000-00000000e2e2", intMgmtPort, []string{
		"hostfwd=tcp:" + s.env.hostIP + ":" + intRevPort + "-" + suiteNodeAddr + ":80",
		"hostfwd=tcp:127.0.0.1:" + intACMEPort + "-" + suiteNodeAddr + ":8555",
		"hostfwd=tcp:127.0.0.1:" + intESTPort + "-" + suiteNodeAddr + ":8443",
	}, cfg, st.admin)
	st.inter.boot(t)
	if status := st.inter.status(t); !strings.Contains(status, "Identity:        AWAITING_CERT") || !strings.Contains(status, "TPM:             OK") {
		t.Fatalf("intermediate before signing: want AWAITING_CERT with the TPM OK:\n%s", status)
	}
	csr := st.inter.mustCtl(t, "ca", "get-subordinate-csr")
	csrPath := filepath.Join(st.inter.dir, "subordinate.csr")
	writeFile(t, csrPath, []byte(csr))
	chain := st.root.mustCtl(t, "ca", "sign-subordinate", "--csr", csrPath, "--profile", "sub-ca")
	chainPath := filepath.Join(st.inter.dir, "subordinate-chain.pem")
	writeFile(t, chainPath, []byte(chain))
	st.inter.mustCtl(t, "ca", "submit-subordinate-cert", "--chain", chainPath)

	st.intPEM = st.inter.mustCtl(t, "identity", "show", "-o", "pem")
	certs := parsePEMCerts(t, []byte(st.intPEM))
	st.intCert = certs[0]
	writeFile(t, filepath.Join(s.env.out, "intermediate.pem"), pemBlock("CERTIFICATE", st.intCert.Raw))
	roots := x509.NewCertPool()
	roots.AddCert(st.rootCert)
	if _, err := st.intCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("intermediate does not verify to the Root: %v", err)
	}
	if !st.intCert.IsCA || st.intCert.MaxPathLen != 0 || !st.intCert.MaxPathLenZero {
		t.Fatalf("intermediate: CA %t pathlen %d (zero %t), want a CA with pathlen 0", st.intCert.IsCA, st.intCert.MaxPathLen, st.intCert.MaxPathLenZero)
	}
	if status := st.inter.status(t); !strings.Contains(status, "Identity:        ESTABLISHED") {
		t.Fatalf("intermediate after submit: not ESTABLISHED:\n%s", status)
	}
	note(t, "TPM-held Intermediate key, chain verifies to the Root")
}

func stepLeaves(t *testing.T, s *suite, st *suiteState) {
	dir := filepath.Join(s.env.out, "leaves")
	_ = os.MkdirAll(dir, 0o755)
	issue := func(name string, key crypto.Signer) (string, error) {
		csr := filepath.Join(dir, name+".csr")
		writeFile(t, csr, pemBlock("CERTIFICATE REQUEST", newCSR(t, key, name+".cryptos.test")))
		return st.inter.ctl("", "ca", "issue-leaf", "--csr", csr, "--profile", "tls-server", "--dns", name+".cryptos.test")
	}
	for _, c := range []struct {
		name string
		key  crypto.Signer
	}{{"leaf-p384", p384(t)}, {"leaf-rsa3072", rsaKey(t, 3072)}} {
		out, err := issue(c.name, c.key)
		if err != nil {
			t.Fatalf("issue-leaf %s: %v\n%s", c.name, err, out)
		}
		leaf := parsePEMCerts(t, []byte(out))[0]
		verifyTo(t, leaf, st.rootCert, []*x509.Certificate{st.intCert}, c.name+".cryptos.test", x509.ExtKeyUsageServerAuth)
		if !listsSerial(t, st.inter, leaf.SerialNumber, "tls-server") {
			t.Fatalf("ca list-issued does not show %s serial %s", c.name, leaf.SerialNumber.Text(16))
		}
	}
	out, err := issue("leaf-rsa2048", rsaKey(t, 2048))
	if err == nil {
		t.Fatalf("an RSA 2048 CSR was issued, want it refused:\n%s", out)
	}
	if !strings.Contains(out, "at least 3072 bits") {
		t.Fatalf("RSA 2048 refused with an unexpected error:\n%s", out)
	}
	note(t, "RSA 2048 refused: "+strings.TrimSpace(lastLines(out, 1)))
}

// listsSerial reports whether `ca list-issued` on v shows serial under profile.
func listsSerial(t *testing.T, v *vm, serial *big.Int, profile string) bool {
	t.Helper()
	out := v.mustCtl(t, "ca", "list-issued")
	want := strings.ToLower(serial.Text(16))
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.ToLower(f[0]) == want {
			return profile == "" || strings.Contains(line, profile)
		}
	}
	return false
}

func stepNginx(t *testing.T, s *suite, st *suiteState) {
	dir := filepath.Join(s.env.out, "nginx")
	_ = os.MkdirAll(dir, 0o755)
	key := p384(t)
	csr := filepath.Join(dir, "leaf.csr")
	writeFile(t, csr, pemBlock("CERTIFICATE REQUEST", newCSR(t, key, nginxName)))
	leafPEM := st.inter.mustCtl(t, "ca", "issue-leaf", "--csr", csr, "--profile", "tls-server", "--dns", nginxName)
	st.nginxLeaf = parsePEMCerts(t, []byte(leafPEM))[0]
	if len(st.nginxLeaf.OCSPServer) == 0 {
		t.Fatalf("leaf carries no OCSP pointer (AIA); revocation_base_url is set on the Intermediate")
	}
	t.Logf("leaf serial %s, OCSP %v, CRL %v", st.nginxLeaf.SerialNumber.Text(16), st.nginxLeaf.OCSPServer, st.nginxLeaf.CRLDistributionPoints)

	intPEM := pemBlock("CERTIFICATE", st.intCert.Raw)
	writeFile(t, filepath.Join(dir, "fullchain.pem"), append(pemBlock("CERTIFICATE", st.nginxLeaf.Raw), intPEM...))
	writeFile(t, filepath.Join(dir, "leaf.pem"), pemBlock("CERTIFICATE", st.nginxLeaf.Raw))
	writeFile(t, filepath.Join(dir, "leaf.key"), keyPEM(t, key))
	writeFile(t, filepath.Join(dir, "intermediate.pem"), intPEM)
	writeFile(t, filepath.Join(dir, "root.pem"), []byte(st.rootPEM))
	writeFile(t, filepath.Join(dir, "trusted.pem"), append(intPEM, []byte(st.rootPEM)...))
	writeFile(t, filepath.Join(dir, "nginx.conf"), []byte(fmt.Sprintf(`worker_processes 1;
error_log /dev/stderr info;
events {}
http {
  access_log /dev/stdout;
  server {
    listen 127.0.0.1:%s ssl;
    server_name %s;
    ssl_certificate /etc/e2e/fullchain.pem;
    ssl_certificate_key /etc/e2e/leaf.key;
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/e2e/trusted.pem;
    location / { return 200 "served by nginx\n"; }
  }
}
`, nginxPort, nginxName)))
	for _, f := range []string{"fullchain.pem", "leaf.key", "trusted.pem", "nginx.conf"} {
		_ = os.Chmod(filepath.Join(dir, f), 0o644)
	}
	_, _ = run(t, "", "docker", "rm", "-f", nginxContainer)
	mustRun(t, "docker", "run", "-d", "--name", nginxContainer, "--network", "host",
		"-v", dir+":/etc/e2e:ro", "-v", filepath.Join(dir, "nginx.conf")+":/etc/nginx/nginx.conf:ro", s.env.nginx)
	st.nginxDir = dir
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := run(t, "", "docker", "logs", nginxContainer)
			t.Logf("nginx logs:\n%s", lastLines(logs, 40))
		}
	})

	url := "https://" + nginxName + ":" + nginxPort + "/"
	resolve := nginxName + ":" + nginxPort + ":127.0.0.1"
	eventually(t, "curl --cacert root.pem through nginx", time.Minute, func() (bool, string) {
		out, err := run(t, "", "curl", "-sS", "--fail", "--cacert", filepath.Join(dir, "root.pem"), "--resolve", resolve, url)
		return err == nil && strings.Contains(out, "served by nginx"), out
	})
	sclient := func() string {
		out, _ := run(t, "", "openssl", "s_client", "-connect", "127.0.0.1:"+nginxPort, "-servername", nginxName,
			"-CAfile", filepath.Join(dir, "root.pem"), "-verify_return_error", "-status")
		return out
	}
	out := sclient()
	if !strings.Contains(out, "Verify return code: 0 (ok)") {
		t.Fatalf("openssl s_client -verify_return_error did not verify:\n%s", out)
	}
	// nginx fetches the OCSP response after the first handshake that needs
	// it, so the staple shows up on a later one.
	eventually(t, "a good OCSP staple from nginx", 90*time.Second, func() (bool, string) {
		o := sclient()
		return strings.Contains(o, "OCSP Response Status: successful") && strings.Contains(o, "Cert Status: good"), stapleState(o)
	})
	if out, err := run(t, "", "curl", "-sS", "--fail", "--cert-status", "--cacert", filepath.Join(dir, "root.pem"), "--resolve", resolve, url); err != nil {
		t.Fatalf("curl --cert-status with a good staple: %v\n%s", err, out)
	}
	note(t, "curl, s_client -verify_return_error and the stapled status all good")
}

func stapleState(sclient string) string {
	for _, l := range strings.Split(sclient, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "OCSP response:") || strings.HasPrefix(l, "OCSP Response Status") || strings.HasPrefix(l, "Cert Status") {
			return l
		}
	}
	return "no OCSP lines"
}

func stepRevocation(t *testing.T, s *suite, st *suiteState) {
	leaf, dir := st.nginxLeaf, st.nginxDir
	serial := leaf.SerialNumber.Text(16)
	out := st.inter.mustCtl(t, "ca", "revoke", "--serial", serial, "--reason", "1")
	if !strings.Contains(strings.ToLower(out), strings.ToLower(serial)) {
		t.Fatalf("revoke output does not name %s:\n%s", serial, out)
	}

	ocspURL := leaf.OCSPServer[0]
	req, err := ocsp.CreateRequest(leaf, st.intCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("OCSP request: %v", err)
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		var resp *http.Response
		if method == http.MethodPost {
			resp, err = http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(req))
		} else {
			resp, err = http.Get(ocspURL + "/" + url.PathEscape(base64.StdEncoding.EncodeToString(req)))
		}
		if err != nil {
			t.Fatalf("OCSP %s %s: %v", method, ocspURL, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("OCSP %s: HTTP %d", method, resp.StatusCode)
		}
		r, err := ocsp.ParseResponseForCert(body, leaf, st.intCert)
		if err != nil {
			t.Fatalf("OCSP %s: parse and verify the response: %v", method, err)
		}
		if r.Status != ocsp.Revoked || r.RevocationReason != ocsp.KeyCompromise {
			t.Fatalf("OCSP %s: status %d reason %d, want revoked (keyCompromise)", method, r.Status, r.RevocationReason)
		}
	}
	if out := mustRun(t, "openssl", "ocsp", "-issuer", filepath.Join(dir, "intermediate.pem"), "-cert", filepath.Join(dir, "leaf.pem"),
		"-url", ocspURL, "-CAfile", filepath.Join(dir, "root.pem"), "-verify_other", filepath.Join(dir, "intermediate.pem")); !strings.Contains(out, ": revoked") {
		t.Fatalf("openssl ocsp: want revoked:\n%s", out)
	}

	if len(leaf.CRLDistributionPoints) == 0 {
		t.Fatal("leaf carries no CRL distribution point")
	}
	resp, err := http.Get(leaf.CRLDistributionPoints[0])
	if err != nil {
		t.Fatalf("fetch the CRL: %v", err)
	}
	crlDER, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse the CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(st.intCert); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	listed := false
	for _, rc := range crl.RevokedCertificateEntries {
		if rc.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("the CRL (%d entries) does not list %s", len(crl.RevokedCertificateEntries), serial)
	}

	// nginx refetches the status after a reload. It staples only a good
	// status: on a revoked one it logs the status and stops stapling, so the
	// good staple has to disappear and the log has to say why.
	mustRun(t, "docker", "exec", nginxContainer, "nginx", "-s", "reload")
	eventually(t, "nginx refetches the status and finds the leaf revoked", 2*time.Minute, func() (bool, string) {
		o, _ := run(t, "", "openssl", "s_client", "-connect", "127.0.0.1:"+nginxPort, "-servername", nginxName,
			"-CAfile", filepath.Join(dir, "root.pem"), "-status")
		logs, _ := run(t, "", "docker", "logs", nginxContainer)
		revokedLogged := strings.Contains(logs, `certificate status "revoked"`)
		stapledRevoked := strings.Contains(o, "Cert Status: revoked")
		stillGood := strings.Contains(o, "Cert Status: good")
		return (stapledRevoked || revokedLogged) && !stillGood, stapleState(o) + fmt.Sprintf("; nginx logged revoked: %t", revokedLogged)
	})
	resolve := nginxName + ":" + nginxPort + ":127.0.0.1"
	if out, err := run(t, "", "curl", "-sS", "--fail", "--cert-status", "--cacert", filepath.Join(dir, "root.pem"),
		"--resolve", resolve, "https://"+nginxName+":"+nginxPort+"/"); err == nil {
		t.Fatalf("curl --cert-status accepted a revoked staple:\n%s", out)
	}
	note(t, "OCSP (POST and GET) and openssl ocsp say revoked, the CRL lists it, nginx drops the good staple, curl --cert-status refuses")
}

func (st *suiteState) intConfig(s *suite, acme, est bool) string {
	sum := sha256.Sum256([]byte(st.estPass))
	return intYAML(st.adminPEM, st.rootPEM, s.env.hostIP, intProtocols{
		acme: acme, est: est, eabKeyB64: st.eabKeyB64, estPassSHA256: hex.EncodeToString(sum[:]),
	})
}

func applyConfig(t *testing.T, v *vm, yaml string) string {
	t.Helper()
	path := filepath.Join(v.dir, fmt.Sprintf("apply-%d.yaml", time.Now().UnixNano()))
	writeFile(t, path, []byte(yaml))
	return v.mustCtl(t, "config", "apply", "-f", path)
}

func stepProtocolsOn(t *testing.T, s *suite, st *suiteState) {
	if status := st.inter.status(t); !strings.Contains(status, "Protocols:       ACME off, EST off") {
		t.Fatalf("before the switch, want ACME and EST off:\n%s", status)
	}
	out := applyConfig(t, st.inter, st.intConfig(s, true, true))
	if !strings.Contains(out, "requires_reboot=true") {
		t.Fatalf("config apply with ACME and EST on: want requires_reboot=true:\n%s", out)
	}
	status := st.inter.status(t)
	for _, want := range []string{
		"ACME on (not running, reboot pending)", "EST on (not running, reboot pending)", "Reboot:          pending",
	} {
		if !strings.Contains(status, want) {
			t.Fatalf("after apply, status missing %q:\n%s", want, status)
		}
	}
	st.inter.reboot(t, suiteIntCN)
	status = st.inter.status(t)
	if !strings.Contains(status, "Protocols:       ACME on, EST on\n") || strings.Contains(status, "Reboot:") {
		t.Fatalf("after the reboot, want ACME and EST running and no pending reboot:\n%s", status)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://127.0.0.1:" + intACMEPort + "/acme/directory")
	if err != nil {
		t.Fatalf("the ACME origin does not answer after the reboot: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ACME directory: HTTP %d after the reboot", resp.StatusCode)
	}
	note(t, "pending shown after apply, cleared by the reboot")
}

func stepProtocolsOff(t *testing.T, s *suite, st *suiteState) {
	out := applyConfig(t, st.inter, st.intConfig(s, false, true))
	if !strings.Contains(out, "requires_reboot=true") {
		t.Fatalf("config apply with ACME off: want requires_reboot=true:\n%s", out)
	}
	status := st.inter.status(t)
	if !strings.Contains(status, "ACME off (still running, reboot pending)") || !strings.Contains(status, "Reboot:          pending") {
		t.Fatalf("after apply, want ACME still running with a reboot pending:\n%s", status)
	}
	st.inter.reboot(t, suiteIntCN)
	status = st.inter.status(t)
	if !strings.Contains(status, "Protocols:       ACME off, EST on\n") || strings.Contains(status, "Reboot:") {
		t.Fatalf("after the reboot, want ACME off, EST on and nothing pending:\n%s", status)
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+intACMEPort, 3*time.Second); err == nil {
		// QEMU accepts on the host side of the forward even with nothing behind
		// it, so a refused request, not a refused dial, proves it is off.
		_ = c.Close()
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://127.0.0.1:" + intACMEPort + "/acme/directory")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("the ACME port still answers HTTP %d after the switch off", resp.StatusCode)
	}
	note(t, "still running until the reboot, off after it")
}

func stepEST(t *testing.T, s *suite, st *suiteState) {
	dir := filepath.Join(s.env.out, "est")
	_ = os.MkdirAll(dir, 0o755)
	base := "https://127.0.0.1:" + intESTPort + "/.well-known/est"
	rootFile := filepath.Join(s.env.out, "root.pem")

	enroll := func(op string, key crypto.Signer, extra ...string) *x509.Certificate {
		t.Helper()
		csr := filepath.Join(dir, op+".b64")
		writeFile(t, csr, []byte(base64.StdEncoding.EncodeToString(newCSR(t, key, estClientName))))
		resp := filepath.Join(dir, op+".p7.b64")
		args := append([]string{"-sS", "--fail-with-body", "--cacert", rootFile,
			"-H", "Content-Type: application/pkcs10", "--data-binary", "@" + csr, "-o", resp}, extra...)
		args = append(args, base+"/"+op)
		if out, err := run(t, "", "curl", args...); err != nil {
			body, _ := os.ReadFile(resp)
			t.Fatalf("EST %s: %v\n%s\n%s", op, err, out, body)
		}
		b64, _ := os.ReadFile(resp)
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(b64)), ""))
		if err != nil {
			t.Fatalf("EST %s: the response is not base64: %v", op, err)
		}
		p7 := filepath.Join(dir, op+".p7")
		writeFile(t, p7, der)
		certs := parsePEMCerts(t, []byte(mustRun(t, "openssl", "pkcs7", "-inform", "DER", "-in", p7, "-print_certs")))
		var leaf *x509.Certificate
		var rest []*x509.Certificate
		for _, c := range certs {
			if c.IsCA {
				rest = append(rest, c)
			} else {
				leaf = c
			}
		}
		if leaf == nil {
			t.Fatalf("EST %s: no end-entity certificate in the response", op)
		}
		verifyTo(t, leaf, st.rootCert, append(rest, st.intCert), estClientName, x509.ExtKeyUsageClientAuth)
		return leaf
	}

	cacerts, err := run(t, "", "curl", "-sS", "--fail", "--cacert", rootFile, base+"/cacerts")
	if err != nil || len(strings.TrimSpace(cacerts)) == 0 {
		t.Fatalf("EST cacerts: %v\n%s", err, cacerts)
	}
	if out, err := run(t, "", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--cacert", rootFile,
		"-u", estUser+":wrong-password", "-H", "Content-Type: application/pkcs10", "--data-binary", "x", base+"/simpleenroll"); err != nil || out != "401" {
		t.Fatalf("EST simpleenroll with a wrong password: want HTTP 401, got %q (%v)", out, err)
	}
	key := p384(t)
	first := enroll("simpleenroll", key, "-u", estUser+":"+st.estPass)
	certFile, keyFile := filepath.Join(dir, "enrolled.pem"), filepath.Join(dir, "enrolled.key")
	writeFile(t, certFile, pemBlock("CERTIFICATE", first.Raw))
	writeFile(t, keyFile, keyPEM(t, key))
	second := enroll("simplereenroll", p384(t), "--cert", certFile, "--key", keyFile)
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Fatal("simplereenroll returned the same serial")
	}
	for _, c := range []*x509.Certificate{first, second} {
		if !listsSerial(t, st.inter, c.SerialNumber, "est-client") {
			t.Fatalf("ca list-issued does not show EST serial %s", c.SerialNumber.Text(16))
		}
	}
	note(t, fmt.Sprintf("enrolled %s, re-enrolled %s", first.SerialNumber.Text(16), second.SerialNumber.Text(16)))
}

func stepRecertify(t *testing.T, s *suite, st *suiteState) {
	before := st.intCert
	csr := st.inter.mustCtl(t, "ca", "get-renewal-csr")
	csrPath := filepath.Join(st.inter.dir, "renewal.csr")
	writeFile(t, csrPath, []byte(csr))
	chain := st.root.mustCtl(t, "ca", "sign-subordinate", "--csr", csrPath, "--profile", "sub-ca")
	chainPath := filepath.Join(st.inter.dir, "renewal-chain.pem")
	writeFile(t, chainPath, []byte(chain))
	st.inter.mustCtl(t, "ca", "submit-renewed-cert", "--chain", chainPath)
	after := parsePEMCerts(t, []byte(st.inter.mustCtl(t, "identity", "show", "-o", "pem")))[0]
	if after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Fatal("re-certify kept the old certificate")
	}
	if !bytes.Equal(after.RawSubjectPublicKeyInfo, before.RawSubjectPublicKeyInfo) {
		t.Fatal("re-certify changed the Intermediate's key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(st.rootCert)
	if _, err := after.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("re-certified Intermediate does not verify to the Root: %v", err)
	}
	st.intCert = after
	writeFile(t, filepath.Join(s.env.out, "intermediate.pem"), pemBlock("CERTIFICATE", after.Raw))
	// A leaf issued now chains through the new certificate.
	key := p384(t)
	dir := filepath.Join(s.env.out, "leaves")
	_ = os.MkdirAll(dir, 0o755)
	leafCSR := filepath.Join(dir, "after-recertify.csr")
	writeFile(t, leafCSR, pemBlock("CERTIFICATE REQUEST", newCSR(t, key, "after-recertify.cryptos.test")))
	leaf := parsePEMCerts(t, []byte(st.inter.mustCtl(t, "ca", "issue-leaf", "--csr", leafCSR, "--profile", "tls-server", "--dns", "after-recertify.cryptos.test")))[0]
	verifyTo(t, leaf, st.rootCert, []*x509.Certificate{after}, "after-recertify.cryptos.test", x509.ExtKeyUsageServerAuth)
	note(t, fmt.Sprintf("serial %s -> %s, same key", before.SerialNumber.Text(16), after.SerialNumber.Text(16)))
}

// stepUpgrade stages the successor image on v, activates it and checks the
// node came back on it with its identity and state, then issues through it.
func stepUpgrade(t *testing.T, s *suite, st *suiteState, v *vm, cn string) {
	if s.env.nextUKI == "" {
		note(t, "no successor image (E2E_IMAGE_NEXT_UKI)")
		t.Skip("no successor image")
	}
	before := v.mustCtl(t, "image", "status")
	idBefore := v.mustCtl(t, "identity", "show", "-o", "pem")
	out := v.mustCtl(t, "image", "stage", "--image", s.env.nextUKI)
	t.Logf("%s: image stage:\n%s", v.name, out)
	staged := v.mustCtl(t, "image", "status")
	if !strings.Contains(staged, "Reboot pending:   yes") {
		t.Fatalf("%s: after staging, want a reboot pending:\n%s", v.name, staged)
	}
	prev, _ := os.ReadFile(v.trust)
	started := time.Now()
	v.mustCtl(t, "image", "activate", "--confirm", cn)
	v.waitUp(t, prev, started, "upgrade")
	after := v.mustCtl(t, "image", "status")
	if !strings.Contains(after, "-next") || !strings.Contains(after, "Reboot pending:   no") {
		t.Fatalf("%s: after the upgrade, want the successor running and nothing pending:\nbefore:\n%s\nafter:\n%s", v.name, before, after)
	}
	if id := v.mustCtl(t, "identity", "show", "-o", "pem"); id != idBefore {
		t.Fatalf("%s: the identity changed across the upgrade", v.name)
	}
	if status := v.status(t); !strings.Contains(status, "Identity:        ESTABLISHED") || !strings.Contains(status, "-next") {
		t.Fatalf("%s: after the upgrade:\n%s", v.name, status)
	}
	dir := filepath.Join(s.env.out, "leaves")
	_ = os.MkdirAll(dir, 0o755)
	if v == st.root {
		// The Root still signs: re-certify the Intermediate through it.
		csr := filepath.Join(st.inter.dir, "post-upgrade.csr")
		writeFile(t, csr, []byte(st.inter.mustCtl(t, "ca", "get-renewal-csr")))
		chain := v.mustCtl(t, "ca", "sign-subordinate", "--csr", csr, "--profile", "sub-ca")
		c := parsePEMCerts(t, []byte(chain))[0]
		if !bytes.Equal(c.RawSubjectPublicKeyInfo, st.intCert.RawSubjectPublicKeyInfo) {
			t.Fatal("the upgraded Root signed a different key")
		}
		roots := x509.NewCertPool()
		roots.AddCert(st.rootCert)
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Fatalf("certificate from the upgraded Root does not verify: %v", err)
		}
	} else {
		key := p384(t)
		csr := filepath.Join(dir, "post-upgrade.csr")
		writeFile(t, csr, pemBlock("CERTIFICATE REQUEST", newCSR(t, key, "post-upgrade.cryptos.test")))
		leaf := parsePEMCerts(t, []byte(v.mustCtl(t, "ca", "issue-leaf", "--csr", csr, "--profile", "tls-server", "--dns", "post-upgrade.cryptos.test")))[0]
		verifyTo(t, leaf, st.rootCert, []*x509.Certificate{st.intCert}, "post-upgrade.cryptos.test", x509.ExtKeyUsageServerAuth)
	}
	note(t, "staged, activated, back on the successor with the same identity, and signing")
}

func stepEscrowExport(t *testing.T, s *suite, st *suiteState) {
	dir := filepath.Join(s.env.out, "escrow")
	_ = os.MkdirAll(dir, 0o755)
	out, err := st.inter.ctl("a-passphrase-long-enough\na-passphrase-long-enough\n", "ca", "export-key", "--out", filepath.Join(dir, "int.bak"), "--yes")
	if err == nil || !strings.Contains(out, "non-exportable (TPM-backed)") {
		t.Fatalf("export on the TPM node: want non-exportable, got err=%v:\n%s", err, out)
	}
	short := "seventeen-bytes!!" // 17 bytes: one under the floor
	out, err = st.root.ctl(short+"\n"+short+"\n", "ca", "export-key", "--out", filepath.Join(dir, "short.bak"), "--yes")
	if err == nil || !strings.Contains(out, "at least 18 bytes") {
		t.Fatalf("export with a 17-byte passphrase: want refused, got err=%v:\n%s", err, out)
	}
	st.backupPwd = "e2e-escrow-" + hex.EncodeToString(randomBytes(8))
	st.backup = filepath.Join(dir, "root.bak")
	if out, err := st.root.ctl(st.backupPwd+"\n"+st.backupPwd+"\n", "ca", "export-key", "--out", st.backup, "--yes"); err != nil {
		t.Fatalf("export from the Root: %v\n%s", err, out)
	}
	if fi, err := os.Stat(st.backup); err != nil || fi.Size() == 0 {
		t.Fatalf("no backup written: %v", err)
	}
	note(t, "TPM node refuses, 17 bytes refused, Root exported")
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func stepEscrowImport(t *testing.T, s *suite, st *suiteState) {
	st.spare = s.newVM(t, "spare", "564d0003-0000-0000-0000-00000000e2e3", spareMgmtPort, nil, rootYAML(st.adminPEM, "e2e-spare"), st.admin)
	st.spare.boot(t)
	if status := st.spare.status(t); !strings.Contains(status, "Identity:        NONE") {
		t.Fatalf("fresh node: want no identity:\n%s", status)
	}
	if out, err := st.spare.ctl("wrong-passphrase-wrong-passphrase\n", "ca", "import-key", "--backup", st.backup); err == nil || !strings.Contains(out, "bad passphrase") {
		t.Fatalf("import with a wrong passphrase: want refused, got err=%v:\n%s", err, out)
	}
	if out, err := st.spare.ctl(st.backupPwd+"\n", "ca", "import-key", "--backup", st.backup); err != nil {
		t.Fatalf("import the Root backup: %v\n%s", err, out)
	}
	got := parsePEMCerts(t, []byte(st.spare.mustCtl(t, "identity", "show", "-o", "pem")))[0]
	if !bytes.Equal(got.Raw, st.rootCert.Raw) {
		t.Fatalf("the restored node holds %s (serial %s), not the Root", got.Subject, got.SerialNumber.Text(16))
	}
	if status := st.spare.status(t); !strings.Contains(status, "Identity:        ESTABLISHED") {
		t.Fatalf("restored node not ESTABLISHED:\n%s", status)
	}
	note(t, "wrong passphrase refused; the restored node holds the Root certificate")
}

func stepConsoleReset(t *testing.T, s *suite, st *suiteState) {
	v := st.spare
	waitForSerial(t, v.serial, "^R  reset (destroys this CA)", time.Minute)
	offset := v.serial.len()
	if _, err := v.keys.Write([]byte{0x12}); err != nil {
		t.Fatalf("send Ctrl-R: %v", err)
	}
	waitForSerialSince(t, v.serial, offset, "Type the Root CA CN to confirm", 30*time.Second)
	if _, err := v.keys.Write([]byte(suiteRootCN + "\r")); err != nil {
		t.Fatalf("type the CN: %v", err)
	}
	waitForSerialSince(t, v.serial, offset, "RESET IN PROGRESS", 30*time.Second)
	waitForSerialSince(t, v.serial, offset, "REPROVISION mode", 3*time.Minute)
	note(t, "Ctrl-R, CN, Enter: wiped and back in re-provision maintenance")
}

func waitForSerialSince(t *testing.T, log *serialLog, offset int, sub string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !strings.Contains(log.since(offset), sub) {
		if time.Now().After(deadline) {
			t.Fatalf("serial did not show %q within %s:\n%s", sub, timeout, lastLines(log.String(), 40))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ---- ACME with cert-manager -----------------------------------------------------

func stepACME(t *testing.T, s *suite, st *suiteState) {
	e := s.env
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	// The node serves ACME over plain HTTP behind a TLS terminator
	// (docs/acme.md). The front's certificate comes from the booted
	// Intermediate, so cert-manager trusts it through the Root.
	frontKey := p384(t)
	dir := filepath.Join(e.out, "acme")
	_ = os.MkdirAll(dir, 0o755)
	csr := filepath.Join(dir, "front.csr")
	writeFile(t, csr, pemBlock("CERTIFICATE REQUEST", newCSR(t, frontKey, "cryptos-acme-front")))
	front := parsePEMCerts(t, []byte(st.inter.mustCtl(t, "ca", "issue-leaf", "--csr", csr, "--profile", "acme-front")))[0]
	origin := &url.URL{Scheme: "http", Host: "127.0.0.1:" + intACMEPort}
	proxy := httputil.NewSingleHostReverseProxy(origin)
	lis, err := net.Listen("tcp", net.JoinHostPort(e.hostIP, acmeFrontPort))
	if err != nil {
		t.Fatalf("listen for the ACME TLS front: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("ACME front: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			proxy.ServeHTTP(w, r)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{front.Raw, st.intCert.Raw}, PrivateKey: frontKey}},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	defer func() { _ = srv.Close() }()
	baseURL := "https://" + net.JoinHostPort(e.hostIP, acmeFrontPort) + "/acme"

	kc := kubectl{t: t, kubeconfig: e.kubeconfig, bin: e.kubectl}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata: {name: cryptos-acme-eab, namespace: cert-manager}
type: Opaque
stringData: {hmac: %[1]s}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: cryptos-image}
spec:
  acme:
    server: %[2]s/directory
    caBundle: %[3]s
    privateKeySecretRef: {name: cryptos-image-account}
    externalAccountBinding:
      keyID: %[4]s
      keySecretRef: {name: cryptos-acme-eab, key: hmac}
    solvers:
      - http01:
          ingress: {ingressClassName: contour}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: %[5]s, namespace: %[6]s}
spec:
  secretName: %[7]s
  dnsNames: [%[8]s]
  privateKey: {algorithm: ECDSA, size: 384}
  issuerRef: {kind: ClusterIssuer, name: cryptos-image}
`, st.eabKeyB64, baseURL, base64.StdEncoding.EncodeToString([]byte(st.rootPEM)), acmeEABKeyID,
		kindCert, kindNS, kindSecret, e.hostname)
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := kc.run(ctx, manifest, "apply", "-f", "-"); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("apply the ClusterIssuer and Certificate: %v", err)
		} else {
			t.Logf("apply refused, retrying: %v", err)
		}
		time.Sleep(5 * time.Second)
	}

	first := kc.waitForCertificate(ctx, "", 6*time.Minute)
	s.checkACMECert(t, st, first)
	firstSerial := first.leaf.SerialNumber.Text(16)
	patch := fmt.Sprintf(`[{"op":"add","path":"/status/conditions/-","value":{"type":"Issuing","status":"True","reason":"ManuallyTriggered","message":"re-issuance triggered by the CryptOS full-image suite","lastTransitionTime":%q}}]`,
		time.Now().UTC().Format(time.RFC3339))
	if _, err := kc.run(ctx, "", "-n", kindNS, "patch", "certificate", kindCert, "--subresource=status", "--type=json", "-p", patch); err != nil {
		t.Fatalf("trigger the renewal: %v", err)
	}
	second := kc.waitForCertificate(ctx, firstSerial, 6*time.Minute)
	s.checkACMECert(t, st, second)
	note(t, fmt.Sprintf("serial %s, renewed to %s, both in list-issued", firstSerial, second.leaf.SerialNumber.Text(16)))
}

func (s *suite) checkACMECert(t *testing.T, st *suiteState, c acmeCert) {
	t.Helper()
	verifyTo(t, c.leaf, st.rootCert, c.chain, s.env.hostname, x509.ExtKeyUsageServerAuth)
	if len(c.leaf.DNSNames) != 1 || c.leaf.DNSNames[0] != s.env.hostname {
		t.Fatalf("ACME leaf SANs %v, want [%s]", c.leaf.DNSNames, s.env.hostname)
	}
	if pub, ok := c.leaf.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P384() {
		t.Fatalf("ACME leaf key %T, want ECDSA P-384", c.leaf.PublicKey)
	}
	if !listsSerial(t, st.inter, c.leaf.SerialNumber, acmeLeafProfile) {
		t.Fatalf("ca list-issued on the Intermediate does not show ACME serial %s", c.leaf.SerialNumber.Text(16))
	}
}

type acmeCert struct {
	leaf  *x509.Certificate
	chain []*x509.Certificate
}

type kubectl struct {
	t               *testing.T
	kubeconfig, bin string
}

func (k kubectl) run(ctx context.Context, stdin string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, k.bin, append([]string{"--kubeconfig", k.kubeconfig}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func (k kubectl) waitForCertificate(ctx context.Context, notSerial string, timeout time.Duration) acmeCert {
	t := k.t
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		ready, _ := k.run(ctx, "", "-n", kindNS, "get", "certificate", kindCert,
			"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}/{.status.conditions[?(@.type=="Ready")].reason}`)
		if ready != last {
			t.Logf("Certificate %s/%s Ready=%s", kindNS, kindCert, ready)
			last = ready
		}
		if strings.HasPrefix(ready, "True/") {
			crt, err := k.run(ctx, "", "-n", kindNS, "get", "secret", kindSecret, "-o", `jsonpath={.data.tls\.crt}`)
			if err == nil {
				if raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(crt)); derr == nil && len(raw) > 0 {
					certs := parsePEMCerts(t, raw)
					if certs[0].SerialNumber.Text(16) != notSerial {
						return acmeCert{leaf: certs[0], chain: certs[1:]}
					}
				}
			}
		}
		if time.Now().After(deadline) {
			for _, args := range [][]string{
				{"-n", kindNS, "describe", "certificate,certificaterequest,order,challenge"},
				{"describe", "clusterissuer", "cryptos-image"},
				{"-n", "cert-manager", "logs", "deploy/cert-manager", "--tail=100"},
			} {
				out, _ := k.run(context.Background(), "", args...)
				t.Logf("--- kubectl %s ---\n%s", strings.Join(args, " "), out)
			}
			t.Fatalf("Certificate %s/%s got no new certificate within %s (last Ready=%q)", kindNS, kindCert, timeout, last)
		}
		time.Sleep(3 * time.Second)
	}
}
