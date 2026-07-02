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

// Phase 1 end-to-end acceptance: boot the UKI in QEMU + swtpm + OVMF,
// drive the first-boot ceremony with cryptosctl, and confirm the Root
// certificate is RFC 5280-clean (zlint).
//
// DRAFT: written to the intended flow but not yet run — it needs a Linux
// host with qemu-system, swtpm, OVMF, a built UKI, and cryptosctl. It
// skips when that toolchain isn't present, so `go test -tags=integration`
// is inert elsewhere. Run on a Linux host with the toolchain installed.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tool/artifact locations come from the environment so the harness is
// runner-agnostic. All are required; missing any skips the test.
type env struct {
	qemu, swtpm, ovmfCode, ovmfVars string
	cryptosctl, zlint               string
	cryptsetupStatic                string // baked into the rootfs
}

func loadEnv(t *testing.T) env {
	t.Helper()
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }
	e := env{
		qemu:             firstNonEmpty(get("QEMU"), "qemu-system-x86_64"),
		swtpm:            firstNonEmpty(get("SWTPM"), "swtpm"),
		ovmfCode:         get("OVMF_CODE"),
		ovmfVars:         get("OVMF_VARS"),
		cryptosctl:       get("CRYPTOSCTL"),
		zlint:            firstNonEmpty(get("ZLINT"), "zlint"),
		cryptsetupStatic: get("CRYPTSETUP_STATIC"),
	}
	missing := []string{}
	if _, err := exec.LookPath(e.qemu); err != nil {
		missing = append(missing, "QEMU")
	}
	if _, err := exec.LookPath(e.swtpm); err != nil {
		missing = append(missing, "swtpm")
	}
	if _, err := exec.LookPath("sgdisk"); err != nil {
		missing = append(missing, "sgdisk")
	}
	for k, v := range map[string]string{"OVMF_CODE": e.ovmfCode, "OVMF_VARS": e.ovmfVars, "CRYPTOSCTL": e.cryptosctl, "CRYPTSETUP_STATIC": e.cryptsetupStatic} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Skipf("integration toolchain not available; missing: %s", strings.Join(missing, ", "))
	}
	return e
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// repoRoot is the cryptos module root (this file lives at test/integration).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func TestPhase1CeremonyEndToEnd(t *testing.T) {
	e := loadEnv(t)
	root := repoRoot(t)
	dir := t.TempDir()

	// 1. Fresh bootstrap admin keypair (the client identity).
	adminCertPEM, adminKeyPEM, _ := generateBootstrapAdmin(t)
	adminCert := filepath.Join(dir, "bootstrap.crt")
	adminKey := filepath.Join(dir, "bootstrap.key")
	writeFile(t, adminCert, adminCertPEM)
	writeFile(t, adminKey, adminKeyPEM)

	// 2. Machine config pinning that admin, baked into the UKI. The mTLS
	// listener anchors its ClientCAs on the full admin cert, so the config
	// carries the PEM (not just the fingerprint form).
	machineYAML := filepath.Join(dir, "machine.yaml")
	writeFile(t, machineYAML, []byte(renderMachineYAML(string(adminCertPEM))))

	// 3. Build the debug UKI with that config (kernel assumed prebuilt).
	uki := buildDebugUKI(t, root, dir, machineYAML, e.cryptsetupStatic)

	// 4. swtpm + QEMU, forwarding localhost:4443 -> guest:443.
	sock := startSwtpm(t, e, dir)
	startQEMU(t, e, uki, sock, dir)

	const endpoint = "127.0.0.1:4443"
	waitForTLS(t, endpoint, 60*time.Second)

	// 5. TOFU-grab the node's ephemeral server cert into a trust file.
	trust := filepath.Join(dir, "trust.crt")
	writeFile(t, trust, fetchServerCert(t, endpoint))

	cryptosctl := func(args ...string) (string, error) {
		full := append([]string{
			"--endpoint", endpoint,
			"--identity", adminCert, "--identity-key", adminKey,
			"--trust", trust, "--server-name", "localhost",
		}, args...)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, e.cryptosctl, full...).CombinedOutput()
		return string(out), err
	}

	// 6. Run the ceremony; assert the event order.
	out, err := cryptosctl("ceremony", "start", "--config", machineYAML)
	if err != nil {
		t.Fatalf("ceremony start: %v\n%s", err, out)
	}
	for _, want := range []string{"KEY_CREATED", "CERT_SIGNED", "MANIFEST_WRITTEN", "ADMIN_ROTATED", "COMPLETE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ceremony output missing %q:\n%s", want, out)
		}
	}

	// 7. Export the Root cert and zlint it (0 errors, 0 warnings).
	pemOut, err := cryptosctl("identity", "show", "-o", "pem")
	if err != nil {
		t.Fatalf("identity show: %v\n%s", err, pemOut)
	}
	rootPEM := filepath.Join(dir, "root.pem")
	writeFile(t, rootPEM, []byte(pemOut))
	assertZlintClean(t, e.zlint, rootPEM)

	// 8. Chain validates; status reports an established identity.
	if out, err := cryptosctl("identity", "validate"); err != nil {
		t.Fatalf("identity validate: %v\n%s", err, out)
	}
	statusOut, err := cryptosctl("status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, statusOut)
	}
	if !strings.Contains(statusOut, "ESTABLISHED") {
		t.Fatalf("status not ESTABLISHED:\n%s", statusOut)
	}
}

func generateBootstrapAdmin(t *testing.T) (certPEM, keyPEM []byte, fingerprintHex string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "integration bootstrap admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	fp := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		hex.EncodeToString(fp[:])
}

func renderMachineYAML(adminCertPEM string) string {
	// Embed the admin cert as a YAML literal block scalar; each PEM line is
	// indented under admin_cert_pem so the multi-line value parses cleanly.
	var indented strings.Builder
	for _, line := range strings.Split(strings.TrimRight(adminCertPEM, "\n"), "\n") {
		indented.WriteString("    ")
		indented.WriteString(line)
		indented.WriteByte('\n')
	}
	return fmt.Sprintf(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: integration-root}
role: {kind: root}
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
storage: {state_partition_label: cryptos-state, first_boot: true}
bootstrap:
  admin_cert_pem: |
%s
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: "CryptOS Integration Root", organization: "Integration", country: "US"}
  root_validity_years: 20
  path_len_constraint: 2
`, strings.TrimRight(indented.String(), "\n"))
}

// buildDebugUKI builds the rootfs + debug UKI with the given machine
// config, returning the UKI path. The kernel is assumed prebuilt
// (task kernel:build) and cached.
func buildDebugUKI(t *testing.T, root, dir, machineYAML, cryptsetupStatic string) string {
	t.Helper()
	run := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"MACHINE_CONFIG="+machineYAML,
			"CRYPTSETUP_STATIC="+cryptsetupStatic,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("task", "kernel:build")
	run("task", "rootfs:build")
	run("task", "uki:assemble", "PROFILE=qemu-dev")
	uki := filepath.Join(root, "build", "out", "cryptos-amd64.uki.unsigned")
	if _, err := os.Stat(uki); err != nil {
		t.Fatalf("UKI not produced at %s: %v", uki, err)
	}
	return uki
}

func startSwtpm(t *testing.T, e env, dir string) string {
	t.Helper()
	state := filepath.Join(dir, "swtpm")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatalf("swtpm state dir: %v", err)
	}
	sock := filepath.Join(state, "sock")
	cmd := exec.Command(e.swtpm, "socket", "--tpm2",
		"--tpmstate", "dir="+state, "--ctrl", "type=unixio,path="+sock)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return sock
}

func startQEMU(t *testing.T, e env, uki, swtpmSock, dir string) {
	t.Helper()
	// State disk: a GPT image with one partition named "cryptos-state" (what the
	// installer would lay down). init resolves it by that GPT name via sysfs and
	// LUKS-formats it on first boot; attached as virtio-blk (-> /dev/vda1).
	statedisk := filepath.Join(dir, "state.img")
	if err := exec.Command("truncate", "-s", "2G", statedisk).Run(); err != nil {
		t.Fatalf("create state disk: %v", err)
	}
	if out, err := exec.Command("sgdisk", "--new=1:0:0",
		"--change-name=1:cryptos-state", "--typecode=1:8300", statedisk).CombinedOutput(); err != nil {
		t.Fatalf("partition state disk: %v\n%s", err, out)
	}
	// OVMF vars must be writable; copy the template into the temp dir.
	vars := filepath.Join(dir, "OVMF_VARS.fd")
	copyFile(t, e.ovmfVars, vars)

	// A UKI is a PE/EFI executable, not a bzImage: -kernel uses the Linux boot
	// protocol, which OVMF rejects for a UKI ("Bad kernel image: Load error").
	// Present it on an EFI System Partition at the removable-media fallback path
	// so OVMF auto-launches it; QEMU's VVFAT (fat:rw:<dir>) serves the directory
	// as a FAT ESP.
	esp := filepath.Join(dir, "esp")
	if err := os.MkdirAll(filepath.Join(esp, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatalf("create esp: %v", err)
	}
	copyFile(t, uki, filepath.Join(esp, "EFI", "BOOT", "BOOTX64.EFI"))

	cmd := exec.Command(e.qemu,
		"-machine", "q35,accel=kvm:tcg", "-m", "2048", "-nographic",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file="+e.ovmfCode,
		"-drive", "if=pflash,format=raw,unit=1,file="+vars,
		"-chardev", "socket,id=chrtpm,path="+swtpmSock,
		"-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
		"-device", "tpm-tis,tpmdev=tpm0",
		"-drive", "format=raw,file=fat:rw:"+esp,
		"-drive", "if=none,id=state,format=raw,file="+statedisk,
		"-device", "virtio-blk-pci,drive=state",
		"-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:4443-:443",
		"-device", "virtio-net-pci,netdev=n0",
	)
	logf, _ := os.Create(filepath.Join(dir, "qemu.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start qemu: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
}

func waitForTLS(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // probe only
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("node did not accept TLS on %s within %s", addr, timeout)
}

// fetchServerCert grabs the node's (ephemeral, self-signed) server cert
// via an InsecureSkipVerify dial so the client can then pin it. The
// client connection is still mutually authenticated by the admin cert.
func fetchServerCert(t *testing.T, addr string) []byte {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // TOFU grab
	if err != nil {
		t.Fatalf("fetch server cert: %v", err)
	}
	defer func() { _ = conn.Close() }()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("server presented no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})
}

func assertZlintClean(t *testing.T, zlint, certPath string) {
	t.Helper()
	out, err := exec.Command(zlint, certPath).CombinedOutput()
	if err != nil {
		t.Fatalf("zlint: %v\n%s", err, out)
	}
	// zlint emits JSON results; any "error" or "warn" result fails Phase 1.
	for _, bad := range []string{`"result":"error"`, `"result":"warn"`} {
		if strings.Contains(string(out), bad) {
			t.Fatalf("zlint reported %s:\n%s", bad, out)
		}
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	writeFile(t, dst, data)
}
