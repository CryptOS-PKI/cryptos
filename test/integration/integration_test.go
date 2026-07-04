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
// Runs on a Linux host with the toolchain present (qemu-system, swtpm, OVMF,
// mtools, a built UKI, cryptosctl, zlint); it skips when any is missing, so
// `go test -tags=integration` is inert elsewhere. Under pure TCG (no /dev/kvm)
// each boot takes a few minutes; the harness sizes its own timeouts for that.

import (
	"bytes"
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
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
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
	// makeInstalledDisk stages the config on the ESP with mtools; skip if absent.
	for _, tool := range []string{"mformat", "mmd", "mcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("mtools not available (%s missing); skipping Phase 1 acceptance test", tool)
		}
	}
	root := repoRoot(t)
	dir := t.TempDir()

	// 1. Fresh bootstrap admin keypair (the client identity).
	adminCertPEM, adminKeyPEM, _ := generateBootstrapAdmin(t)
	adminCert := filepath.Join(dir, "bootstrap.crt")
	adminKey := filepath.Join(dir, "bootstrap.key")
	writeFile(t, adminCert, adminCertPEM)
	writeFile(t, adminKey, adminKeyPEM)

	// 2. Machine config pinning that admin. It is staged on the ESP of the
	// installed disk so the node seeds it on first boot (the install-flow
	// delivery path); the UKI itself carries no config. The mTLS listener
	// anchors its ClientCAs on the full admin cert, so the config carries the
	// PEM (not just the fingerprint form). Seeding the config is also what gives
	// the node its static network address, so the mTLS listener binds the
	// address the harness forwards to.
	machineYAML := filepath.Join(dir, "machine.yaml")
	writeFile(t, machineYAML, []byte(renderMachineYAML(string(adminCertPEM))))

	// 3. Build the config-free debug UKI (kernel assumed prebuilt).
	uki := buildDebugUKI(t, root, e.cryptsetupStatic)

	// 4. Pre-installed disk (GPT: EFI + cryptos-state) with machine.yaml staged
	// on the ESP, exactly as the maintenance installer leaves it after
	// apply-config. First boot seeds the config, LUKS-formats the state
	// partition, and serves the ceremony over mTLS.
	installedDisk := makeInstalledDisk(t, dir, machineYAML)
	vars := filepath.Join(dir, "OVMF_VARS.fd")
	copyFile(t, e.ovmfVars, vars)
	esp := filepath.Join(dir, "esp")
	if err := os.MkdirAll(filepath.Join(esp, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatalf("create esp: %v", err)
	}
	copyFile(t, uki, filepath.Join(esp, "EFI", "BOOT", "BOOTX64.EFI"))

	// 5. swtpm + QEMU, forwarding localhost:4443 -> guest:443.
	sock := startSwtpm(t, e, dir)
	cmd := launchQEMU(t, e, uki, sock, installedDisk, vars, esp, filepath.Join(dir, "qemu.log"))
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	const endpoint = "127.0.0.1:4443"
	waitForTLS(t, endpoint, 60*time.Second)

	// 6. TOFU-grab the node's ephemeral server cert into a trust file.
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

	// 7. Run the ceremony; assert the event order.
	out, err := cryptosctl("ceremony", "start", "--config", machineYAML)
	if err != nil {
		t.Fatalf("ceremony start: %v\n%s", err, out)
	}
	for _, want := range []string{"KEY_CREATED", "CERT_SIGNED", "MANIFEST_WRITTEN", "ADMIN_ROTATED", "COMPLETE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ceremony output missing %q:\n%s", want, out)
		}
	}

	// 8. Export the Root cert and zlint it (0 errors, 0 warnings).
	pemOut, err := cryptosctl("identity", "show", "-o", "pem")
	if err != nil {
		t.Fatalf("identity show: %v\n%s", err, pemOut)
	}
	rootPEM := filepath.Join(dir, "root.pem")
	writeFile(t, rootPEM, []byte(pemOut))
	assertZlintClean(t, e.zlint, rootPEM)

	// 9. Chain validates; status reports an established identity.
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
	return renderMachineYAMLWithName(adminCertPEM, "integration-root")
}

// renderMachineYAMLWithName renders a machine config with the given name.
// The admin cert is embedded as a YAML literal block scalar.
func renderMachineYAMLWithName(adminCertPEM, name string) string {
	var indented strings.Builder
	for _, line := range strings.Split(strings.TrimRight(adminCertPEM, "\n"), "\n") {
		indented.WriteString("    ")
		indented.WriteString(line)
		indented.WriteByte('\n')
	}
	return fmt.Sprintf(`apiVersion: cryptos.dev/v1alpha1
kind: MachineConfig
metadata: {name: %s}
role: {kind: root}
network: {interface: eth0, address: 10.0.0.10/24, gateway: 10.0.0.1}
bootstrap:
  admin_cert_pem: |
%s
pki:
  root_key_alg: ECDSA-P384
  root_subject: {common_name: "CryptOS Integration Root", organization: "Integration", country: "US"}
  root_validity_years: 20
  path_len_constraint: 2
`, name, strings.TrimRight(indented.String(), "\n"))
}

// lastLines returns the last n lines of s.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

// buildDebugUKI builds the rootfs + debug UKI, returning the UKI path.
// The image carries no machine config; config is delivered via the ESP
// stage at runtime. The kernel is assumed prebuilt (task kernel:build)
// and cached.
func buildDebugUKI(t *testing.T, root, cryptsetupStatic string) string {
	t.Helper()
	run := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
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

// launchQEMU starts a QEMU VM with the given UKI, swtpm socket, pre-created
// state disk, OVMF vars file, and ESP directory. The log file is written to
// logPath. Returns the running command; the caller is responsible for killing
// it (the cleanup is NOT registered here to allow controlled shutdown order).
func launchQEMU(t *testing.T, e env, uki, swtpmSock, statedisk, vars, esp, logPath string) *exec.Cmd {
	t.Helper()
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
		// The node uses a static 10.0.0.10/24 (see renderMachineYAML), so the
		// user-mode network must use that subnet (default is 10.0.2.0/24) and the
		// host-forward must target the node's actual address, not the SLIRP
		// default guest IP — otherwise the forward reaches nothing.
		"-netdev", "user,id=n0,net=10.0.0.0/24,host=10.0.0.1,hostfwd=tcp:127.0.0.1:4443-10.0.0.10:443",
		"-device", "virtio-net-pci,netdev=n0",
	)
	logf, _ := os.Create(logPath)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start qemu: %v", err)
	}
	return cmd
}

// TestConfigPersistsAcrossReboot boots the same installed disk twice.
//
// Boot 1: the node seeds its config from the ESP stage (EFI/cryptos/machine.yaml,
// pre-staged with node-a), runs the ceremony, then applies a new config with
// metadata.name=node-b (via ApplyConfig). Shut down.
// Boot 2: same disk, no reformat. Assert:
//   - BootCount=2 (the state partition etcd incremented on the second boot)
//   - IdentityState=ESTABLISHED (existing identity was read; no re-ceremony)
//   - serial log contains "first_boot=false" (config was read from the state
//     partition, not re-seeded from the ESP stage)
//
// These three invariants together prove that the persisted config — including
// the node-b change from ApplyConfig — was read from the encrypted state
// partition on boot 2 rather than re-seeding from the ESP stage.
func TestConfigPersistsAcrossReboot(t *testing.T) {
	// mtools are needed to stage the config on the ESP of the installed disk.
	for _, tool := range []string{"mformat", "mmd", "mcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("mtools not available (%s missing); skipping reboot-persistence test", tool)
		}
	}

	e := loadEnv(t)
	root := repoRoot(t)
	dir := t.TempDir()

	// Admin keypair for the ceremony and subsequent RPCs.
	adminCertPEM, adminKeyPEM, _ := generateBootstrapAdmin(t)
	adminCert := filepath.Join(dir, "bootstrap.crt")
	adminKey := filepath.Join(dir, "bootstrap.key")
	writeFile(t, adminCert, adminCertPEM)
	writeFile(t, adminKey, adminKeyPEM)

	// node-a: the ESP-staged config (seeded on first boot, used in the ceremony).
	nodeAYAML := filepath.Join(dir, "node-a.yaml")
	writeFile(t, nodeAYAML, []byte(renderMachineYAMLWithName(string(adminCertPEM), "node-a")))

	// node-b: the config applied via ApplyConfig on boot 1 (persisted to state).
	nodeBYAML := filepath.Join(dir, "node-b.yaml")
	writeFile(t, nodeBYAML, []byte(renderMachineYAMLWithName(string(adminCertPEM), "node-b")))

	// Build the config-free UKI once (kernel assumed prebuilt). Config is
	// delivered via the ESP stage; the UKI itself carries none.
	uki := buildDebugUKI(t, root, e.cryptsetupStatic)

	// Shared OVMF vars and boot ESP (reused across both boots to preserve EFI state).
	vars := filepath.Join(dir, "OVMF_VARS.fd")
	copyFile(t, e.ovmfVars, vars)
	esp := filepath.Join(dir, "esp")
	if err := os.MkdirAll(filepath.Join(esp, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatalf("create esp: %v", err)
	}
	copyFile(t, uki, filepath.Join(esp, "EFI", "BOOT", "BOOTX64.EFI"))

	// Create the pre-installed disk once; both boots share it. node-a is staged
	// on the EFI partition so the node seeds from it on first boot.
	installedDisk := makeInstalledDisk(t, dir, nodeAYAML)

	// swtpm state persists across both boots (just like real TPM hardware).
	sock := startSwtpm(t, e, dir)

	const endpoint = "127.0.0.1:4443"

	// ---- Boot 1 ----
	t.Log("boot 1: ESP-stage seed + ceremony + ApplyConfig")
	boot1 := launchQEMU(t, e, uki, sock, installedDisk, vars, esp, filepath.Join(dir, "qemu-boot1.log"))
	t.Cleanup(func() { _ = boot1.Process.Kill() })

	waitForTLS(t, endpoint, 60*time.Second)

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

	// Run the ceremony with the node-a config (matches the ESP-staged config).
	out, err := cryptosctl("ceremony", "start", "--config", nodeAYAML)
	if err != nil {
		t.Fatalf("boot1 ceremony start: %v\n%s", err, out)
	}
	for _, want := range []string{"KEY_CREATED", "CERT_SIGNED", "MANIFEST_WRITTEN", "ADMIN_ROTATED", "COMPLETE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ceremony output missing %q:\n%s", want, out)
		}
	}

	// Apply the node-b config. The node persists it to the state partition.
	// The generation will be >1 because the ESP-stage seed write and the
	// ceremony config-persist both preceded this call.
	applyOut, err := cryptosctl("config", "apply", "-f", nodeBYAML)
	if err != nil {
		t.Fatalf("boot1 config apply: %v\n%s", err, applyOut)
	}
	if !strings.Contains(applyOut, "requires_reboot=true") {
		t.Fatalf("config apply: expected requires_reboot=true:\n%s", applyOut)
	}
	t.Logf("boot1 config apply output: %s", applyOut)

	// Shut down boot 1: wait for the ext4 journal commit interval (default 5s)
	// so all writes to the state partition are durable before we kill the VM.
	// The seed file and the config file are each written with fsync+rename
	// (durable on their own), but etcd's journal commits still need the ext4
	// commit interval to flush; add headroom for TCG where the writeback timer
	// fires less reliably under emulated CPU load.
	time.Sleep(15 * time.Second)
	_ = boot1.Process.Kill()
	_, _ = boot1.Process.Wait()
	// Allow the OS to release port 4443.
	time.Sleep(2 * time.Second)

	// ---- Boot 2 ----
	// Same installed disk, same swtpm state, same OVMF vars. No reformat.
	// The ESP stage was deleted on boot 1; the node reads from the state partition.
	t.Log("boot 2: verify persisted config loaded")
	boot2 := launchQEMU(t, e, uki, sock, installedDisk, vars, esp, filepath.Join(dir, "qemu-boot2.log"))
	t.Cleanup(func() { _ = boot2.Process.Kill() })

	waitForTLS(t, endpoint, 60*time.Second)

	// The server cert regenerates on each boot; re-grab the trust anchor.
	trust2 := filepath.Join(dir, "trust2.crt")
	writeFile(t, trust2, fetchServerCert(t, endpoint))

	cryptosctl2 := func(args ...string) (string, error) {
		full := append([]string{
			"--endpoint", endpoint,
			"--identity", adminCert, "--identity-key", adminKey,
			"--trust", trust2, "--server-name", "localhost",
		}, args...)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, e.cryptosctl, full...).CombinedOutput()
		return string(out), err
	}

	statusOut, err := cryptosctl2("status")
	if err != nil {
		t.Fatalf("boot2 status: %v\n%s", err, statusOut)
	}
	t.Logf("boot2 status:\n%s", statusOut)

	// Boot count must be 2 — proves a second full boot on the same state disk.
	if !strings.Contains(statusOut, "Boot count:      2") {
		t.Errorf("boot2: expected BootCount=2:\n%s", statusOut)
	}
	// Identity must be ESTABLISHED — proves no re-ceremony ran.
	if !strings.Contains(statusOut, "ESTABLISHED") {
		t.Errorf("boot2: expected ESTABLISHED identity:\n%s", statusOut)
	}

	// The serial log must show first_boot=false, proving the config was read
	// from the state partition rather than re-seeded from the ESP stage.
	boot2Log, err := os.ReadFile(filepath.Join(dir, "qemu-boot2.log"))
	if err != nil {
		t.Fatalf("read boot2 serial log: %v", err)
	}
	if !strings.Contains(string(boot2Log), "first_boot=false") {
		t.Errorf("boot2 serial log does not contain first_boot=false (config not read from state):\n%s",
			lastLines(string(boot2Log), 50))
	}
	t.Logf("boot2 serial log excerpt:\n%s", lastLines(string(boot2Log), 30))
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

// TestFirstBootFromESPStage exercises the ESP-stage seeding path end to end.
//
// # Fallback rationale (Refs #115)
//
// The full ISO → maintenance-mode apply-config install → reboot → disk-boot
// cycle is infeasible in this harness because the box has no /dev/kvm. Pure TCG
// emulation takes 10–15 minutes per boot; two full boots plus a disk install
// step (sgdisk + mkfs.vfat inside the VM under TCG) would exceed any
// reasonable CI timeout and mask real failures under timing noise. The
// maintenance-install path itself is covered by component/unit tests in
// internal/install (install sequence, staging, validation) and
// internal/init (maintenanceInstaller: success, error, nil config,
// locateUKI error). Those component tests together prove the apply-config RPC
// → install.Install → StageConfig → reboot signal chain.
//
// This test covers the complementary half: given an already-installed disk
// (GPT: EFI + cryptos-state partitions, machine.yaml pre-staged on the ESP at
// EFI/cryptos/machine.yaml), a first boot correctly seeds the machine config
// from the stage, persists it to the state partition, removes the stage file,
// and proceeds to run the ceremony. This is the observable post-install
// invariant that operators and CI use to confirm a successful install.
//
// The pre-installed disk is built on the host using sgdisk + mtools (no root
// needed): sgdisk lays the GPT, mformat formats the FAT partition at its
// sector offset, and mcopy writes the staged machine.yaml. QEMU attaches the
// image as a virtio-blk drive so the kernel sees the GPT partition names via
// sysfs (CONFIG_EFI_PARTITION), matching exactly what a real installed disk
// presents.
func TestFirstBootFromESPStage(t *testing.T) {
	e := loadEnv(t)
	// mtools are needed to write files into the FAT partition of the raw disk
	// image without root. Check once; skip rather than fail if absent.
	for _, tool := range []string{"mformat", "mmd", "mcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("mtools not available (%s missing); skipping ESP-stage integration test", tool)
		}
	}

	root := repoRoot(t)
	dir := t.TempDir()

	adminCertPEM, adminKeyPEM, _ := generateBootstrapAdmin(t)
	adminCert := filepath.Join(dir, "bootstrap.crt")
	adminKey := filepath.Join(dir, "bootstrap.key")
	writeFile(t, adminCert, adminCertPEM)
	writeFile(t, adminKey, adminKeyPEM)

	machineYAML := filepath.Join(dir, "machine.yaml")
	writeFile(t, machineYAML, []byte(renderMachineYAML(string(adminCertPEM))))

	// Build the config-free UKI once (kernel assumed prebuilt). The image
	// carries no machine config; the node seeds exclusively from the ESP stage.
	uki := buildDebugUKI(t, root, e.cryptsetupStatic)

	// Create a pre-installed disk: GPT with EFI (FAT32, staged machine.yaml)
	// + cryptos-state (blank, for first-boot LUKS format). This mimics exactly
	// what the maintenance installer produces after apply-config.
	installedDisk := makeInstalledDisk(t, dir, machineYAML)

	vars := filepath.Join(dir, "OVMF_VARS.fd")
	copyFile(t, e.ovmfVars, vars)
	esp := filepath.Join(dir, "esp")
	if err := os.MkdirAll(filepath.Join(esp, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatalf("create esp: %v", err)
	}
	copyFile(t, uki, filepath.Join(esp, "EFI", "BOOT", "BOOTX64.EFI"))

	sock := startSwtpm(t, e, dir)

	const endpoint = "127.0.0.1:4443"
	cmd := launchQEMU(t, e, uki, sock, installedDisk, vars, esp, filepath.Join(dir, "qemu.log"))
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	// TCG is slow; allow extra time for the first boot (LUKS format + ext4
	// format + ESP-stage read all happen before the mTLS listener comes up).
	waitForTLS(t, endpoint, 60*time.Second)

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

	// The ceremony succeeding is exclusive proof that the config was seeded from
	// the ESP stage: the image carries no baked config, so the only way the node
	// can have an admin cert to authenticate against is from the staged
	// machine.yaml. A wrong or missing stage would cause ceremony rejection.
	out, err := cryptosctl("ceremony", "start", "--config", machineYAML)
	if err != nil {
		t.Fatalf("ceremony start: %v\n%s", err, out)
	}
	for _, want := range []string{"KEY_CREATED", "CERT_SIGNED", "MANIFEST_WRITTEN", "ADMIN_ROTATED", "COMPLETE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ceremony output missing %q:\n%s", want, out)
		}
	}

	// The serial log must show first_boot=true (this is the first boot of the
	// installed disk) and must NOT show "maintenance" (the cryptos-state
	// partition is present, so the node must have booted normally).
	serialLog, err := os.ReadFile(filepath.Join(dir, "qemu.log"))
	if err != nil {
		t.Fatalf("read serial log: %v", err)
	}
	if strings.Contains(string(serialLog), "MAINTENANCE mode") {
		t.Errorf("node entered maintenance mode — cryptos-state partition not found (check disk image):\n%s",
			lastLines(string(serialLog), 30))
	}
	if !strings.Contains(string(serialLog), "first_boot=true") {
		t.Errorf("serial log does not contain first_boot=true (first LUKS boot expected):\n%s",
			lastLines(string(serialLog), 30))
	}
	// The branded boot must render on the serial console: the shield wordmark and
	// the per-step [ok] status lines from the console renderer (internal/console).
	for _, want := range []string{"CryptOS", "[ok]  state volume", "[ok]  management API"} {
		if !strings.Contains(string(serialLog), want) {
			t.Errorf("serial missing branded boot marker %q:\n%s", want, lastLines(string(serialLog), 30))
		}
	}
	t.Logf("serial log excerpt:\n%s", lastLines(string(serialLog), 30))

	// The cryptos-console dashboard is spawned by PID 1 after the listeners are
	// up, so it appears on the serial console a beat after the ceremony. Poll the
	// serial capture with a short grace window for the dashboard frame. Its
	// markers are distinct from the M1 boot [ok] lines: the "^R  reset" footer
	// and the framed Root CN only ever come from RenderDashboard.
	dashboardMarkers := []string{"^R  reset (destroys this CA)", "CryptOS Integration Root"}
	deadline := time.Now().Add(30 * time.Second)
	var lastDash string
	for {
		dash, err := os.ReadFile(filepath.Join(dir, "qemu.log"))
		if err != nil {
			t.Fatalf("read serial log for dashboard: %v", err)
		}
		lastDash = string(dash)
		rendered := true
		for _, want := range dashboardMarkers {
			if !strings.Contains(lastDash, want) {
				rendered = false
				break
			}
		}
		if rendered {
			break
		}
		if time.Now().After(deadline) {
			for _, want := range dashboardMarkers {
				if !strings.Contains(lastDash, want) {
					t.Errorf("serial missing dashboard marker %q within grace window:\n%s",
						want, lastLines(lastDash, 40))
				}
			}
			break
		}
		time.Sleep(time.Second)
	}
	t.Logf("dashboard serial excerpt:\n%s", lastLines(lastDash, 20))

	// After a successful ceremony the stage file should have been deleted from
	// the ESP. Verify with mtools: attempt to copy the stage file out; if mcopy
	// succeeds (exit 0) the file was not deleted and the test fails. If mcopy
	// exits non-zero but the output does not indicate "file not found", something
	// unexpected went wrong with the disk image and the test also fails.
	espOffset := espPartitionOffset(t, installedDisk)
	stageSrc := "::/EFI/cryptos/machine.yaml"
	stageDst := filepath.Join(dir, "stage-check.yaml")
	checkOut, mcopyErr := exec.Command("mcopy", "-i",
		installedDisk+"@@"+espOffset, stageSrc, stageDst,
	).CombinedOutput()
	if _, statErr := os.Stat(stageDst); statErr == nil {
		// mcopy succeeded and wrote the file: the stage was NOT deleted.
		t.Errorf("ESP stage file was not deleted after first-boot seeding (machine.yaml still present):\n%s", checkOut)
	} else if mcopyErr == nil {
		// mcopy reported success but the file is absent — should be impossible.
		t.Errorf("mcopy reported success but stage-check.yaml is absent (unexpected):\n%s", checkOut)
	} else {
		// mcopy failed (expected: source file absent from ESP). Confirm the output
		// looks like a "not found" failure rather than a disk or argument error;
		// any other mcopy error would leave a confusing silent pass.
		outStr := strings.ToLower(string(checkOut))
		if !strings.Contains(outStr, "not found") && !strings.Contains(outStr, "no such file") &&
			!strings.Contains(outStr, "cannot open") {
			t.Errorf("mcopy failed with unexpected error (not a 'file absent' result — check disk image):\n%s", checkOut)
		}
		// File absent from ESP: deletion confirmed.
	}
}

// makeInstalledDisk creates a raw disk image that mimics what the maintenance
// installer produces: a 2 GiB GPT disk with two partitions:
//   - partition 1: "EFI" (FAT32, 512 MiB) — machine.yaml pre-staged at
//     EFI/cryptos/machine.yaml so the node reads it on first boot.
//   - partition 2: "cryptos-state" (unformatted, rest of disk) — the node
//     LUKS-formats this on first boot.
//
// Uses sgdisk (no root) for GPT layout and mtools (no root) for FAT
// manipulation at the raw byte offset of partition 1.
func makeInstalledDisk(t *testing.T, dir, machineYAML string) string {
	t.Helper()
	disk := filepath.Join(dir, "installed.img")

	// Create the raw image.
	if err := exec.Command("truncate", "-s", "2G", disk).Run(); err != nil {
		t.Fatalf("create installed disk: %v", err)
	}

	// Lay the GPT: EFI (512 MiB) + cryptos-state (rest).
	if out, err := exec.Command("sgdisk",
		"--new=1:0:+512MiB",
		"--typecode=1:C12A7328-F81F-11D2-BA4B-00A0C93EC93B", // EFI System Partition
		"--change-name=1:EFI",
		"--new=2:0:0",
		"--typecode=2:CA7D7CCB-63ED-4C53-861C-1742536059CC", // Linux LUKS
		"--change-name=2:cryptos-state",
		disk,
	).CombinedOutput(); err != nil {
		t.Fatalf("partition installed disk: %v\n%s", err, out)
	}

	// Compute the byte offset of partition 1.
	offsetStr := espPartitionOffset(t, disk)
	offsetArg := disk + "@@" + offsetStr

	// Format the EFI partition as FAT32 using mformat (no mount/root needed).
	if out, err := exec.Command("mformat", "-F", "-v", "EFI", "-i", offsetArg, "::").CombinedOutput(); err != nil {
		t.Fatalf("mformat EFI partition: %v\n%s", err, out)
	}

	// Create the EFI/cryptos directory tree.
	for _, dir := range []string{"::/EFI", "::/EFI/cryptos"} {
		if out, err := exec.Command("mmd", "-i", offsetArg, dir).CombinedOutput(); err != nil {
			t.Fatalf("mmd %s: %v\n%s", dir, err, out)
		}
	}

	// Stage the machine config at EFI/cryptos/machine.yaml.
	if out, err := exec.Command("mcopy", "-i", offsetArg,
		machineYAML, "::/EFI/cryptos/machine.yaml").CombinedOutput(); err != nil {
		t.Fatalf("mcopy machine.yaml to ESP: %v\n%s", err, out)
	}

	return disk
}

// espPartitionOffset returns the byte offset of partition 1 in the raw disk
// image as a decimal string, suitable for the mtools "file@@offset" syntax.
func espPartitionOffset(t *testing.T, disk string) string {
	t.Helper()
	out, err := exec.Command("sgdisk", "--info=1", disk).CombinedOutput()
	if err != nil {
		t.Fatalf("sgdisk --info=1: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		// "First sector: 2048 (at 1024.0 KiB)"
		if strings.HasPrefix(line, "First sector:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				sector := fields[2]
				// Convert to byte offset (512 bytes/sector).
				var sectorNum int64
				if _, err := fmt.Sscanf(sector, "%d", &sectorNum); err != nil {
					t.Fatalf("parse first sector from %q: %v", line, err)
				}
				return fmt.Sprintf("%d", sectorNum*512)
			}
		}
	}
	t.Fatalf("could not find first sector in sgdisk output:\n%s", out)
	return ""
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

// launchQEMUNoTPM boots the UKI with no TPM device and a fixed SMBIOS UUID (so
// the nodeID key is stable across boots). Mirrors launchQEMU otherwise.
func launchQEMUNoTPM(t *testing.T, e env, uki, statedisk, vars, esp, logPath, uuid string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(e.qemu,
		"-machine", "q35,accel=kvm:tcg", "-m", "2048", "-nographic",
		"-uuid", uuid,
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file="+e.ovmfCode,
		"-drive", "if=pflash,format=raw,unit=1,file="+vars,
		"-drive", "format=raw,file=fat:rw:"+esp,
		"-drive", "if=none,id=state,format=raw,file="+statedisk,
		"-device", "virtio-blk-pci,drive=state",
		"-netdev", "user,id=n0,net=10.0.0.0/24,host=10.0.0.1,hostfwd=tcp:127.0.0.1:4443-10.0.0.10:443",
		"-device", "virtio-net-pci,netdev=n0",
	)
	logf, _ := os.Create(logPath)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start qemu (no tpm): %v", err)
	}
	return cmd
}

func buildNodeIDUKI(t *testing.T, root, cryptsetupStatic string) string {
	t.Helper()
	run := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CRYPTSETUP_STATIC="+cryptsetupStatic, "STATEKEY=nodeid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("task", "kernel:build")
	run("task", "rootfs:build")
	run("task", "uki:assemble", "PROFILE=qemu-dev")
	uki := filepath.Join(root, "build", "out", "cryptos-amd64.uki.unsigned")
	if _, err := os.Stat(uki); err != nil {
		t.Fatalf("nodeid UKI not produced: %v", err)
	}
	return uki
}

func TestNodeIDNoTPMBootAndCeremony(t *testing.T) {
	e := loadEnv(t)
	for _, tool := range []string{"mformat", "mmd", "mcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("mtools not available (%s missing)", tool)
		}
	}
	root := repoRoot(t)
	dir := t.TempDir()
	const nodeUUID = "564d1234-0000-0000-0000-abcdef012345"

	adminCertPEM, adminKeyPEM, _ := generateBootstrapAdmin(t)
	adminCert := filepath.Join(dir, "bootstrap.crt")
	adminKey := filepath.Join(dir, "bootstrap.key")
	writeFile(t, adminCert, adminCertPEM)
	writeFile(t, adminKey, adminKeyPEM)
	machineYAML := filepath.Join(dir, "machine.yaml")
	writeFile(t, machineYAML, []byte(renderMachineYAML(string(adminCertPEM))))

	uki := buildNodeIDUKI(t, root, e.cryptsetupStatic)
	installedDisk := makeInstalledDisk(t, dir, machineYAML)
	vars := filepath.Join(dir, "OVMF_VARS.fd")
	copyFile(t, e.ovmfVars, vars)
	esp := filepath.Join(dir, "esp")
	if err := os.MkdirAll(filepath.Join(esp, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatalf("create esp: %v", err)
	}
	copyFile(t, uki, filepath.Join(esp, "EFI", "BOOT", "BOOTX64.EFI"))

	const endpoint = "127.0.0.1:4443"
	boot1 := launchQEMUNoTPM(t, e, uki, installedDisk, vars, esp, filepath.Join(dir, "qemu-boot1.log"), nodeUUID)
	t.Cleanup(func() { _ = boot1.Process.Kill() })
	waitForTLS(t, endpoint, 90*time.Second)

	trust := filepath.Join(dir, "trust.crt")
	writeFile(t, trust, fetchServerCert(t, endpoint))
	ctl := func(args ...string) (string, error) {
		full := append([]string{"--endpoint", endpoint, "--identity", adminCert,
			"--identity-key", adminKey, "--trust", trust, "--server-name", "localhost"}, args...)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, e.cryptosctl, full...).CombinedOutput()
		return string(out), err
	}

	out, err := ctl("ceremony", "start", "--config", machineYAML)
	if err != nil {
		t.Fatalf("ceremony start: %v\n%s", err, out)
	}
	for _, want := range []string{"KEY_CREATED", "CERT_SIGNED", "MANIFEST_WRITTEN", "ADMIN_ROTATED", "COMPLETE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ceremony missing %q:\n%s", want, out)
		}
	}
	pemOut, err := ctl("identity", "show", "-o", "pem")
	if err != nil {
		t.Fatalf("identity show: %v\n%s", err, pemOut)
	}
	rootPEM := filepath.Join(dir, "root.pem")
	writeFile(t, rootPEM, []byte(pemOut))
	assertZlintClean(t, e.zlint, rootPEM) // software-signed Root is RFC 5280-clean

	statusOut, err := ctl("status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, statusOut)
	}
	if !strings.Contains(statusOut, "ESTABLISHED") {
		t.Fatalf("status not ESTABLISHED:\n%s", statusOut)
	}
	if !strings.Contains(statusOut, "UNAVAILABLE") {
		t.Errorf("nodeID node should report TPM UNAVAILABLE:\n%s", statusOut)
	}

	time.Sleep(15 * time.Second)
	_ = boot1.Process.Kill()
	_, _ = boot1.Process.Wait()
	time.Sleep(2 * time.Second)

	// Boot 2: same disk + same UUID -> same derived key reopens the state.
	boot2 := launchQEMUNoTPM(t, e, uki, installedDisk, vars, esp, filepath.Join(dir, "qemu-boot2.log"), nodeUUID)
	t.Cleanup(func() { _ = boot2.Process.Kill() })
	waitForTLS(t, endpoint, 90*time.Second)
	trust2 := filepath.Join(dir, "trust2.crt")
	writeFile(t, trust2, fetchServerCert(t, endpoint))
	ctl2 := func(args ...string) (string, error) {
		full := append([]string{"--endpoint", endpoint, "--identity", adminCert,
			"--identity-key", adminKey, "--trust", trust2, "--server-name", "localhost"}, args...)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, e.cryptosctl, full...).CombinedOutput()
		return string(out), err
	}
	statusOut2, err := ctl2("status")
	if err != nil {
		t.Fatalf("boot2 status: %v\n%s", err, statusOut2)
	}
	if !strings.Contains(statusOut2, "ESTABLISHED") || !strings.Contains(statusOut2, "Boot count:      2") {
		t.Errorf("boot2 did not reopen state (want ESTABLISHED + Boot count 2):\n%s", statusOut2)
	}
}

// serialLog is a concurrency-safe capture of the guest serial console. QEMU's
// serial output and the test's keystroke writer run on separate goroutines, so
// reads and writes are mutex-guarded. It doubles as the log file writer.
type serialLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
	f   *os.File
}

func (s *serialLog) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		_, _ = s.f.Write(p)
	}
	return s.buf.Write(p)
}

func (s *serialLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// contains reports whether the captured serial output contains sub.
func (s *serialLog) contains(sub string) bool {
	return strings.Contains(s.String(), sub)
}

// launchQEMUSerial boots the UKI exactly like launchQEMU (same TPM, disk, net,
// and host-forward), but routes the guest serial console to an in-process
// bidirectional pipe rather than a plain log file. The console (PID 1's
// supervised cryptos-console) reads /dev/console for keystrokes and writes its
// frames there, so the returned keys writer drives the reset ceremony (Ctrl-R,
// the typed CN, Enter) and the returned *serialLog captures every frame for
// assertions. The monitor is disabled (-serial stdio -monitor none) so the
// serial byte stream is not multiplexed with the QEMU monitor.
func launchQEMUSerial(t *testing.T, e env, uki, swtpmSock, statedisk, vars, esp, logPath string) (*exec.Cmd, io.WriteCloser, *serialLog) {
	t.Helper()
	logf, _ := os.Create(logPath)
	log := &serialLog{f: logf}

	keysR, keysW := io.Pipe()

	cmd := exec.Command(e.qemu,
		"-machine", "q35,accel=kvm:tcg", "-m", "2048",
		"-display", "none", "-monitor", "none", "-serial", "stdio",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file="+e.ovmfCode,
		"-drive", "if=pflash,format=raw,unit=1,file="+vars,
		"-chardev", "socket,id=chrtpm,path="+swtpmSock,
		"-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
		"-device", "tpm-tis,tpmdev=tpm0",
		"-drive", "format=raw,file=fat:rw:"+esp,
		"-drive", "if=none,id=state,format=raw,file="+statedisk,
		"-device", "virtio-blk-pci,drive=state",
		"-netdev", "user,id=n0,net=10.0.0.0/24,host=10.0.0.1,hostfwd=tcp:127.0.0.1:4443-10.0.0.10:443",
		"-device", "virtio-net-pci,netdev=n0",
	)
	cmd.Stdin = keysR
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatalf("start qemu (serial): %v", err)
	}
	return cmd, keysW, log
}

// resetOverMTLS dials the node's mTLS listener with the admin identity and
// invokes the raw Reset RPC (cryptosctl has no reset subcommand: reset is a
// local-socket-only operation, so it is exercised here directly). It returns the
// gRPC status of the call.
func resetOverMTLS(t *testing.T, endpoint, adminCert, adminKey, trust, confirmCN string) error {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(adminCert, adminKey)
	if err != nil {
		t.Fatalf("load admin identity: %v", err)
	}
	trustPEM, err := os.ReadFile(trust)
	if err != nil {
		t.Fatalf("read trust: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustPEM) {
		t.Fatalf("trust %s has no PEM certs", trust)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   "localhost",
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatalf("dial mTLS %s: %v", endpoint, err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = cryptosv1.NewNodeServiceClient(conn).Reset(ctx, &cryptosv1.ResetRequest{ConfirmCommonName: confirmCN})
	return err
}

// TestResetWipesAndReprovisions is the console-reset end-to-end acceptance.
//
// # Host requirement (no /dev/kvm here)
//
// This test performs three full guest boots. Under pure TCG (no /dev/kvm) each
// boot takes 10-15 minutes, so it is NOT part of the routine CI run on the
// build box; run it host-side on a machine with KVM: `task test:integration`
// (or `go test -tags=integration -run ResetWipesAndReprovisions ./test/...`)
// with QEMU + swtpm + OVMF + mtools present. It compile-checks everywhere via
// `go vet -tags=integration ./test/...`.
//
// The flow proves the whole M3 reset lifecycle:
//
//   - Boot 1: seed config from the ESP stage, run the ceremony -> ESTABLISHED.
//     Assert Reset over the mTLS listener returns Unimplemented (the RPC is
//     local-socket-only). Then drive the on-box console over the serial line:
//     Ctrl-R arms the ceremony, retype the exact Root CN, Enter confirms. The
//     console calls the local-socket Reset, which erases the state-key material,
//     clears the ESP stage, and reboots.
//   - Boot 2: the cryptos-state partition still exists but is blank, so Boot
//     lands in REPROVISION maintenance (not the bare-disk ISO installer).
//     Assert the serial log shows REPROVISION mode, then apply a config over the
//     client-auth-off maintenance listener; the reprovisioner persists it and
//     reboots.
//   - Boot 3: the config is now on the state partition (no ESP stage), so the
//     node boots normally and a fresh ceremony re-establishes identity.
func TestResetWipesAndReprovisions(t *testing.T) {
	e := loadEnv(t)
	for _, tool := range []string{"mformat", "mmd", "mcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("mtools not available (%s missing); skipping reset end-to-end test", tool)
		}
	}
	root := repoRoot(t)
	dir := t.TempDir()

	adminCertPEM, adminKeyPEM, _ := generateBootstrapAdmin(t)
	adminCert := filepath.Join(dir, "bootstrap.crt")
	adminKey := filepath.Join(dir, "bootstrap.key")
	writeFile(t, adminCert, adminCertPEM)
	writeFile(t, adminKey, adminKeyPEM)

	machineYAML := filepath.Join(dir, "machine.yaml")
	writeFile(t, machineYAML, []byte(renderMachineYAML(string(adminCertPEM))))

	// The console reports the Root CA's leaf CN; the reset confirm must retype it
	// exactly. renderMachineYAML pins root_subject.common_name to this value.
	const rootCN = "CryptOS Integration Root"

	uki := buildDebugUKI(t, root, e.cryptsetupStatic)

	vars := filepath.Join(dir, "OVMF_VARS.fd")
	copyFile(t, e.ovmfVars, vars)
	esp := filepath.Join(dir, "esp")
	if err := os.MkdirAll(filepath.Join(esp, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatalf("create esp: %v", err)
	}
	copyFile(t, uki, filepath.Join(esp, "EFI", "BOOT", "BOOTX64.EFI"))

	installedDisk := makeInstalledDisk(t, dir, machineYAML)
	sock := startSwtpm(t, e, dir)

	const endpoint = "127.0.0.1:4443"

	// ---- Boot 1: seed + ceremony + mTLS-refuses-Reset + console reset ----
	t.Log("boot 1: seed + ceremony, then console reset")
	boot1, keys, serial1 := launchQEMUSerial(t, e, uki, sock, installedDisk, vars, esp, filepath.Join(dir, "qemu-boot1.log"))
	t.Cleanup(func() { _ = boot1.Process.Kill() })

	waitForTLS(t, endpoint, 60*time.Second)

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

	out, err := cryptosctl("ceremony", "start", "--config", machineYAML)
	if err != nil {
		t.Fatalf("boot1 ceremony start: %v\n%s", err, out)
	}
	for _, want := range []string{"KEY_CREATED", "CERT_SIGNED", "MANIFEST_WRITTEN", "ADMIN_ROTATED", "COMPLETE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ceremony output missing %q:\n%s", want, out)
		}
	}

	// Reset over the mTLS listener must be refused: the RPC is wired only on the
	// local console socket (Resetter nil elsewhere -> Unimplemented).
	err = resetOverMTLS(t, endpoint, adminCert, adminKey, trust, rootCN)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Reset over mTLS: got %v, want Unimplemented", err)
	}

	// Wait for the dashboard to render on the serial console (PID 1 spawns the
	// console after the listeners are up) so Ctrl-R arms from a serving frame.
	waitForSerial(t, serial1, "^R  reset (destroys this CA)", 30*time.Second)

	// Drive the console reset ceremony over the serial line: Ctrl-R, retype the
	// Root CN, Enter. The console calls the local-socket Reset, which erases the
	// state-key material, clears the ESP stage, and reboots the node.
	if _, err := keys.Write([]byte{0x12}); err != nil { // Ctrl-R
		t.Fatalf("write Ctrl-R: %v", err)
	}
	waitForSerial(t, serial1, "Type the Root CA CN to confirm", 15*time.Second)
	if _, err := keys.Write([]byte(rootCN + "\r")); err != nil {
		t.Fatalf("write CN + Enter: %v", err)
	}

	// The successful Reset renders the "resetting" screen, then the node reboots.
	waitForSerial(t, serial1, "RESET IN PROGRESS", 20*time.Second)

	// The node reboots itself after the wipe; give it a moment, then reclaim the
	// host port and the serial pipe for boot 2.
	time.Sleep(15 * time.Second)
	_ = keys.Close()
	_ = boot1.Process.Kill()
	_, _ = boot1.Process.Wait()
	time.Sleep(2 * time.Second)

	// ---- Boot 2: REPROVISION maintenance + apply config ----
	t.Log("boot 2: re-provision maintenance")
	boot2, keys2, serial2 := launchQEMUSerial(t, e, uki, sock, installedDisk, vars, esp, filepath.Join(dir, "qemu-boot2.log"))
	t.Cleanup(func() {
		_ = keys2.Close()
		_ = boot2.Process.Kill()
	})

	waitForTLS(t, endpoint, 60*time.Second)

	// The state partition still exists but is blank after the wipe, so Boot lands
	// in REPROVISION maintenance rather than the bare-disk ISO installer.
	waitForSerial(t, serial2, "REPROVISION mode", 30*time.Second)

	// The re-provision listener has client auth OFF (Talos --insecure), so apply
	// the config without a client identity. It persists the config to the mounted
	// state and reboots into the ceremony.
	applyOut, err := func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		o, e2 := exec.CommandContext(ctx, e.cryptosctl,
			"--endpoint", endpoint, "--insecure", "--server-name", "localhost",
			"config", "apply", "-f", machineYAML,
		).CombinedOutput()
		return string(o), e2
	}()
	if err != nil {
		t.Fatalf("boot2 reprovision config apply: %v\n%s", err, applyOut)
	}
	if !strings.Contains(applyOut, "requires_reboot=true") {
		t.Fatalf("reprovision apply: expected requires_reboot=true:\n%s", applyOut)
	}
	waitForSerial(t, serial2, "re-provision complete; rebooting", 20*time.Second)

	time.Sleep(15 * time.Second)
	_ = keys2.Close()
	_ = boot2.Process.Kill()
	_, _ = boot2.Process.Wait()
	time.Sleep(2 * time.Second)

	// ---- Boot 3: fresh ceremony re-establishes identity ----
	t.Log("boot 3: re-establish identity")
	boot3, keys3, _ := launchQEMUSerial(t, e, uki, sock, installedDisk, vars, esp, filepath.Join(dir, "qemu-boot3.log"))
	t.Cleanup(func() {
		_ = keys3.Close()
		_ = boot3.Process.Kill()
	})

	waitForTLS(t, endpoint, 60*time.Second)
	trust3 := filepath.Join(dir, "trust3.crt")
	writeFile(t, trust3, fetchServerCert(t, endpoint))

	cryptosctl3 := func(args ...string) (string, error) {
		full := append([]string{
			"--endpoint", endpoint,
			"--identity", adminCert, "--identity-key", adminKey,
			"--trust", trust3, "--server-name", "localhost",
		}, args...)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		o, e2 := exec.CommandContext(ctx, e.cryptosctl, full...).CombinedOutput()
		return string(o), e2
	}

	out, err = cryptosctl3("ceremony", "start", "--config", machineYAML)
	if err != nil {
		t.Fatalf("boot3 ceremony start: %v\n%s", err, out)
	}
	for _, want := range []string{"KEY_CREATED", "CERT_SIGNED", "MANIFEST_WRITTEN", "ADMIN_ROTATED", "COMPLETE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("boot3 ceremony output missing %q:\n%s", want, out)
		}
	}
	statusOut, err := cryptosctl3("status")
	if err != nil {
		t.Fatalf("boot3 status: %v\n%s", err, statusOut)
	}
	if !strings.Contains(statusOut, "ESTABLISHED") {
		t.Fatalf("boot3 status not ESTABLISHED after re-provision:\n%s", statusOut)
	}
}

// waitForSerial polls the captured serial output until it contains sub or the
// timeout elapses. TCG boots are slow, so callers size generous windows.
func waitForSerial(t *testing.T, log *serialLog, sub string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if log.contains(sub) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("serial did not show %q within %s:\n%s", sub, timeout, lastLines(log.String(), 40))
}
