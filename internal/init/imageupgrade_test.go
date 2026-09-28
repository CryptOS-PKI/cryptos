package init

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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/imageupgrade"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

const testCACN = "Example Root CA G1"

// releaseKey is a stand-in for the operator's Secure Boot release key.
type releaseKey struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newReleaseKey(t *testing.T) releaseKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		NotAfter:     time.Now().Add(time.Hour),
		NotBefore:    time.Now().Add(-time.Hour),
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "CryptOS Release Signing"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	return releaseKey{cert: cert, key: key}
}

func (r releaseKey) sign(t *testing.T, image []byte) []byte {
	t.Helper()

	sum := sha256.Sum256(image)
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}

	return sig
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// espDir is a directory standing in for a mounted ESP. It records how each
// mount asked for, so a test can assert the node never mounted the real
// ESP read-write for an image it was going to refuse.
type espDir struct {
	root      string
	mounts    []bool // one entry per mount; true means read-write
	mountErr  error
	unmounted int
}

func newESPDir(t *testing.T, activeImage []byte) *espDir {
	t.Helper()

	root := t.TempDir()
	if activeImage != nil {
		if err := os.MkdirAll(filepath.Join(root, "EFI", "BOOT"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, imageupgrade.ActiveRelPath), activeImage, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	return &espDir{root: root}
}

func (e *espDir) mount(readWrite bool, fn func(root string) error) error {
	e.mounts = append(e.mounts, readWrite)
	if e.mountErr != nil {
		return e.mountErr
	}
	defer func() { e.unmounted++ }()

	return fn(e.root)
}

func (e *espDir) mountedReadWrite() bool {
	for _, rw := range e.mounts {
		if rw {
			return true
		}
	}

	return false
}

// newTestUpgrader builds an upgrader over a directory ESP, as run.go builds
// one over the real partition.
func newTestUpgrader(t *testing.T, esp *espDir, rel releaseKey, running []byte, reboot func()) *nodeImageUpgrader {
	t.Helper()

	return newTestUpgraderCN(t, esp, rel, running, reboot, func() string { return testCACN })
}

// newTestUpgraderCN is newTestUpgrader with the CA CN lookup supplied, so a
// test can change the node's CA CN after the upgrader is built.
func newTestUpgraderCN(t *testing.T, esp *espDir, rel releaseKey, running []byte, reboot func(), caCN func() string) *nodeImageUpgrader {
	t.Helper()

	u, err := newImageUpgrader(imageUpgradeOptions{
		CACN:    caCN,
		Mount:   esp.mount,
		Reboot:  reboot,
		Release: rel.cert,
		Running: digestOf(running),
		Version: "v1.2.3",
	})
	if err != nil {
		t.Fatalf("newImageUpgrader: %v", err)
	}

	return u
}

// The upgrade #208 is for: a signed image becomes the one the node will boot,
// the state partition is never touched, and the caller is told a reboot is
// still outstanding.
func TestUpgrader_StageInstallsAndReportsARebootPending(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("Stage must not reboot") })

	image := []byte("the new image")
	st, err := u.Stage(context.Background(), image, rel.sign(t, image))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if st.GetActiveSha256() != digestOf(image) {
		t.Errorf("active_sha256 = %q, want the new image", st.GetActiveSha256())
	}
	if st.GetRunningSha256() != digestOf(old) {
		t.Errorf("running_sha256 = %q, want the image the node booted", st.GetRunningSha256())
	}
	if st.GetPreviousSha256() != digestOf(old) {
		t.Errorf("previous_sha256 = %q, want the old image retained", st.GetPreviousSha256())
	}
	if !st.GetRebootPending() {
		t.Error("reboot_pending must be true while running and active differ")
	}
	if st.GetRunningVersion() != "v1.2.3" {
		t.Errorf("running_version = %q", st.GetRunningVersion())
	}
}

// The ESP must not even be mounted writable for an image the node is going to
// refuse. Verifying first keeps a bad upload from touching the boot partition
// of a production CA at all.
func TestUpgrader_StageVerifiesBeforeMountingWritable(t *testing.T) {
	rel := newReleaseKey(t)
	other := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	image := []byte("the new image")
	_, err := u.Stage(context.Background(), image, other.sign(t, image))
	if !errors.Is(err, grpc.ErrImageNotVerified) {
		t.Fatalf("err = %v, want ErrImageNotVerified", err)
	}
	if esp.mountedReadWrite() {
		t.Error("the ESP was mounted read-write for an image that failed verification")
	}
	got, readErr := os.ReadFile(filepath.Join(esp.root, imageupgrade.ActiveRelPath))
	if readErr != nil || string(got) != string(old) {
		t.Errorf("active image = %q (%v), want it untouched", got, readErr)
	}
}

// Rollback restores the retained image and, like staging, leaves the reboot
// to the operator.
func TestUpgrader_RollbackRestoresTheRetainedImage(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("Rollback must not reboot") })

	image := []byte("the bad new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	st, err := u.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if st.GetActiveSha256() != digestOf(old) {
		t.Errorf("active_sha256 = %q, want the retained image restored", st.GetActiveSha256())
	}
}

// A node that has never been upgraded has nothing to roll back to, and that
// reads as a precondition rather than an internal failure.
func TestUpgrader_RollbackWithNothingRetained(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	if _, err := u.Rollback(context.Background()); !errors.Is(err, grpc.ErrNoPreviousImage) {
		t.Fatalf("err = %v, want ErrNoPreviousImage", err)
	}
}

// Rebooting an issuing CA is an outage, so an empty confirmation can never
// authorize one -- the same fail-closed rule the resetter applies.
func TestUpgrader_ActivateFailsClosedOnAnEmptyConfirmation(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	rebooted := false
	u := newTestUpgrader(t, esp, rel, old, func() { rebooted = true })

	if err := u.Activate(context.Background(), ""); !errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("err = %v, want ErrConfirmMismatch", err)
	}
	if rebooted {
		t.Error("the node rebooted on an empty confirmation")
	}
}

func TestUpgrader_ActivateRefusesTheWrongCommonName(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	rebooted := false
	u := newTestUpgrader(t, esp, rel, old, func() { rebooted = true })

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := u.Activate(context.Background(), "Some Other CA"); !errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("err = %v, want ErrConfirmMismatch", err)
	}
	if rebooted {
		t.Error("the node rebooted on a mismatched confirmation")
	}
}

// Rebooting when nothing is staged is an outage with nothing to show for it,
// so it is refused rather than obeyed.
func TestUpgrader_ActivateRefusesWhenNothingIsStaged(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	rebooted := false
	u := newTestUpgrader(t, esp, rel, old, func() { rebooted = true })

	err := u.Activate(context.Background(), testCACN)
	if err == nil || errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("err = %v, want a complaint that nothing is staged", err)
	}
	if rebooted {
		t.Error("the node rebooted with no staged image")
	}
}

func TestUpgrader_ActivateRebootsOnTheRightCommonName(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	rebooted := false
	u := newTestUpgrader(t, esp, rel, old, func() { rebooted = true })

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := u.Activate(context.Background(), testCACN); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !rebooted {
		t.Error("the node did not reboot on a correct confirmation")
	}
}

// On a node that has not been upgraded, running and active are the same image
// and nothing is outstanding.
func TestUpgrader_StatusOnAnUnupgradedNode(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	st, err := u.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.GetRebootPending() {
		t.Error("reboot_pending must be false when running and active are the same image")
	}
	if st.GetPreviousSha256() != "" {
		t.Errorf("previous_sha256 = %q, want empty", st.GetPreviousSha256())
	}
	if esp.mountedReadWrite() {
		t.Error("reading status mounted the ESP read-write")
	}
}

// A build with no release certificate must refuse to construct an upgrader, so
// the RPCs are Unimplemented rather than silently accepting any image.
func TestNewImageUpgrader_RequiresARelease(t *testing.T) {
	esp := newESPDir(t, []byte("image"))
	_, err := newImageUpgrader(imageUpgradeOptions{
		CACN:    func() string { return testCACN },
		Mount:   esp.mount,
		Reboot:  func() {},
		Running: "aa",
	})
	if err == nil {
		t.Error("newImageUpgrader accepted a build with no release certificate")
	}
}

// Every mount is released, including on the failure paths, or the ESP stays
// busy and the next upgrade cannot mount it.
func TestUpgrader_UnmountsEvenWhenStagingFails(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgrader(t, esp, rel, old, func() { t.Fatal("must not reboot") })

	// A directory where the incoming image must go makes the write fail.
	if err := os.MkdirAll(filepath.Join(esp.root, "EFI", "BOOT", "BOOTX64.NEW.EFI"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err == nil {
		t.Fatal("Stage reported success despite an unwritable slot")
	}
	if esp.unmounted != len(esp.mounts) {
		t.Errorf("unmounted %d of %d mounts", esp.unmounted, len(esp.mounts))
	}
	got, _ := os.ReadFile(filepath.Join(esp.root, imageupgrade.ActiveRelPath))
	if string(got) != string(old) {
		t.Errorf("active image = %q, want the node still bootable", got)
	}
}

// The CA CN is read per call. A node whose CA certificate is installed after
// its current boot (a subordinate's submit-subordinate-cert, or the ceremony
// boot) had an empty CN at startup, and must still accept the correct CN
// without first needing the reboot it is asking for.
func TestUpgrader_ActivateHonoursACACNInstalledAfterBoot(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	cn := ""
	rebooted := false
	u := newTestUpgraderCN(t, esp, rel, old, func() { rebooted = true }, func() string { return cn })

	image := []byte("the new image")
	if _, err := u.Stage(context.Background(), image, rel.sign(t, image)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := u.Activate(context.Background(), testCACN); !errors.Is(err, reset.ErrNoCAIdentity) {
		t.Fatalf("before the CA certificate is installed: err = %v, want ErrNoCAIdentity", err)
	}
	if rebooted {
		t.Fatal("the node rebooted with no CA identity")
	}

	cn = testCACN
	if err := u.Activate(context.Background(), testCACN); err != nil {
		t.Fatalf("after the CA certificate is installed: %v", err)
	}
	if !rebooted {
		t.Error("the node did not reboot on a correct confirmation")
	}
}

// Rollback is confirmed by the activate that follows it, so the same late CN
// must be honoured there too.
func TestUpgrader_ActivateAfterRollbackHonoursACACNInstalledAfterBoot(t *testing.T) {
	rel := newReleaseKey(t)
	running := []byte("the running image")
	esp := newESPDir(t, running)
	cn := ""
	rebooted := false
	u := newTestUpgraderCN(t, esp, rel, running, func() { rebooted = true }, func() string { return cn })

	// Two stages leave a retained image that differs from the running one, so
	// rolling back leaves a reboot pending.
	for _, img := range [][]byte{[]byte("image one"), []byte("image two")} {
		if _, err := u.Stage(context.Background(), img, rel.sign(t, img)); err != nil {
			t.Fatalf("Stage: %v", err)
		}
	}
	st, err := u.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !st.GetRebootPending() {
		t.Fatal("rollback to a different image must leave a reboot pending")
	}

	cn = testCACN
	if err := u.Activate(context.Background(), testCACN); err != nil {
		t.Fatalf("Activate after rollback: %v", err)
	}
	if !rebooted {
		t.Error("the node did not reboot on a correct confirmation")
	}
}

func TestUpgrader_ActivateWithNoCAIdentity(t *testing.T) {
	rel := newReleaseKey(t)
	old := []byte("the running image")
	esp := newESPDir(t, old)
	u := newTestUpgraderCN(t, esp, rel, old, func() { t.Fatal("must not reboot") }, func() string { return "" })

	for _, confirm := range []string{"", testCACN} {
		if err := u.Activate(context.Background(), confirm); !errors.Is(err, reset.ErrNoCAIdentity) {
			t.Fatalf("confirm %q: err = %v, want ErrNoCAIdentity", confirm, err)
		}
	}
}
