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
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// mockRunner records each Run invocation and returns canned results.
type mockRunner struct {
	calls  []mockCall
	stdout []byte
	stderr []byte
	runErr error
}

type mockCall struct {
	args  []string
	stdin []byte
}

func (m *mockRunner) Run(_ context.Context, stdin io.Reader, args ...string) ([]byte, []byte, error) {
	call := mockCall{args: append([]string(nil), args...)}
	if stdin != nil {
		buf, _ := io.ReadAll(stdin)
		call.stdin = buf
	}
	m.calls = append(m.calls, call)
	return m.stdout, m.stderr, m.runErr
}

func dummyMasterKey() []byte {
	// 64-byte AES-XTS-Plain64 default. Contents irrelevant; tests only
	// check that the bytes reach cryptsetup unchanged.
	k := make([]byte, 64)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestFormat_BuildsCorrectArguments(t *testing.T) {
	mock := &mockRunner{}
	dev := &Device{Path: "/dev/test", Runner: mock}

	if err := dev.Format(context.Background(), dummyMasterKey()); err != nil {
		t.Fatalf("Format: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mock.calls))
	}
	args := mock.calls[0].args

	// First arg must be luksFormat.
	if args[0] != "luksFormat" {
		t.Fatalf("args[0] = %q, want luksFormat", args[0])
	}
	// Required flags.
	mustContain(t, args, "--type", "luks2")
	mustContain(t, args, "--cipher", "aes-xts-plain64")
	mustContain(t, args, "--key-size", "512")
	mustContain(t, args, "--hash", "sha256")
	mustContain(t, args, "--pbkdf", "argon2id")
	mustContain(t, args, "--key-file", "-")
	if !contains(args, "--batch-mode") {
		t.Fatalf("missing --batch-mode in args: %v", args)
	}
	// Device path is the final argument.
	if args[len(args)-1] != "/dev/test" {
		t.Fatalf("device path not at end: %v", args)
	}
}

func TestFormat_MasterKeyOnStdin_NotInArgs(t *testing.T) {
	mock := &mockRunner{}
	dev := &Device{Path: "/dev/test", Runner: mock}
	key := dummyMasterKey()

	if err := dev.Format(context.Background(), key); err != nil {
		t.Fatalf("Format: %v", err)
	}
	call := mock.calls[0]
	if !bytes.Equal(call.stdin, key) {
		t.Fatalf("stdin master key mismatch")
	}
	// The key bytes must NOT appear in argv.
	joined := strings.Join(call.args, " ")
	if strings.Contains(joined, string(key)) {
		t.Fatalf("master key leaked into argv: %q", joined)
	}
}

func TestFormat_RejectsEmptyMasterKey(t *testing.T) {
	dev := &Device{Path: "/dev/test", Runner: &mockRunner{}}
	if err := dev.Format(context.Background(), nil); err == nil {
		t.Fatalf("Format(nil key) should fail")
	}
	if err := dev.Format(context.Background(), []byte("short")); err == nil {
		t.Fatalf("Format(short key) should fail")
	}
}

func TestFormat_PropagatesRunnerError(t *testing.T) {
	mock := &mockRunner{runErr: errors.New("boom"), stderr: []byte("device locked")}
	dev := &Device{Path: "/dev/test", Runner: mock}
	err := dev.Format(context.Background(), dummyMasterKey())
	if err == nil {
		t.Fatalf("Format should propagate runner error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %q missing underlying cause", err)
	}
	if !strings.Contains(err.Error(), "device locked") {
		t.Fatalf("error %q missing stderr context", err)
	}
}

func TestFormat_RejectsMissingPath(t *testing.T) {
	dev := &Device{Runner: &mockRunner{}}
	if err := dev.Format(context.Background(), dummyMasterKey()); err == nil {
		t.Fatalf("Format without Path should fail")
	}
}

func TestFormat_RejectsMissingRunner(t *testing.T) {
	dev := &Device{Path: "/dev/test"}
	if err := dev.Format(context.Background(), dummyMasterKey()); err == nil {
		t.Fatalf("Format without Runner should fail")
	}
}

func TestOpen_HappyPath(t *testing.T) {
	mock := &mockRunner{}
	dev := &Device{Path: "/dev/test", Runner: mock}
	vol, err := dev.Open(context.Background(), dummyMasterKey(), "cryptos-state")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if vol.Path != "/dev/mapper/cryptos-state" {
		t.Fatalf("vol.Path = %q, want /dev/mapper/cryptos-state", vol.Path)
	}
	if vol.Name != "cryptos-state" {
		t.Fatalf("vol.Name = %q, want cryptos-state", vol.Name)
	}
	args := mock.calls[0].args
	if args[0] != "luksOpen" {
		t.Fatalf("expected luksOpen, got %q", args[0])
	}
	mustContain(t, args, "--key-file", "-")
	if !contains(args, "/dev/test") || !contains(args, "cryptos-state") {
		t.Fatalf("Open args missing device or name: %v", args)
	}
}

func TestOpen_RejectsBadMappedNames(t *testing.T) {
	dev := &Device{Path: "/dev/test", Runner: &mockRunner{}}
	bad := []string{
		"",                      // empty
		"-leading-dash",         // can't start with dash
		"has space",             // space disallowed
		"has/slash",             // slash disallowed
		"has;semicolon",         // shell metachar
		strings.Repeat("x", 64), // too long
	}
	for _, name := range bad {
		if _, err := dev.Open(context.Background(), dummyMasterKey(), name); err == nil {
			t.Fatalf("Open should reject mapped name %q", name)
		}
	}
}

func TestOpen_MasterKeyOnStdin(t *testing.T) {
	mock := &mockRunner{}
	dev := &Device{Path: "/dev/test", Runner: mock}
	key := dummyMasterKey()
	_, err := dev.Open(context.Background(), key, "cryptos-state")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(mock.calls[0].stdin, key) {
		t.Fatalf("stdin master key mismatch")
	}
}

func TestClose_HappyPath(t *testing.T) {
	mock := &mockRunner{}
	dev := &Device{Path: "/dev/test", Runner: mock}
	vol, err := dev.Open(context.Background(), dummyMasterKey(), "cryptos-state")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := vol.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(mock.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(mock.calls))
	}
	closeArgs := mock.calls[1].args
	if closeArgs[0] != "luksClose" || closeArgs[1] != "cryptos-state" {
		t.Fatalf("Close args wrong: %v", closeArgs)
	}
}

func TestClose_PropagatesRunnerError(t *testing.T) {
	dev := &Device{Path: "/dev/test", Runner: &mockRunner{}}
	vol, err := dev.Open(context.Background(), dummyMasterKey(), "cryptos-state")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Swap in an error-returning runner before Close.
	vol.device.Runner = &mockRunner{runErr: errors.New("locked"), stderr: []byte("device busy")}
	if err := vol.Close(context.Background()); err == nil {
		t.Fatalf("Close should propagate runner error")
	}
}

func TestClose_RejectsAlreadyClosed(t *testing.T) {
	dev := &Device{Path: "/dev/test", Runner: &mockRunner{}}
	vol, err := dev.Open(context.Background(), dummyMasterKey(), "cryptos-state")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := vol.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := vol.Close(context.Background()); err == nil {
		t.Fatalf("second Close should fail")
	}
}

// helpers

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func mustContain(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i, a := range args {
		if a == flag {
			if i+1 >= len(args) || args[i+1] != value {
				t.Fatalf("flag %q has wrong value: args=%v", flag, args)
			}
			return
		}
	}
	t.Fatalf("flag %q missing from args=%v", flag, args)
}

// newFakeDevice creates a sparse file of the given size standing in for
// the state block device.
func newFakeDevice(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fake device: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(size); err != nil {
		t.Fatalf("truncate fake device: %v", err)
	}
	return path
}

func writeAt(t *testing.T, path string, off int64, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open fake device: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatalf("write fake device: %v", err)
	}
}

func readAt(t *testing.T, path string, off int64, n int) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fake device: %v", err)
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatalf("read fake device: %v", err)
	}
	return b
}

var luks2Magic = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}

func TestErase_InvokesLuksErase(t *testing.T) {
	mock := &mockRunner{}
	path := newFakeDevice(t, 1<<20)
	dev := &Device{Path: path, Runner: mock}
	if err := dev.Erase(context.Background()); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mock.calls))
	}
	got := mock.calls[0].args
	want := []string{"luksErase", "--batch-mode", path}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Erase args = %v, want %v", got, want)
	}
}

func TestErase_PropagatesRunnerError(t *testing.T) {
	mock := &mockRunner{runErr: errors.New("boom"), stderr: []byte("device busy")}
	dev := &Device{Path: "/dev/x", Runner: mock}
	err := dev.Erase(context.Background())
	if err == nil {
		t.Fatalf("Erase should propagate runner error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %q missing underlying cause", err)
	}
	if !strings.Contains(err.Error(), "device busy") {
		t.Fatalf("error %q missing stderr context", err)
	}
}

// luksErase destroys only the keyslots; the LUKS header (and its
// secondary copy) stays on disk, so IsLUKS keeps reporting true and the
// next boot neither opens nor re-formats the volume. Erase must destroy
// every header copy cryptsetup probes for, without touching the data
// segment that starts at the LUKS2 default 16 MiB offset.
func TestErase_DestroysLUKSHeaders(t *testing.T) {
	path := newFakeDevice(t, 32<<20)
	// Primary header plus the secondary-header offsets cryptsetup scans.
	offsets := []int64{0, 16 << 10, 32 << 10, 64 << 10, 128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20, 4 << 20}
	for _, off := range offsets {
		writeAt(t, path, off, luks2Magic)
	}
	sentinel := []byte("data-segment")
	writeAt(t, path, headerWipeSize, sentinel)

	dev := &Device{Path: path, Runner: &mockRunner{}}
	if err := dev.Erase(context.Background()); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	for _, off := range offsets {
		if got := readAt(t, path, off, len(luks2Magic)); bytes.Equal(got, luks2Magic) {
			t.Errorf("LUKS magic still present at offset %d after Erase", off)
		}
	}
	if got := readAt(t, path, headerWipeSize, len(sentinel)); !bytes.Equal(got, sentinel) {
		t.Errorf("Erase clobbered the data segment: got %q", got)
	}
}

func TestErase_SmallDeviceWipedWithoutError(t *testing.T) {
	path := newFakeDevice(t, 64<<10)
	writeAt(t, path, 0, luks2Magic)
	writeAt(t, path, 16<<10, luks2Magic)
	dev := &Device{Path: path, Runner: &mockRunner{}}
	if err := dev.Erase(context.Background()); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if got := readAt(t, path, 0, 64<<10); !bytes.Equal(got, make([]byte, 64<<10)) {
		t.Error("small device not fully zeroed")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != 64<<10 {
		t.Errorf("Erase grew the device to %d bytes", fi.Size())
	}
}

func TestErase_DoesNotWipeWhenLuksEraseFails(t *testing.T) {
	path := newFakeDevice(t, 1<<20)
	writeAt(t, path, 0, luks2Magic)
	dev := &Device{Path: path, Runner: &mockRunner{runErr: errors.New("boom")}}
	if err := dev.Erase(context.Background()); err == nil {
		t.Fatal("Erase should fail when luksErase fails")
	}
	if got := readAt(t, path, 0, len(luks2Magic)); !bytes.Equal(got, luks2Magic) {
		t.Error("header wiped despite luksErase failure")
	}
}

func TestErase_FailsWhenDeviceCannotBeOpened(t *testing.T) {
	dev := &Device{Path: filepath.Join(t.TempDir(), "missing"), Runner: &mockRunner{}}
	if err := dev.Erase(context.Background()); err == nil {
		t.Fatal("Erase should fail when the header cannot be wiped")
	}
}

// TestErase_RealCryptsetup reproduces the reported brick against a real
// cryptsetup binary: after Erase, isLuks must report false so the next
// boot takes the first-boot format path. Skipped where cryptsetup is
// unavailable.
func TestErase_RealCryptsetup(t *testing.T) {
	bin, err := exec.LookPath("cryptsetup")
	if err != nil {
		t.Skip("cryptsetup not on PATH")
	}
	ctx := context.Background()
	run := &ExecRunner{Binary: bin}
	path := newFakeDevice(t, 32<<20)
	// Cheap PBKDF: the test exercises header handling, not key strength.
	if _, stderr, err := run.Run(ctx, bytes.NewReader(dummyMasterKey()),
		"luksFormat", "--type", "luks2", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
		"--batch-mode", "--key-file", "-", path); err != nil {
		t.Skipf("luksFormat unavailable here: %v (%s)", err, stderr)
	}
	dev := &Device{Path: path, Runner: run}
	if !dev.IsLUKS(ctx) {
		t.Fatal("IsLUKS = false right after luksFormat")
	}
	if err := dev.Erase(ctx); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if dev.IsLUKS(ctx) {
		t.Fatal("IsLUKS = true after Erase; the next boot would not re-provision")
	}
}

func TestErase_RejectsMissingPath(t *testing.T) {
	dev := &Device{Runner: &mockRunner{}}
	if err := dev.Erase(context.Background()); err == nil {
		t.Fatalf("Erase without Path should fail")
	}
}

func TestErase_RejectsMissingRunner(t *testing.T) {
	dev := &Device{Path: "/dev/x"}
	if err := dev.Erase(context.Background()); err == nil {
		t.Fatalf("Erase without Runner should fail")
	}
}

func TestIsLUKS(t *testing.T) {
	// Exit 0 (no error) -> device has a LUKS header.
	yes := &Device{Path: "/dev/state", Runner: &mockRunner{}}
	if !yes.IsLUKS(context.Background()) {
		t.Error("IsLUKS = false on cryptsetup success, want true")
	}
	if got := yes.Runner.(*mockRunner).calls[0].args; got[0] != "isLuks" || got[1] != "/dev/state" {
		t.Errorf("args = %v, want [isLuks /dev/state]", got)
	}
	// Non-zero exit -> not a LUKS device.
	no := &Device{Path: "/dev/state", Runner: &mockRunner{runErr: errors.New("not luks")}}
	if no.IsLUKS(context.Background()) {
		t.Error("IsLUKS = true on cryptsetup failure, want false")
	}
	// Defensive: nil runner / empty path.
	if (&Device{}).IsLUKS(context.Background()) {
		t.Error("IsLUKS on empty device = true, want false")
	}
}
