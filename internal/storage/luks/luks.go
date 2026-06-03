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
	"fmt"
	"io"
	"os/exec"
	"regexp"
)

// Runner executes a single cryptsetup invocation. The package shells
// out to a real cryptsetup binary in production; tests inject a mock.
//
// The contract:
//   - args are passed as-is to cryptsetup; the caller is responsible
//     for argument hygiene.
//   - stdin carries the LUKS master key when present (never as an
//     argument, never via environment). The implementation MUST hand
//     stdin to the process's STDIN file descriptor unchanged.
type Runner interface {
	Run(ctx context.Context, stdin io.Reader, args ...string) (stdout, stderr []byte, err error)
}

// ExecRunner is the production Runner: it shells out to a cryptsetup
// binary on PATH. The binary path may be overridden via Binary, which
// PID 1 sets to the static cryptsetup embedded in the SquashFS rootfs.
type ExecRunner struct {
	// Binary is the path to the cryptsetup executable. If empty,
	// "cryptsetup" is looked up on PATH.
	Binary string
}

// Run satisfies Runner.
func (e *ExecRunner) Run(ctx context.Context, stdin io.Reader, args ...string) ([]byte, []byte, error) {
	bin := e.Binary
	if bin == "" {
		bin = "cryptsetup"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// Device represents an unopened LUKS-formatted (or to-be-formatted)
// block device. Operations on a Device drive cryptsetup but do not
// hold the master key beyond a single call.
type Device struct {
	// Path is the underlying block device path (e.g. /dev/nvme0n1p2 or
	// /dev/disk/by-partlabel/cryptos-state). Required.
	Path string

	// Runner executes cryptsetup. Required.
	Runner Runner
}

// Volume is an opened LUKS volume.
type Volume struct {
	// Path is the dm-crypt block device exposed by cryptsetup
	// (e.g. /dev/mapper/cryptos-state).
	Path string

	// Name is the mapped name (suffix of /dev/mapper/<name>).
	Name string

	device *Device
}

// mappedNameRE constrains mapped names to safe characters; cryptsetup
// happily accepts arbitrary strings but anything outside this set is
// almost certainly a bug.
var mappedNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// validateMasterKey checks the master key bytes. LUKS2 with AES-XTS-Plain64
// uses a 64-byte master key by default (two 32-byte halves for XTS).
func validateMasterKey(key []byte) error {
	if len(key) == 0 {
		return errors.New("luks: master key is empty")
	}
	if len(key) < 16 {
		return fmt.Errorf("luks: master key too short: %d bytes (min 16)", len(key))
	}
	return nil
}

// Format runs `cryptsetup luksFormat` with strong Phase 1 defaults:
// LUKS2, AES-XTS-Plain64, SHA-256 PBKDF hash, Argon2id key derivation.
// The master key is passed via stdin (--key-file=-) so it never appears
// in process arguments.
//
// Format does not mount or open the volume; call Open afterwards.
func (d *Device) Format(ctx context.Context, masterKey []byte) error {
	if d == nil || d.Path == "" {
		return errors.New("luks: Format: device path is required")
	}
	if d.Runner == nil {
		return errors.New("luks: Format: Runner is required")
	}
	if err := validateMasterKey(masterKey); err != nil {
		return err
	}

	args := []string{
		"luksFormat",
		"--type", "luks2",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--hash", "sha256",
		"--pbkdf", "argon2id",
		"--batch-mode", // no interactive confirmation prompts
		"--key-file", "-",
		d.Path,
	}
	_, stderr, err := d.Runner.Run(ctx, bytes.NewReader(masterKey), args...)
	if err != nil {
		return fmt.Errorf("luks: Format: cryptsetup failed: %w (stderr: %s)", err, string(bytes.TrimSpace(stderr)))
	}
	return nil
}

// Open runs `cryptsetup luksOpen` with the supplied master key and
// returns a Volume on success. The mapped name must match
// `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`.
func (d *Device) Open(ctx context.Context, masterKey []byte, mappedName string) (*Volume, error) {
	if d == nil || d.Path == "" {
		return nil, errors.New("luks: Open: device path is required")
	}
	if d.Runner == nil {
		return nil, errors.New("luks: Open: Runner is required")
	}
	if !mappedNameRE.MatchString(mappedName) {
		return nil, fmt.Errorf("luks: Open: invalid mapped name %q", mappedName)
	}
	if err := validateMasterKey(masterKey); err != nil {
		return nil, err
	}

	args := []string{
		"luksOpen",
		"--key-file", "-",
		d.Path,
		mappedName,
	}
	_, stderr, err := d.Runner.Run(ctx, bytes.NewReader(masterKey), args...)
	if err != nil {
		return nil, fmt.Errorf("luks: Open: cryptsetup failed: %w (stderr: %s)", err, string(bytes.TrimSpace(stderr)))
	}
	return &Volume{
		Path:   "/dev/mapper/" + mappedName,
		Name:   mappedName,
		device: d,
	}, nil
}

// Close runs `cryptsetup luksClose <name>`. After Close returns, the
// Volume's Path is no longer backed.
func (v *Volume) Close(ctx context.Context) error {
	if v == nil || v.device == nil {
		return errors.New("luks: Close: volume is not open")
	}
	args := []string{"luksClose", v.Name}
	_, stderr, err := v.device.Runner.Run(ctx, nil, args...)
	if err != nil {
		return fmt.Errorf("luks: Close: cryptsetup failed: %w (stderr: %s)", err, string(bytes.TrimSpace(stderr)))
	}
	v.device = nil
	return nil
}
