// Package install provisions a bare-metal disk for CryptOS: it lays out
// the GPT (an EFI System Partition + the cryptos-state partition), writes
// the signed UKI to the ESP's removable-media fallback path, and leaves
// the state partition unformatted for the node's first-boot LUKS format.
//
// Disk-touching steps run external tools (sgdisk, mkfs.vfat, mount) via an
// injectable Runner so the layout and command construction are unit
// testable; the actual writes are validated on real hardware.
package install

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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// Partition type GUIDs.
const (
	// espTypeGUID is the EFI System Partition type (sgdisk shortcode EF00).
	espTypeGUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
	// stateTypeGUID is the "Linux LUKS" partition type — semantically
	// correct for the LUKS2 state partition and recognized by tooling.
	stateTypeGUID = "CA7D7CCB-63ED-4C53-861C-1742536059CC"
)

// Defaults.
const (
	defaultESPLabel    = "EFI"
	defaultStateLabel  = "cryptos-state"
	defaultESPSizeMiB  = 512
	fallbackUKIRelPath = "EFI/BOOT/BOOTX64.EFI" // UEFI removable-media fallback
)

// Runner executes a single external command. Production shells out; tests
// inject a recorder. Combined stdout/stderr is returned for diagnostics.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (output []byte, err error)
}

// Absolute paths for tools baked into the rootfs. PID 1 has no PATH so bare
// command names do not resolve; all disk-touching binaries are invoked by their
// baked-in absolute path (the same reason mkfsExt4 in internal/init uses
// /sbin/mkfs.ext4 directly).
const (
	sgdiskBin    = "/sbin/sgdisk"
	mkfsVfatBin  = "/sbin/mkfs.vfat"
	mountBin     = "/bin/mount"
	umountBin    = "/bin/umount"
	partprobeBin = "/sbin/partprobe"
)

// ExecRunner is the production Runner.
type ExecRunner struct{}

// Run satisfies Runner by shelling out to name. name should be an absolute
// path; bare names are accepted for test harness convenience but fail at
// runtime when PATH is empty (PID 1 context).
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Options configures an install.
type Options struct {
	// Disk is the whole target block device (e.g. /dev/nvme0n1). Required.
	// IT IS WIPED.
	Disk string
	// UKI is the path to the signed UKI to install. Required.
	UKI string
	// ESPLabel / StateLabel are GPT partition names; the node finds the
	// state partition by its label. Default "EFI" / "cryptos-state".
	ESPLabel   string
	StateLabel string
	// ESPSizeMiB is the EFI System Partition size. Default 512.
	ESPSizeMiB int
}

func (o *Options) withDefaults() {
	if o.ESPLabel == "" {
		o.ESPLabel = defaultESPLabel
	}
	if o.StateLabel == "" {
		o.StateLabel = defaultStateLabel
	}
	if o.ESPSizeMiB == 0 {
		o.ESPSizeMiB = defaultESPSizeMiB
	}
}

func (o Options) validate() error {
	switch {
	case o.Disk == "":
		return errors.New("install: Disk is required")
	case o.UKI == "":
		return errors.New("install: UKI is required")
	case o.ESPSizeMiB < 64:
		return fmt.Errorf("install: ESPSizeMiB too small: %d", o.ESPSizeMiB)
	}
	return nil
}

// byPartLabel is the udev symlink for a GPT partition name.
func byPartLabel(label string) string { return "/dev/disk/by-partlabel/" + label }

// sgdiskArgs builds the single sgdisk invocation that wipes the disk and
// creates the ESP (partition 1) and the cryptos-state partition
// (partition 2, rest of disk), with their type GUIDs and names.
func sgdiskArgs(o Options) []string {
	return []string{
		"--zap-all",
		"--new=1:0:+" + strconv.Itoa(o.ESPSizeMiB) + "MiB",
		"--typecode=1:" + espTypeGUID,
		"--change-name=1:" + o.ESPLabel,
		"--new=2:0:0",
		"--typecode=2:" + stateTypeGUID,
		"--change-name=2:" + o.StateLabel,
		o.Disk,
	}
}

// Install partitions Disk, formats the ESP, and writes the UKI to the
// ESP's removable-media fallback path. The state partition is left
// unformatted; the node LUKS-formats and seals it on first boot. UEFI
// boots BOOTX64.EFI without a firmware boot entry, so efibootmgr is not
// required (the operator may add an explicit entry afterwards).
//
// copyFn writes src to dst (injected for testing); mountDir is a scratch
// mount point.
func Install(ctx context.Context, o Options, r Runner, mountDir string, copyFn func(dst, src string) error) error {
	o.withDefaults()
	if err := o.validate(); err != nil {
		return err
	}
	if r == nil || copyFn == nil || mountDir == "" {
		return errors.New("install: Runner, copyFn, and mountDir are required")
	}

	steps := []struct {
		name string
		args []string
	}{
		{sgdiskBin, sgdiskArgs(o)},
		{partprobeBin, []string{o.Disk}},
		{mkfsVfatBin, []string{"-F", "32", "-n", o.ESPLabel, byPartLabel(o.ESPLabel)}},
		{mountBin, []string{byPartLabel(o.ESPLabel), mountDir}},
	}
	for _, s := range steps {
		if out, err := r.Run(ctx, s.name, s.args...); err != nil {
			return fmt.Errorf("install: %s: %w (%s)", s.name, err, out)
		}
	}

	dst := filepath.Join(mountDir, fallbackUKIRelPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		_, _ = r.Run(ctx, umountBin, mountDir)
		return fmt.Errorf("install: mkdir ESP path: %w", err)
	}
	if err := copyFn(dst, o.UKI); err != nil {
		_, _ = r.Run(ctx, umountBin, mountDir)
		return fmt.Errorf("install: copy UKI: %w", err)
	}
	if out, err := r.Run(ctx, umountBin, mountDir); err != nil {
		return fmt.Errorf("install: umount: %w (%s)", err, out)
	}
	return nil
}

// CopyFile copies src to dst, used as the production copyFn.
func CopyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
