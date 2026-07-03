// Package install provisions a bare-metal disk for CryptOS: it lays out
// the GPT (an EFI System Partition + the cryptos-state partition), writes
// the signed UKI to the ESP's removable-media fallback path, and leaves
// the state partition unformatted for the node's first-boot LUKS format.
//
// Disk-touching steps run external tools (sgdisk, mkfs.vfat) via an injectable
// Runner so the layout and command construction are unit testable; mount/umount
// and partition-table reread are performed via injected Deps (syscall
// implementations in install_linux.go, stubs in install_other.go).
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
	"time"
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
	sgdiskBin   = "/sbin/sgdisk"
	mkfsVfatBin = "/sbin/mkfs.vfat"
)

// ExecRunner is the production Runner.
type ExecRunner struct{}

// Run satisfies Runner by shelling out to name. name should be an absolute
// path; bare names are accepted for test harness convenience but fail at
// runtime when PATH is empty (PID 1 context).
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// configStagingRelPath is the path under the mounted ESP where the operator
// machine config is staged for first-boot consumption.
const configStagingRelPath = "EFI/cryptos/machine.yaml"

// Deps holds the syscall-level operations that Install needs. Production
// callers pass RealDeps(); tests pass a fake. This seam keeps Install
// unit-testable without a real disk or root privileges.
type Deps struct {
	// RereadPartitions asks the kernel to reread the partition table on disk.
	// Called after sgdisk so devtmpfs creates the new partition nodes.
	RereadPartitions func(disk string) error
	// Mount mounts esp (vfat) at dir.
	Mount func(esp, dir string) error
	// Unmount unmounts dir.
	Unmount func(dir string) error
	// WaitForDevice polls esp until its device node appears in devtmpfs or
	// the timeout elapses. Tests inject a no-op; production uses the default
	// (nil → waitForDevice is called with a 5-second timeout).
	WaitForDevice func(esp string) error
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
	// ConfigYAML, when non-empty, is the raw machine config YAML that is
	// staged at EFI/cryptos/machine.yaml on the new ESP so the node can
	// read it on first boot. An empty slice skips staging (existing callers
	// remain valid).
	ConfigYAML []byte
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

// partitionDevice returns the block device path for the given partition number
// on disk. Disks whose name ends in a digit (NVMe, MMC, loop devices) use a
// "p<N>" suffix (e.g. /dev/nvme0n1p1, /dev/mmcblk0p1, /dev/loop0p1); others
// (SCSI/VirtIO style) append the number directly (e.g. /dev/sda1, /dev/vda1).
func partitionDevice(disk string, part int) string {
	if len(disk) > 0 && disk[len(disk)-1] >= '0' && disk[len(disk)-1] <= '9' {
		return fmt.Sprintf("%sp%d", disk, part)
	}
	return fmt.Sprintf("%s%d", disk, part)
}

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

// waitForDevice polls path until it appears in devtmpfs or the deadline is
// reached. devtmpfs node creation after BLKRRPART is not instantaneous — a
// short busy-wait is necessary before mkfs.vfat targets the partition.
func waitForDevice(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("install: device %s did not appear within %s", path, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Install partitions Disk, formats the ESP, and writes the UKI to the
// ESP's removable-media fallback path. The state partition is left
// unformatted; the node LUKS-formats and seals it on first boot. UEFI
// boots BOOTX64.EFI without a firmware boot entry, so efibootmgr is not
// required (the operator may add an explicit entry afterwards).
//
// copyFn writes src to dst (injected for testing); mountDir is a scratch
// mount point. d provides the mount/unmount/reread-partitions operations;
// production callers pass RealDeps() (defined in install_linux.go).
func Install(ctx context.Context, o Options, r Runner, mountDir string, copyFn func(dst, src string) error, d Deps) error {
	o.withDefaults()
	if err := o.validate(); err != nil {
		return err
	}
	if r == nil || copyFn == nil || mountDir == "" {
		return errors.New("install: Runner, copyFn, and mountDir are required")
	}
	if d.RereadPartitions == nil || d.Mount == nil || d.Unmount == nil {
		return errors.New("install: Deps.RereadPartitions, Mount, and Unmount are required")
	}
	waitDev := d.WaitForDevice
	if waitDev == nil {
		waitDev = func(esp string) error { return waitForDevice(esp, 5*time.Second) }
	}

	// Step 1: Partition the disk with sgdisk (baked binary).
	if out, err := r.Run(ctx, sgdiskBin, sgdiskArgs(o)...); err != nil {
		return fmt.Errorf("install: %s: %w (%s)", sgdiskBin, err, out)
	}

	// Step 2: Ask the kernel to reread the GPT so devtmpfs creates the
	// partition nodes. No userland partprobe needed.
	if err := d.RereadPartitions(o.Disk); err != nil {
		return fmt.Errorf("install: reread partitions: %w", err)
	}

	// Step 3: Compute the ESP device path and wait for it to appear.
	esp := partitionDevice(o.Disk, 1)
	if err := waitDev(esp); err != nil {
		return err
	}

	// Step 4: Format the ESP (baked binary).
	if out, err := r.Run(ctx, mkfsVfatBin, "-F", "32", "-n", o.ESPLabel, esp); err != nil {
		return fmt.Errorf("install: %s: %w (%s)", mkfsVfatBin, err, out)
	}

	// Step 5: Mount the ESP.
	if err := d.Mount(esp, mountDir); err != nil {
		return fmt.Errorf("install: mount %s: %w", esp, err)
	}

	// Steps 6-8: Copy/stage while mounted; unmount on any error.
	dst := filepath.Join(mountDir, fallbackUKIRelPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		_ = d.Unmount(mountDir)
		return fmt.Errorf("install: mkdir ESP path: %w", err)
	}
	if err := copyFn(dst, o.UKI); err != nil {
		_ = d.Unmount(mountDir)
		return fmt.Errorf("install: copy UKI: %w", err)
	}
	if len(o.ConfigYAML) > 0 {
		if err := StageConfig(mountDir, o.ConfigYAML); err != nil {
			_ = d.Unmount(mountDir)
			return err
		}
	}

	// Step 9: Unmount.
	if err := d.Unmount(mountDir); err != nil {
		return fmt.Errorf("install: unmount: %w", err)
	}
	return nil
}

// StageConfig writes rawYAML to <espMountDir>/EFI/cryptos/machine.yaml,
// creating the directory if necessary. It is called while the target ESP
// is still mounted so the config is in place before the first umount.
func StageConfig(espMountDir string, rawYAML []byte) error {
	dest := filepath.Join(espMountDir, configStagingRelPath)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("install: StageConfig mkdir: %w", err)
	}
	if err := os.WriteFile(dest, rawYAML, 0o644); err != nil {
		return fmt.Errorf("install: StageConfig write: %w", err)
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
