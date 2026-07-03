//go:build linux

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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// bootESPLabel is the GPT partition name of the ISO/boot-media ESP.
const bootESPLabel = "EFI"

// bootUKIRelPath is the UEFI removable-media fallback path under the ESP
// where the signed UKI lives on the boot media.
const bootUKIRelPath = "EFI/BOOT/BOOTX64.EFI"

// bootUKIISOName is the fixed filename placed at the root of the ISO9660
// volume when building a CD/DVD ISO. It is used as the fallback when no GPT
// EFI partition is found (i.e. when booted from a CD/ISO).
const bootUKIISOName = "cryptos.uki"

// srDevPattern matches SCSI CD-ROM block device names (sr0, sr1, …).
var srDevPattern = regexp.MustCompile(`^sr[0-9]+$`)

// LocateBootUKI finds the booted UKI, trying two strategies in order:
//
//  1. GPT partition with label "EFI" (disk-based reinstall path): mount the
//     vfat ESP and return EFI/BOOT/BOOTX64.EFI.
//  2. CD-ROM fallback (ISO/VMware CD boot path): scan /sys/class/block for
//     an sr* device, mount it iso9660 read-only, and return cryptos.uki at
//     the mount root.
//
// The caller owns the returned path for the lifetime of the mount; the
// mount is left in place so the caller can copy or read the UKI. Cleanup
// (umount + rmdir) is the caller's responsibility.
func LocateBootUKI() (string, error) {
	return locateBootUKIIn("/sys/class/block")
}

// locateBootUKIIn is LocateBootUKI with an explicit sysfs root so the
// label-resolution and CD-device-discovery seams can be unit-tested without
// touching the real filesystem or calling mount(2).
func locateBootUKIIn(sysfsRoot string) (string, error) {
	// Strategy 1: GPT EFI partition (disk boot).
	dev, err := resolveStateDeviceIn(sysfsRoot, bootESPLabel)
	if err == nil {
		return mountAndVerifyVFAT(dev, bootUKIRelPath)
	}
	// Only fall through on "no partition named" — anything else (e.g.
	// permission error reading sysfs) is a real failure.
	if !isNotFoundErr(err) {
		return "", fmt.Errorf("init: locateBootUKI: %w", err)
	}

	// Strategy 2: CD-ROM fallback (ISO boot).
	srDev, err2 := findCDROMDeviceIn(sysfsRoot)
	if err2 != nil {
		return "", fmt.Errorf("init: locateBootUKI: no EFI partition and no CD-ROM device found: %w", err2)
	}
	return mountAndVerifyISO(srDev, bootUKIISOName)
}

// isNotFoundErr reports whether err carries the "no partition named" sentinel
// from resolveStateDeviceIn.
func isNotFoundErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no partition named")
}

// findCDROMDeviceIn scans sysfsRoot for a block device whose name matches
// sr[0-9]+. Returns the /dev path of the first one found.
func findCDROMDeviceIn(sysfsRoot string) (string, error) {
	entries, err := os.ReadDir(sysfsRoot)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", sysfsRoot, err)
	}
	for _, e := range entries {
		if srDevPattern.MatchString(e.Name()) {
			return "/dev/" + e.Name(), nil
		}
	}
	return "", errors.New("no sr* CD-ROM block device found in " + sysfsRoot)
}

// mountAndVerifyVFAT mounts dev as vfat read-only at a temp dir, checks that
// relPath exists, and returns the absolute path.
func mountAndVerifyVFAT(dev, relPath string) (string, error) {
	tmp, err := os.MkdirTemp("", "cryptos-boot-esp-*")
	if err != nil {
		return "", fmt.Errorf("init: locateBootUKI: mktemp: %w", err)
	}

	// MS_RDONLY = 1
	if err := unix.Mount(dev, tmp, "vfat", 1, ""); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: mount %s: %w", dev, err)
	}

	ukiPath := filepath.Join(tmp, relPath)
	if _, err := os.Stat(ukiPath); err != nil {
		_ = unix.Unmount(tmp, 0)
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: UKI not found at %s: %w", ukiPath, err)
	}
	return ukiPath, nil
}

// mountAndVerifyISO mounts dev as iso9660 read-only at a temp dir, checks that
// fileName exists at the mount root, and returns the absolute path.
func mountAndVerifyISO(dev, fileName string) (string, error) {
	tmp, err := os.MkdirTemp("", "cryptos-boot-cdrom-*")
	if err != nil {
		return "", fmt.Errorf("init: locateBootUKI: mktemp: %w", err)
	}

	// MS_RDONLY = 1
	if err := unix.Mount(dev, tmp, "iso9660", 1, ""); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: mount iso9660 %s: %w", dev, err)
	}

	ukiPath := filepath.Join(tmp, fileName)
	if _, err := os.Stat(ukiPath); err != nil {
		_ = unix.Unmount(tmp, 0)
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: %s not found on CD %s: %w", fileName, dev, err)
	}
	return ukiPath, nil
}
