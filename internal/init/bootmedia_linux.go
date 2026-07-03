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
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// bootESPLabel is the GPT partition name of the ISO/boot-media ESP.
const bootESPLabel = "EFI"

// bootUKIRelPath is the UEFI removable-media fallback path under the ESP
// where the signed UKI lives on the boot media.
const bootUKIRelPath = "EFI/BOOT/BOOTX64.EFI"

// LocateBootUKI finds the ESP on the boot media (GPT label "EFI"), mounts
// it read-only at a temporary directory, verifies that the UKI exists at
// the removable-media fallback path, and returns its absolute path.
//
// The caller owns the returned path for the lifetime of the mount; the
// mount is left in place so the caller can copy or read the UKI. Cleanup
// (umount + rmdir) is the caller's responsibility.
//
// The device is resolved via the same sysfs label scan used by
// resolveStateDevice; no udev symlinks are required.
func LocateBootUKI() (string, error) {
	return locateBootUKIIn("/sys/class/block")
}

// locateBootUKIIn is LocateBootUKI with an explicit sysfs root so the
// label-resolution seam can be unit-tested without touching the real
// filesystem or calling mount(2).
func locateBootUKIIn(sysfsRoot string) (string, error) {
	dev, err := resolveStateDeviceIn(sysfsRoot, bootESPLabel)
	if err != nil {
		return "", fmt.Errorf("init: locateBootUKI: %w", err)
	}

	tmp, err := os.MkdirTemp("", "cryptos-boot-esp-*")
	if err != nil {
		return "", fmt.Errorf("init: locateBootUKI: mktemp: %w", err)
	}

	// MS_RDONLY = 1
	if err := unix.Mount(dev, tmp, "vfat", 1, ""); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: mount %s: %w", dev, err)
	}

	ukiPath := filepath.Join(tmp, bootUKIRelPath)
	if _, err := os.Stat(ukiPath); err != nil {
		_ = unix.Unmount(tmp, 0)
		_ = os.Remove(tmp)
		return "", fmt.Errorf("init: locateBootUKI: UKI not found at %s: %w", ukiPath, err)
	}
	return ukiPath, nil
}
