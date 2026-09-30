package node

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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// sectorSize is the fixed unit the kernel reports /sys/block/<dev>/size in.
const sectorSize = 512

// virtualDiskPrefixes are /sys/block entries that are never real install
// targets: loopback, RAM/zram, device-mapper, and optical/floppy.
var virtualDiskPrefixes = []string{"loop", "ram", "zram", "dm-", "sr", "fd", "md"}

// InstallDiskLister enumerates candidate install block devices by reading the
// kernel's /sys/block, which needs no udev (the CryptOS image ships none). The
// sysfs root is injectable so the scan can be unit-tested against a fixture.
type InstallDiskLister struct{ root string }

// NewInstallDiskLister returns a lister over the real /sys/block.
func NewInstallDiskLister() *InstallDiskLister { return &InstallDiskLister{root: "/sys/block"} }

// ListInstallDisks returns the whole-disk block devices suitable as install
// targets (size, model, and rotational/removable hints), sorted by path.
// Partitions never appear: /sys/block lists whole devices only. Virtual and
// optical/floppy devices are filtered out.
func (l *InstallDiskLister) ListInstallDisks(_ context.Context) ([]*cryptosv1.InstallDisk, error) {
	entries, err := os.ReadDir(l.root)
	if err != nil {
		return nil, err
	}
	var disks []*cryptosv1.InstallDisk
	for _, e := range entries {
		name := e.Name()
		if isVirtualDisk(name) {
			continue
		}
		sectors := readUint(filepath.Join(l.root, name, "size"))
		if sectors == 0 {
			continue // no media / zero-size device (e.g. an empty card reader)
		}
		disks = append(disks, &cryptosv1.InstallDisk{
			Path:       "/dev/" + name,
			SizeBytes:  sectors * sectorSize,
			Model:      readTrimmed(filepath.Join(l.root, name, "device", "model")),
			Rotational: readTrimmed(filepath.Join(l.root, name, "queue", "rotational")) == "1",
			Removable:  readTrimmed(filepath.Join(l.root, name, "removable")) == "1",
		})
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i].Path < disks[j].Path })
	return disks, nil
}

// isVirtualDisk reports whether a /sys/block entry is a non-install-target
// (loopback, RAM, device-mapper, optical, floppy, md).
func isVirtualDisk(name string) bool {
	for _, p := range virtualDiskPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// readTrimmed reads a sysfs attribute and trims surrounding whitespace,
// returning "" on any error (a missing attribute is not fatal).
func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readUint reads a sysfs unsigned integer attribute, returning 0 on any error
// or non-numeric content.
func readUint(path string) uint64 {
	n, err := strconv.ParseUint(readTrimmed(path), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
