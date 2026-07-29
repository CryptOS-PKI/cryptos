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
	"testing"
)

// writeBlock creates a fake /sys/block/<name> entry with the given attributes.
func writeBlock(t *testing.T, root, name, size, model, rotational, removable string) {
	t.Helper()
	dir := filepath.Join(root, name)
	mustWrite(t, filepath.Join(dir, "size"), size)
	mustWrite(t, filepath.Join(dir, "removable"), removable)
	mustWrite(t, filepath.Join(dir, "queue", "rotational"), rotational)
	if model != "" {
		mustWrite(t, filepath.Join(dir, "device", "model"), model)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestListInstallDisks(t *testing.T) {
	root := t.TempDir()
	// A real NVMe SSD and a rotational SATA disk are candidates; loopback, RAM,
	// and an empty (zero-size) card reader are not.
	writeBlock(t, root, "nvme0n1", "41943040", "Samsung SSD", "0", "0") // 20 GiB
	writeBlock(t, root, "sda", "2097152", "VBOX HARDDISK", "1", "0")    // 1 GiB
	writeBlock(t, root, "loop0", "8", "", "0", "0")
	writeBlock(t, root, "ram0", "16384", "", "0", "0")
	writeBlock(t, root, "sdb", "0", "Empty Reader", "0", "1") // zero-size: skipped

	l := &InstallDiskLister{root: root}
	disks, err := l.ListInstallDisks(context.Background())
	if err != nil {
		t.Fatalf("ListInstallDisks: %v", err)
	}

	if len(disks) != 2 {
		t.Fatalf("got %d disks, want 2 (nvme0n1, sda); got %+v", len(disks), disks)
	}
	// Sorted by path: /dev/nvme0n1 < /dev/sda.
	if disks[0].Path != "/dev/nvme0n1" || disks[1].Path != "/dev/sda" {
		t.Fatalf("paths = %q,%q; want /dev/nvme0n1,/dev/sda", disks[0].Path, disks[1].Path)
	}
	if disks[0].SizeBytes != 41943040*512 {
		t.Errorf("nvme size = %d, want %d", disks[0].SizeBytes, uint64(41943040*512))
	}
	if disks[0].Model != "Samsung SSD" || disks[0].Rotational {
		t.Errorf("nvme model/rotational = %q/%v, want Samsung SSD/false", disks[0].Model, disks[0].Rotational)
	}
	if !disks[1].Rotational {
		t.Errorf("sda should be rotational")
	}
}
