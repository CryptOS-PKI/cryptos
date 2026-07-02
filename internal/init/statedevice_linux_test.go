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
	"os"
	"path/filepath"
	"testing"
)

// writeUevent lays down <root>/<dev>/uevent with the given lines.
func writeUevent(t *testing.T, root, dev string, lines string) {
	t.Helper()
	dir := filepath.Join(root, dev)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uevent"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveStateDevice(t *testing.T) {
	root := t.TempDir()
	// Whole disk: no PARTNAME.
	writeUevent(t, root, "vda", "MAJOR=254\nMINOR=0\nDEVNAME=vda\nDEVTYPE=disk\n")
	// A decoy partition and the target, out of order.
	writeUevent(t, root, "vda1", "MAJOR=254\nMINOR=1\nDEVNAME=vda1\nDEVTYPE=partition\nPARTNAME=esp\n")
	writeUevent(t, root, "vda2", "MAJOR=254\nMINOR=2\nDEVNAME=vda2\nDEVTYPE=partition\nPARTNAME=cryptos-state\n")

	got, err := resolveStateDeviceIn(root, "cryptos-state")
	if err != nil {
		t.Fatalf("resolveStateDeviceIn: %v", err)
	}
	if want := "/dev/vda2"; got != want {
		t.Errorf("device = %q, want %q", got, want)
	}
}

func TestResolveStateDeviceNotFound(t *testing.T) {
	root := t.TempDir()
	writeUevent(t, root, "vda1", "DEVNAME=vda1\nPARTNAME=esp\n")
	if _, err := resolveStateDeviceIn(root, "cryptos-state"); err == nil {
		t.Fatal("expected an error when no partition matches, got nil")
	}
}
