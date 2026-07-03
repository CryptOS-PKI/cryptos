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
	"strings"
	"testing"
)

// TestLocateBootUKI_ResolvesESPLabel verifies that locateBootUKIIn finds the
// partition with GPT label "EFI" via the sysfs scan. The mount syscall is
// integration-level and is not exercised here; the test confirms only that the
// device resolution seam (resolveStateDeviceIn) is wired correctly for the
// boot-ESP label.
func TestLocateBootUKI_ResolvesESPLabel(t *testing.T) {
	root := t.TempDir()
	// Lay down a fake sysfs tree: decoy partition + the boot ESP.
	writeUevent(t, root, "sda1", "MAJOR=8\nMINOR=1\nDEVNAME=sda1\nDEVTYPE=partition\nPARTNAME=cryptos-state\n")
	writeUevent(t, root, "sda2", "MAJOR=8\nMINOR=2\nDEVNAME=sda2\nDEVTYPE=partition\nPARTNAME=EFI\n")

	// locateBootUKIIn will resolve sda2, then attempt a real mount — which
	// will fail in the test environment. We confirm it got past the
	// resolution step (the error is about mount, not "no partition named").
	_, err := locateBootUKIIn(root)
	if err == nil {
		// Unexpectedly succeeded — only possible if /dev/sda2 exists and is
		// a mountable vfat device, which is not the case in CI.
		t.Fatal("expected an error from mount in test environment, got nil")
	}
	if strings.Contains(err.Error(), "no partition named") {
		t.Errorf("device resolution failed; expected mount-level error, got: %v", err)
	}
}

// TestLocateBootUKI_NotFound verifies that locateBootUKIIn returns an error
// when no partition with GPT label "EFI" is present.
func TestLocateBootUKI_NotFound(t *testing.T) {
	root := t.TempDir()
	writeUevent(t, root, "sda1", "DEVNAME=sda1\nPARTNAME=cryptos-state\n")

	_, err := locateBootUKIIn(root)
	if err == nil {
		t.Fatal("expected error when no EFI partition present, got nil")
	}
	if !strings.Contains(err.Error(), "no partition named") {
		t.Errorf("unexpected error: %v", err)
	}
}
