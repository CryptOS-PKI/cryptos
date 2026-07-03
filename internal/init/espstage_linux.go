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

	"golang.org/x/sys/unix"
)

// espConfigRelPath is the path under the ESP mount where the installer stages
// the operator config (mirrors install.configStagingRelPath).
const espConfigRelPath = "EFI/cryptos/machine.yaml"

// realESPStageAccessors returns the live stageReader and stageDeleter that
// mount the installed disk's ESP (GPT label "EFI"), read/delete the staged
// config at EFI/cryptos/machine.yaml, and unmount. Each call mounts and
// unmounts independently so the two operations are decoupled.
func realESPStageAccessors() espStageAccessors {
	return espStageAccessors{
		stageReader:  readESPStage,
		stageDeleter: deleteESPStage,
	}
}

// readESPStage mounts the installed disk's ESP read-only, reads
// EFI/cryptos/machine.yaml, unmounts, and returns the raw bytes.
// present is false (with no error) when the file does not exist on the ESP.
func readESPStage() (raw []byte, present bool, err error) {
	tmp, err := os.MkdirTemp("", "cryptos-esp-read-*")
	if err != nil {
		return nil, false, fmt.Errorf("init: espStage read: mktemp: %w", err)
	}
	defer func() { _ = os.Remove(tmp) }()

	dev, err := resolveStateDevice(bootESPLabel)
	if err != nil {
		// No EFI partition: treat as no stage present (the disk may not be
		// installed or this is the boot-media path, not the target disk).
		return nil, false, nil
	}

	// MS_RDONLY = 1
	if err := unix.Mount(dev, tmp, "vfat", 1, ""); err != nil {
		return nil, false, fmt.Errorf("init: espStage read: mount %s: %w", dev, err)
	}
	defer func() { _ = unix.Unmount(tmp, 0) }()

	stagePath := filepath.Join(tmp, espConfigRelPath)
	b, err := os.ReadFile(stagePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("init: espStage read: %w", err)
	}
	return b, true, nil
}

// deleteESPStage mounts the installed disk's ESP read-write and removes
// EFI/cryptos/machine.yaml. Called only after a successful store.Write.
func deleteESPStage() error {
	tmp, err := os.MkdirTemp("", "cryptos-esp-del-*")
	if err != nil {
		return fmt.Errorf("init: espStage delete: mktemp: %w", err)
	}
	defer func() { _ = os.Remove(tmp) }()

	dev, err := resolveStateDevice(bootESPLabel)
	if err != nil {
		return fmt.Errorf("init: espStage delete: resolve EFI partition: %w", err)
	}

	if err := unix.Mount(dev, tmp, "vfat", 0, ""); err != nil {
		return fmt.Errorf("init: espStage delete: mount %s: %w", dev, err)
	}
	defer func() { _ = unix.Unmount(tmp, 0) }()

	stagePath := filepath.Join(tmp, espConfigRelPath)
	if err := os.Remove(stagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("init: espStage delete: remove %s: %w", stagePath, err)
	}
	return nil
}
