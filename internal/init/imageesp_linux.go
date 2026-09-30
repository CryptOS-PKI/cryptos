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

	"golang.org/x/sys/unix"
)

// realESPMounter mounts the installed disk's ESP (GPT label "EFI") for the
// duration of one operation and unmounts afterwards.
//
// Mounting per operation rather than keeping the ESP mounted for the life of
// the node: the boot partition of a CA has no business being writable and
// attached while nothing is upgrading it, and a mount that outlives the
// operation is a mount that can be left behind by a panic.
//
// The mount must cover the whole operation, not each file access. Staging
// writes the incoming image, copies the current one aside, and renames -- a
// sequence that only leaves the node bootable if it happens against one mount.
func realESPMounter(readWrite bool, fn func(root string) error) error {
	dir, err := os.MkdirTemp("", "cryptos-esp-image-*")
	if err != nil {
		return fmt.Errorf("init: image ESP: mktemp: %w", err)
	}
	defer func() { _ = os.Remove(dir) }()

	dev, err := resolveStateDevice(bootESPLabel)
	if err != nil {
		return fmt.Errorf("init: image ESP: resolve the EFI partition: %w", err)
	}

	var flags uintptr
	if !readWrite {
		flags = unix.MS_RDONLY
	}
	if err := unix.Mount(dev, dir, "vfat", flags, ""); err != nil {
		return fmt.Errorf("init: image ESP: mount %s: %w", dev, err)
	}
	defer func() {
		// Unmount is the durability barrier on vfat, so it is also what makes a
		// staged image survive the reboot that follows.
		_ = unix.Unmount(dir, 0)
	}()

	return fn(dir)
}
