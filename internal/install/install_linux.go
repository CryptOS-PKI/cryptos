//go:build linux

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
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// RealDeps returns the production Deps that use Linux syscalls: BLKRRPART
// ioctl to reread the partition table, and unix.Mount/unix.Unmount for
// mount/umount. No external binaries (partprobe, /bin/mount, /bin/umount)
// are needed, so this works in the maintenance image (PID 1) which has none.
func RealDeps() Deps {
	return Deps{
		RereadPartitions: rereadPartitions,
		Mount:            mountESP,
		Unmount:          unmountESP,
	}
}

// rereadPartitions opens disk and issues BLKRRPART so the kernel re-parses
// the GPT and devtmpfs creates the new partition device nodes.
func rereadPartitions(disk string) error {
	f, err := os.Open(disk)
	if err != nil {
		return fmt.Errorf("install: open %s: %w", disk, err)
	}
	defer func() { _ = f.Close() }()
	if err := unix.IoctlSetInt(int(f.Fd()), unix.BLKRRPART, 0); err != nil {
		return fmt.Errorf("install: BLKRRPART %s: %w", disk, err)
	}
	return nil
}

// mountESP mounts esp (a vfat EFI System Partition) at dir read-write.
func mountESP(esp, dir string) error {
	if err := unix.Mount(esp, dir, "vfat", 0, ""); err != nil {
		return fmt.Errorf("install: mount %s at %s: %w", esp, dir, err)
	}
	return nil
}

// unmountESP unmounts dir.
func unmountESP(dir string) error {
	if err := unix.Unmount(dir, 0); err != nil {
		return fmt.Errorf("install: unmount %s: %w", dir, err)
	}
	return nil
}
