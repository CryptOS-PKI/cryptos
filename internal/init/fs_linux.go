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
	"os/exec"

	"golang.org/x/sys/unix"
)

// mkfsExt4Binary is the static mkfs.ext4 baked into the rootfs. Invoked by
// absolute path: PID 1 has no PATH, so a bare "mkfs.ext4" fails to resolve
// (the same reason cryptsetup is called via an absolute path).
const mkfsExt4Binary = "/sbin/mkfs.ext4"

// mkfsExt4 lays down an ext4 filesystem on the unlocked state volume
// (first boot only). -F forces operation on the dm-crypt device; -q is
// quiet.
func mkfsExt4(device string) error {
	out, err := exec.Command(mkfsExt4Binary, "-q", "-F", device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("init: mkfs.ext4 %s: %w (%s)", device, err, out)
	}
	return nil
}

// mountFS mounts source at target. The target directory must exist.
func mountFS(source, target, fstype string) error {
	if err := unix.Mount(source, target, fstype, 0, ""); err != nil {
		return fmt.Errorf("init: mount %s on %s: %w", source, target, err)
	}
	return nil
}

// setHostname sets the kernel hostname. An empty name is a no-op.
func setHostname(name string) error {
	if name == "" {
		return nil
	}
	if err := unix.Sethostname([]byte(name)); err != nil {
		return fmt.Errorf("init: set hostname %q: %w", name, err)
	}
	return nil
}
