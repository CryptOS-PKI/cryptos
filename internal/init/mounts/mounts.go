package mounts

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
)

// Linux MS_* mount flag values (stable kernel ABI). Defined locally so
// the mount spec table and its driver stay OS-independent and unit
// testable on any platform; the real syscall binding is in the
// linux-tagged file.
const (
	msNoSUID uintptr = 1 << 1 // MS_NOSUID
	msNoDev  uintptr = 1 << 2 // MS_NODEV
	msNoExec uintptr = 1 << 3 // MS_NOEXEC
)

// mountFunc matches the signature of golang.org/x/sys/unix.Mount.
type mountFunc func(source, target, fstype string, flags uintptr, data string) error

// mkdirFunc matches os.MkdirAll, injected for testability.
type mkdirFunc func(path string, perm os.FileMode) error

// spec describes a single early mount.
type spec struct {
	source string
	target string
	fstype string
	flags  uintptr
	data   string
}

// earlyMounts is the ordered set of pseudo-filesystems PID 1 mounts
// before anything else. Order matters: /dev must exist
// before device-dependent subsystems, /run before sockets.
var earlyMounts = []spec{
	{"proc", "/proc", "proc", msNoSUID | msNoExec | msNoDev, ""},
	{"sysfs", "/sys", "sysfs", msNoSUID | msNoExec | msNoDev, ""},
	{"devtmpfs", "/dev", "devtmpfs", msNoSUID, "mode=0755"},
	{"tmpfs", "/run", "tmpfs", msNoSUID | msNoDev, "mode=0755"},
	{"tmpfs", "/tmp", "tmpfs", msNoSUID | msNoDev, "mode=1777"},
}

// EarlyMounts performs the early kernel-mount sequence using the real
// platform syscall. It is idempotent in practice (re-mounting an
// already-mounted target is the caller's concern); a failure is fatal to
// boot and PID 1 turns it into reboot(2).
func EarlyMounts() error {
	return mountAll(os.MkdirAll, sysMount)
}

// mountAll creates each target directory and performs each mount in
// order, stopping at the first error. Separated from EarlyMounts so
// tests can drive it with fakes.
func mountAll(mkdir mkdirFunc, mount mountFunc) error {
	for _, m := range earlyMounts {
		if err := mkdir(m.target, 0o755); err != nil {
			return fmt.Errorf("mounts: mkdir %s: %w", m.target, err)
		}
		if err := mount(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			return fmt.Errorf("mounts: mount %s on %s (%s): %w", m.source, m.target, m.fstype, err)
		}
	}
	return nil
}
