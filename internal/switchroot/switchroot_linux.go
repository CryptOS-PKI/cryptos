//go:build linux

package switchroot

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
	"io/fs"

	"golang.org/x/sys/unix"
)

// loopMajor is the device-node major number for loop devices.
const loopMajor = 7

// linuxSystem is the real System backed by Linux syscalls.
type linuxSystem struct{}

// NewSystem returns the real Linux System.
func NewSystem() System { return linuxSystem{} }

func (linuxSystem) Mkdir(path string, perm uint32) error {
	return unix.Mkdir(path, perm)
}

func (linuxSystem) Mount(source, target, fstype string, flags uintptr, data string) error {
	return unix.Mount(source, target, fstype, flags, data)
}

func (linuxSystem) Chdir(dir string) error { return unix.Chdir(dir) }

func (linuxSystem) Chroot(dir string) error { return unix.Chroot(dir) }

func (linuxSystem) Exec(argv0 string, argv, envv []string) error {
	return unix.Exec(argv0, argv, envv)
}

// AttachLoop binds backingFile (read-only) to the first free loop device,
// creating the device node if devtmpfs has not yet materialized it.
func (linuxSystem) AttachLoop(backingFile string) (string, error) {
	backingFd, err := unix.Open(backingFile, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open backing file: %w", err)
	}
	defer func() { _ = unix.Close(backingFd) }()

	ctrl, err := unix.Open("/dev/loop-control", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open /dev/loop-control: %w", err)
	}
	defer func() { _ = unix.Close(ctrl) }()

	num, err := unix.IoctlRetInt(ctrl, unix.LOOP_CTL_GET_FREE)
	if err != nil {
		return "", fmt.Errorf("LOOP_CTL_GET_FREE: %w", err)
	}

	dev := fmt.Sprintf("/dev/loop%d", num)
	node := int(unix.Mkdev(loopMajor, uint32(num)))
	if err := unix.Mknod(dev, unix.S_IFBLK|0o600, node); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("mknod %s: %w", dev, err)
	}

	loopFd, err := unix.Open(dev, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", dev, err)
	}
	defer func() { _ = unix.Close(loopFd) }()

	// The kernel takes its own reference to backingFd, so it is safe to
	// close ours afterward.
	if err := unix.IoctlSetInt(loopFd, unix.LOOP_SET_FD, backingFd); err != nil {
		return "", fmt.Errorf("LOOP_SET_FD: %w", err)
	}
	return dev, nil
}
