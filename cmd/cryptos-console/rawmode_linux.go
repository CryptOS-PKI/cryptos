//go:build linux

package main

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

import "golang.org/x/sys/unix"

// makeRaw puts the terminal at fd into raw mode so keystrokes arrive one byte
// at a time without local echo or line editing. It returns a restore func that
// puts the original settings back, and an error if fd is not a terminal (for
// example when stdin is a pipe under test). On error the restore func is a
// no-op so the caller can defer it unconditionally.
func makeRaw(fd int) (restore func(), err error) {
	orig, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}, err
	}
	raw := *orig
	// Disable canonical mode, echo, signal generation, and extended input so
	// Ctrl-R and friends reach us as raw bytes rather than being interpreted
	// by the line discipline.
	raw.Lflag &^= unix.ICANON | unix.ECHO | unix.ISIG | unix.IEXTEN
	// Disable CR-to-NL translation and software flow control so Ctrl-R (0x12,
	// which is also XOFF's neighbor) is delivered verbatim.
	raw.Iflag &^= unix.ICRNL | unix.IXON
	// Read returns as soon as one byte is available.
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return func() {}, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, orig) }, nil
}
