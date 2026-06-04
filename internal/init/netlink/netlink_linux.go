//go:build linux

package netlink

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
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// interfaceIndex resolves an interface name to its kernel index.
func interfaceIndex(name string) (int, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifc.Index, nil
}

// BringUpLoopback sets the loopback interface up.
func BringUpLoopback() error {
	return bringUpLoopback(interfaceIndex, sendAck)
}

// ConfigureInterface brings cfg.Name up, assigns its static IPv4 address,
// and installs the default route via cfg.Gateway.
func ConfigureInterface(cfg Config) error {
	return configure(cfg, interfaceIndex, sendAck)
}

// sendAck opens an AF_NETLINK route socket, sends one request, and waits
// for the kernel's ACK, returning any error the kernel reports.
func sendAck(msg []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink: socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		return fmt.Errorf("netlink: bind: %w", err)
	}
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink: send: %w", err)
	}

	resp := make([]byte, unix.Getpagesize())
	n, _, err := unix.Recvfrom(fd, resp, 0)
	if err != nil {
		return fmt.Errorf("netlink: recv ack: %w", err)
	}
	errno, ok := parseAck(resp[:n])
	if !ok {
		return fmt.Errorf("netlink: unexpected reply (%d bytes)", n)
	}
	if errno != 0 {
		// netlink reports negative errno.
		return fmt.Errorf("netlink: kernel rejected request: %w", syscall.Errno(-errno))
	}
	return nil
}
