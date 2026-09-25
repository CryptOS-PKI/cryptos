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

import (
	"log"
	"os"

	"golang.org/x/sys/unix"

	bootinit "github.com/CryptOS-PKI/cryptos/internal/init"
)

// rebootCommand maps a shutdown action to the reboot(2) command for it.
// Anything but an explicit power-off restarts the node.
func rebootCommand(action bootinit.ShutdownAction) int {
	if action == bootinit.ShutdownPowerOff {
		return unix.LINUX_REBOOT_CMD_POWER_OFF
	}
	return unix.LINUX_REBOOT_CMD_RESTART
}

// halt flushes buffers and restarts or powers off the node. PID 1 must never
// return; there is no recovery shell.
func halt(action bootinit.ShutdownAction) {
	unix.Sync()
	log.Printf("filesystems synced; asking the kernel for a %s", action)
	if err := unix.Reboot(rebootCommand(action)); err != nil {
		log.Printf("%s failed: %v", action, err)
	}
	// Unreachable if the reboot succeeds.
	os.Exit(1)
}
