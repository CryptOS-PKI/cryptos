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

import "golang.org/x/sys/unix"

// disableCtrlAltDel stops the kernel restarting the node the instant
// Ctrl-Alt-Del arrives and has it send SIGINT to PID 1 instead, so the key
// combination (or a hypervisor console's "send Ctrl-Alt-Del") takes the
// orderly shutdown path. Call it only once SIGINT is being handled: with no
// handler the Go runtime exits on SIGINT, and PID 1 exiting panics the kernel.
func disableCtrlAltDel() error {
	return unix.Reboot(unix.LINUX_REBOOT_CMD_CAD_OFF)
}
