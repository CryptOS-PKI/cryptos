//go:build linux

package init

/*
Copyright The CryptOS Authors.

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
	"io"
	"log"
	"os"
)

// openConsole opens the node console for branded boot output. PID 1 has
// /dev/console once devtmpfs is mounted (mounts.EarlyMounts).
func openConsole() (io.Writer, error) {
	return os.OpenFile("/dev/console", os.O_WRONLY, 0)
}

// routeVerboseLogs sends the stdlib logger to the kernel ring buffer so
// detailed log lines never clutter the branded console. Boot calls it right
// after EarlyMounts, once devtmpfs has created /dev/kmsg and /proc is mounted.
// Prod boots quiet (suppressed on screen); dev serial still surfaces them via
// dmesg/kmsg. Best-effort: if /dev/kmsg is unavailable, logging stays on its
// default.
func routeVerboseLogs() {
	routeVerboseLogsTo(devkmsgSysctlPath, kmsgPath)
}

const (
	kmsgPath          = "/dev/kmsg"
	devkmsgSysctlPath = "/proc/sys/kernel/printk_devkmsg"
)

func routeVerboseLogsTo(sysctl, kmsg string) {
	// By default the kernel lets a /dev/kmsg writer through at 10 lines per 5
	// seconds and silently drops the rest. PID 1 logs more than that on a
	// normal boot, so without this the later boot lines (and any error after
	// them) never reach the ring buffer or the console.
	sysctlErr := os.WriteFile(sysctl, []byte("on\n"), 0)
	if f, err := os.OpenFile(kmsg, os.O_WRONLY, 0); err == nil {
		log.SetOutput(f)
	}
	if sysctlErr != nil {
		log.Printf("init: kmsg rate limit stays on; later log lines may be dropped: %v", sysctlErr)
	}
}
