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
// after EarlyMounts, once devtmpfs has created /dev/kmsg. Prod boots quiet
// (suppressed on screen); dev serial still surfaces them via dmesg/kmsg.
// Best-effort: if /dev/kmsg is unavailable, logging stays on its default.
func routeVerboseLogs() {
	if f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0); err == nil {
		log.SetOutput(f)
	}
}
