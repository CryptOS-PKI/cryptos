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
	"context"
	"log"
	"os"
	"os/exec"
	"time"
)

// consoleBinary is the dashboard client baked into the rootfs.
const consoleBinary = "/sbin/cryptos-console"

// consoleRestartDelay is the backoff between console restarts. A crashed
// console is not fatal; it is relaunched after this pause.
const consoleRestartDelay = time.Second

// superviseConsole runs the console dashboard as a supervised child of PID 1.
// It launches /sbin/cryptos-console with its standard streams wired to
// /dev/console and relaunches it whenever it exits, until ctx is done. A
// console crash is never fatal: a serving CA must keep serving even if the
// dashboard dies, so failures are logged (to the kmsg-routed logger) and the
// loop simply backs off and tries again. It never panics.
func superviseConsole(ctx context.Context) {
	for ctx.Err() == nil {
		runConsoleOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(consoleRestartDelay):
		}
	}
}

// runConsoleOnce launches the console once and blocks until it exits, wiring
// its standard streams to /dev/console and closing that handle on return.
func runConsoleOnce(ctx context.Context) {
	cmd := exec.CommandContext(ctx, consoleBinary)
	if cons, err := os.OpenFile("/dev/console", os.O_RDWR, 0); err == nil {
		defer func() { _ = cons.Close() }()
		cmd.Stdin = cons
		cmd.Stdout = cons
		cmd.Stderr = cons
	}
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		log.Printf("console: %s exited: %v; restarting", consoleBinary, err)
	}
}
