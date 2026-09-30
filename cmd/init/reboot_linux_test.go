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
	"testing"

	"golang.org/x/sys/unix"

	bootinit "github.com/CryptOS-PKI/cryptos/internal/init"
)

func TestRebootCommand(t *testing.T) {
	if got := rebootCommand(bootinit.ShutdownReboot); got != unix.LINUX_REBOOT_CMD_RESTART {
		t.Errorf("reboot -> %#x, want RESTART", got)
	}
	if got := rebootCommand(bootinit.ShutdownPowerOff); got != unix.LINUX_REBOOT_CMD_POWER_OFF {
		t.Errorf("power-off -> %#x, want POWER_OFF", got)
	}
}
