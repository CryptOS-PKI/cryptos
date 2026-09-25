//go:build !linux

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

import "errors"

// errShutdownUnsupported keeps the module building on a non-Linux dev host.
var errShutdownUnsupported = errors.New("init: shutdown control is unsupported on this platform")

// disableCtrlAltDel is unsupported off Linux. CryptOS PID 1 only ever runs on
// Linux; this stub keeps the package buildable on a developer workstation.
func disableCtrlAltDel() error { return errShutdownUnsupported }

// forceHalt is a no-op off Linux: there is no kernel to ask to restart.
func forceHalt(ShutdownAction) {}
