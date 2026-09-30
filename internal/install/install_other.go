//go:build !linux

package install

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
	"runtime"
)

// errUnsupported is returned by stub Deps on non-Linux platforms.
// CryptOS only ever runs on Linux; these stubs keep developer workstations
// (macOS, Windows) building cleanly.
var errUnsupported = errors.New("install: disk operations are unsupported on " + runtime.GOOS)

// RealDeps returns stub Deps on non-Linux platforms. All functions return
// errUnsupported; Install will fail at the RereadPartitions call if invoked.
func RealDeps() Deps {
	return Deps{
		RereadPartitions: func(string) error { return errUnsupported },
		Mount:            func(_, _ string) error { return errUnsupported },
		Unmount:          func(string) error { return errUnsupported },
	}
}
