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

import (
	"errors"
	"runtime"
)

// errFSUnsupported keeps the module building on a non-Linux dev host;
// CryptOS only ever boots on Linux.
var errFSUnsupported = errors.New("init: filesystem bring-up is unsupported on " + runtime.GOOS)

func mkfsExt4(string) error        { return errFSUnsupported }
func mountFS(_, _, _ string) error { return errFSUnsupported }
func setHostname(string) error     { return errFSUnsupported }
