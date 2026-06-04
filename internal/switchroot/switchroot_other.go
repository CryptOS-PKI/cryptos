//go:build !linux

package switchroot

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

// errUnsupported is returned by the non-Linux stub; the shim only ever runs
// as PID 1 on Linux. The stub exists so the package builds on the dev host.
var errUnsupported = errors.New("switchroot: only supported on linux")

type stubSystem struct{}

// NewSystem returns a stub that errors on every call off Linux.
func NewSystem() System { return stubSystem{} }

func (stubSystem) Mkdir(string, uint32) error                          { return errUnsupported }
func (stubSystem) Mount(string, string, string, uintptr, string) error { return errUnsupported }
func (stubSystem) AttachLoop(string) (string, error)                   { return "", errUnsupported }
func (stubSystem) Chdir(string) error                                  { return errUnsupported }
func (stubSystem) Chroot(string) error                                 { return errUnsupported }
func (stubSystem) Exec(string, []string, []string) error               { return errUnsupported }
