//go:build !linux

package timesync

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
	"errors"
	"time"
)

// SystemClock returns a clock that reads the host time but refuses to adjust
// it: only a CryptOS node (Linux) disciplines its clock.
func SystemClock() Clock { return otherClock{} }

type otherClock struct{}

var errUnsupported = errors.New("timesync: adjusting the clock is supported only on Linux")

func (otherClock) Now() time.Time                 { return time.Now() }
func (otherClock) Step(time.Duration) error       { return errUnsupported }
func (otherClock) Slew(time.Duration) error       { return errUnsupported }
func (otherClock) MarkSynced(time.Duration) error { return errUnsupported }
