//go:build linux

package timesync

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
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// SystemClock returns the kernel real-time clock.
func SystemClock() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Step sets CLOCK_REALTIME to now plus d.
func (systemClock) Step(d time.Duration) error {
	ts := unix.NsecToTimespec(time.Now().Add(d).UnixNano())
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ts); err != nil {
		return fmt.Errorf("clock_settime: %w", err)
	}
	return nil
}

// Slew hands d to the kernel's adjtime path (ADJ_OFFSET_SINGLESHOT), which
// absorbs it at up to 500 ppm without moving the clock backwards. A new call
// replaces any adjustment still pending, which is what a fresh measurement
// wants.
func (systemClock) Slew(d time.Duration) error {
	tx := unix.Timex{Modes: unix.ADJ_OFFSET_SINGLESHOT, Offset: d.Microseconds()}
	if _, err := unix.Adjtimex(&tx); err != nil {
		return fmt.Errorf("adjtimex(ADJ_OFFSET_SINGLESHOT): %w", err)
	}
	return nil
}

// MarkSynced clears STA_UNSYNC and sets the error estimates. With STA_UNSYNC
// clear the kernel's 11-minute mode copies the system time to the hardware
// clock (CONFIG_RTC_SYSTOHC), so the next boot starts closer. The kernel sets
// STA_UNSYNC again by itself if the maximum error grows past its limit
// without another sync.
func (systemClock) MarkSynced(maxErr time.Duration) error {
	var cur unix.Timex
	if _, err := unix.Adjtimex(&cur); err != nil {
		return fmt.Errorf("adjtimex(read): %w", err)
	}
	us := maxErr.Microseconds()
	tx := unix.Timex{
		Modes:    unix.ADJ_STATUS | unix.ADJ_MAXERROR | unix.ADJ_ESTERROR,
		Status:   cur.Status &^ unix.STA_UNSYNC,
		Maxerror: us,
		Esterror: us,
	}
	if _, err := unix.Adjtimex(&tx); err != nil {
		return fmt.Errorf("adjtimex(clear STA_UNSYNC): %w", err)
	}
	return nil
}
