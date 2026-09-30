package mounts

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
	"os"
	"testing"
)

func TestMountAll_SequenceAndFlags(t *testing.T) {
	var mkdirs []string
	var mounts []spec

	mkdir := func(path string, _ os.FileMode) error {
		mkdirs = append(mkdirs, path)
		return nil
	}
	mount := func(source, target, fstype string, flags uintptr, data string) error {
		mounts = append(mounts, spec{source, target, fstype, flags, data})
		return nil
	}

	if err := mountAll(mkdir, mount); err != nil {
		t.Fatalf("mountAll: %v", err)
	}
	if len(mounts) != len(earlyMounts) {
		t.Fatalf("performed %d mounts, want %d", len(mounts), len(earlyMounts))
	}
	for i, m := range mounts {
		want := earlyMounts[i]
		if m != want {
			t.Errorf("mount[%d] = %+v, want %+v", i, m, want)
		}
		if mkdirs[i] != want.target {
			t.Errorf("mkdir[%d] = %q, want %q (mkdir must precede mount)", i, mkdirs[i], want.target)
		}
	}

	// Every mount carries nosuid.
	for _, m := range mounts {
		if m.flags&msNoSUID == 0 {
			t.Errorf("mount %s missing MS_NOSUID", m.target)
		}
	}
	// /proc and /sys must be noexec + nodev.
	for _, m := range mounts {
		if m.target == "/proc" || m.target == "/sys" {
			if m.flags&msNoExec == 0 || m.flags&msNoDev == 0 {
				t.Errorf("%s must be noexec+nodev, flags=%d", m.target, m.flags)
			}
		}
	}
}

func TestMountAll_MountErrorStops(t *testing.T) {
	calls := 0
	mkdir := func(string, os.FileMode) error { return nil }
	mount := func(_, target, _ string, _ uintptr, _ string) error {
		calls++
		if target == "/sys" {
			return errors.New("boom")
		}
		return nil
	}
	err := mountAll(mkdir, mount)
	if err == nil {
		t.Fatal("mountAll = nil, want error")
	}
	// /proc then /sys, then stop.
	if calls != 2 {
		t.Errorf("mount called %d times, want 2 (stop at first error)", calls)
	}
}

func TestMountAll_MkdirErrorStops(t *testing.T) {
	mountCalled := false
	mkdir := func(string, os.FileMode) error { return errors.New("nope") }
	mount := func(_, _, _ string, _ uintptr, _ string) error {
		mountCalled = true
		return nil
	}
	if err := mountAll(mkdir, mount); err == nil {
		t.Fatal("mountAll = nil, want error on mkdir failure")
	}
	if mountCalled {
		t.Error("mount should not run after mkdir fails")
	}
}

func TestEarlyMountsTable_Complete(t *testing.T) {
	want := map[string]bool{"/proc": false, "/sys": false, "/dev": false, "/run": false, "/tmp": false}
	for _, m := range earlyMounts {
		if _, ok := want[m.target]; !ok {
			t.Errorf("unexpected mount target %q", m.target)
			continue
		}
		want[m.target] = true
	}
	for target, seen := range want {
		if !seen {
			t.Errorf("missing required early mount %q", target)
		}
	}
}
