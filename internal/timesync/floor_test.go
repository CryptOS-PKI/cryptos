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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFloorStartsAtBuildTime(t *testing.T) {
	build := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	f, err := OpenFloor(filepath.Join(t.TempDir(), "clock-floor"), build)
	if err != nil {
		t.Fatalf("OpenFloor: %v", err)
	}
	if got := f.Get(); !got.Equal(build) {
		t.Fatalf("Get = %v, want the build time %v", got, build)
	}
}

func TestFloorAdvancePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock-floor")
	build := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	f, err := OpenFloor(path, build)
	if err != nil {
		t.Fatalf("OpenFloor: %v", err)
	}
	later := time.Date(2026, 9, 29, 12, 0, 0, 5, time.UTC)
	if err := f.Advance(later); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	// An earlier time never lowers the floor.
	if err := f.Advance(later.Add(-time.Hour)); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	g, err := OpenFloor(path, build)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := g.Get(); !got.Equal(later) {
		t.Fatalf("reopened floor = %v, want %v", got, later)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("floor file mode = %v, want 0600", info.Mode().Perm())
	}
}

// A build time later than the persisted floor wins: a new image never runs
// behind the day it was built.
func TestFloorBuildTimeWinsWhenLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock-floor")
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f, _ := OpenFloor(path, time.Time{})
	if err := f.Advance(old); err != nil {
		t.Fatal(err)
	}
	build := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	g, err := OpenFloor(path, build)
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Get(); !got.Equal(build) {
		t.Fatalf("Get = %v, want %v", got, build)
	}
}

// A damaged floor file is reported, not silently treated as "no floor", and
// the floor still holds at the build time.
func TestFloorCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock-floor")
	if err := os.WriteFile(path, []byte("not a time\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	f, err := OpenFloor(path, build)
	if err == nil {
		t.Fatal("OpenFloor accepted a corrupt floor file")
	}
	if f == nil || !f.Get().Equal(build) {
		t.Fatal("OpenFloor must still return a floor at the build time")
	}
}
