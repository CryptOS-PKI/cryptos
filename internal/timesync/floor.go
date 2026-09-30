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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Floor is the earliest time the node's clock may be set to: the latest of
// the image build time, the last good sync, and the latest notBefore the node
// has issued. Setting the clock behind it would reorder audit and issuance
// times on a CA that has already used later ones. It persists in a small file
// on the encrypted state volume, which is mounted before networking, so the
// boot sync can read it before etcd starts.
type Floor struct {
	path  string
	build time.Time

	mu  sync.Mutex
	cur time.Time
}

// OpenFloor loads the floor file at path, raised to build. A missing file is a
// first boot and leaves the floor at build. A file that cannot be parsed is
// returned as an error alongside a usable Floor at build, so the caller can
// log it loudly and keep going; the next Advance rewrites the file.
func OpenFloor(path string, build time.Time) (*Floor, error) {
	f := &Floor{path: path, build: build.UTC(), cur: build.UTC()}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, fmt.Errorf("timesync: read clock floor %s: %w", path, err)
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(raw)))
	if err != nil {
		return f, fmt.Errorf("timesync: clock floor %s is damaged: %w", path, err)
	}
	if t.After(f.cur) {
		f.cur = t.UTC()
	}
	return f, nil
}

// Get returns the current floor.
func (f *Floor) Get() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}

// Advance raises the floor to t and persists it. A t at or below the floor is
// a no-op, so callers may pass every issuance time without checking.
func (f *Floor) Advance(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !t.After(f.cur) {
		return nil
	}
	if err := writeFloor(f.path, t.UTC()); err != nil {
		return err
	}
	f.cur = t.UTC()
	return nil
}

// writeFloor replaces the floor file atomically, so a crash mid-write leaves
// the old floor rather than a torn one.
func writeFloor(path string, t time.Time) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".clock-floor-*")
	if err != nil {
		return fmt.Errorf("timesync: write clock floor: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(t.Format(time.RFC3339Nano) + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("timesync: write clock floor: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("timesync: write clock floor: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("timesync: write clock floor: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("timesync: write clock floor: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("timesync: write clock floor: %w", err)
	}
	return nil
}
