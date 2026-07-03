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
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SeedLength is the master state-partition seed length in bytes. The
// audit-log and ceremony-manifest signing keys are HKDF-derived from this
// one seed (with distinct labels), so it must match both subsystems
// (asserted in the tests against audit.SeedLength / ceremony.SeedLength).
const SeedLength = 32

// LoadOrCreateSeed returns the master seed at path. On first boot (no
// file) it generates a fresh seed from crypto/rand and persists it
// 0600 (creating the parent directory 0700); on every later boot it
// reads the existing seed back. The seed lives on the encrypted state
// partition, so it is only ever present once the volume is unlocked.
func LoadOrCreateSeed(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("init: LoadOrCreateSeed: path is required")
	}
	switch data, err := os.ReadFile(path); {
	case err == nil:
		if len(data) != SeedLength {
			return nil, fmt.Errorf("init: LoadOrCreateSeed: %s is %d bytes, want %d (corrupt seed?)", path, len(data), SeedLength)
		}
		return data, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("init: LoadOrCreateSeed: read %s: %w", path, err)
	}

	// First boot: generate and persist atomically with fsync so the seed is
	// durable even if the node loses power before the filesystem's write-back
	// timer fires. Write to a temp file, sync, rename, then sync the directory
	// (the same pattern as config.FileStore.atomicWrite).
	seed := make([]byte, SeedLength)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("init: LoadOrCreateSeed: generate: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("init: LoadOrCreateSeed: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".seed-*")
	if err != nil {
		return nil, fmt.Errorf("init: LoadOrCreateSeed: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after successful rename
	if _, err := tmp.Write(seed); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("init: LoadOrCreateSeed: write temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("init: LoadOrCreateSeed: chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("init: LoadOrCreateSeed: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("init: LoadOrCreateSeed: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("init: LoadOrCreateSeed: rename: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("init: LoadOrCreateSeed: open dir: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("init: LoadOrCreateSeed: sync dir: %w", err)
	}
	if err := d.Close(); err != nil {
		return nil, fmt.Errorf("init: LoadOrCreateSeed: close dir: %w", err)
	}
	return seed, nil
}
