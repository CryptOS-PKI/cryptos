package config

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
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	configFileName     = "machine.yaml"
	generationFileName = "generation"
)

// FileStore persists the machine config as YAML on the (already-mounted,
// unlocked) state filesystem. The YAML file is the single source of truth read
// at boot; a sidecar holds a monotonic generation counter.
type FileStore struct{ dir string }

func NewFileStore(dir string) *FileStore { return &FileStore{dir: dir} }

func (s *FileStore) configPath() string     { return filepath.Join(s.dir, configFileName) }
func (s *FileStore) generationPath() string { return filepath.Join(s.dir, generationFileName) }

// Read returns the stored config bytes and generation. ok is false when no
// config has been written yet.
func (s *FileStore) Read() (raw []byte, generation uint64, ok bool, err error) {
	b, err := os.ReadFile(s.configPath())
	if os.IsNotExist(err) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("config: read %s: %w", s.configPath(), err)
	}
	gen, err := s.readGeneration()
	if err != nil {
		return nil, 0, false, err
	}
	return b, gen, true, nil
}

// Write validates rawYAML, atomically writes it, and bumps the generation.
func (s *FileStore) Write(rawYAML []byte) (generation uint64, err error) {
	if _, err := Parse(rawYAML); err != nil {
		return 0, fmt.Errorf("config: refuse to persist invalid config: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return 0, fmt.Errorf("config: mkdir %s: %w", s.dir, err)
	}
	next := uint64(1)
	if cur, gerr := s.readGeneration(); gerr == nil {
		next = cur + 1
	}
	// Write generation FIRST, config LAST (each file is individually atomic).
	// Do not reverse: a crash between the two must leave generation ahead of
	// content (old valid config labelled a bumped, advisory generation), never
	// content ahead of generation — which would let a client observe the old
	// generation after an apply and re-apply into already-new content. The
	// config file is the boot source of truth; generation is advisory.
	if err := atomicWrite(s.generationPath(), []byte(strconv.FormatUint(next, 10)+"\n"), 0o400); err != nil {
		return 0, err
	}
	if err := atomicWrite(s.configPath(), rawYAML, 0o400); err != nil {
		return 0, err
	}
	return next, nil
}

func (s *FileStore) readGeneration() (uint64, error) {
	b, err := os.ReadFile(s.generationPath())
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("config: read generation: %w", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: parse generation %q: %w", b, err)
	}
	return n, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("config: temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: rename %s: %w", path, err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("config: open dir %s: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("config: fsync dir %s: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("config: close dir %s: %w", dir, err)
	}
	return nil
}
