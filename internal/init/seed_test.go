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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/audit"
	"github.com/CryptOS-PKI/cryptos/internal/ceremony"
)

func TestSeedLengthMatchesSubsystems(t *testing.T) {
	if SeedLength != audit.SeedLength {
		t.Errorf("SeedLength %d != audit.SeedLength %d", SeedLength, audit.SeedLength)
	}
	if SeedLength != ceremony.SeedLength {
		t.Errorf("SeedLength %d != ceremony.SeedLength %d", SeedLength, ceremony.SeedLength)
	}
}

func TestLoadOrCreateSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "seed")

	// First boot: generates and persists.
	first, err := LoadOrCreateSeed(path)
	if err != nil {
		t.Fatalf("first LoadOrCreateSeed: %v", err)
	}
	if len(first) != SeedLength {
		t.Fatalf("seed len = %d, want %d", len(first), SeedLength)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("seed file not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("seed file perms = %o, want 600", perm)
	}

	// Subsequent boot: reads the same bytes back.
	second, err := LoadOrCreateSeed(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateSeed: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("seed changed between boots")
	}

	// Not all zero (actually random).
	if bytes.Equal(first, make([]byte, SeedLength)) {
		t.Error("seed is all zeros")
	}
}

func TestLoadOrCreateSeed_Errors(t *testing.T) {
	if _, err := LoadOrCreateSeed(""); err == nil {
		t.Error("empty path should error")
	}
	// Corrupt seed (wrong length) is rejected, not silently regenerated.
	bad := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(bad, []byte("too short"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadOrCreateSeed(bad); err == nil {
		t.Error("wrong-length seed should error")
	}
}
