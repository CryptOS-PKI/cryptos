package main

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
	"runtime"
	"testing"
)

func TestRun_WritesAllOutputs(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "CryptOS Secure Boot (test)", 90, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, name := range []string{"sb.key", "sb.crt", "sb.der"} {
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
	// The private key is owner-only (skip the check where modes are not
	// faithfully represented, e.g. Windows).
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "sb.key"))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("sb.key mode = %o, want 600", perm)
		}
	}
}

func TestRun_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "x", 0, false); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := run(dir, "x", 0, false); err == nil {
		t.Error("second run without --force should fail")
	}
	if err := run(dir, "x", 0, true); err != nil {
		t.Errorf("run with --force should overwrite: %v", err)
	}
}

func TestRun_InvalidCN(t *testing.T) {
	if err := run(t.TempDir(), "", 0, false); err == nil {
		t.Error("empty CN should fail")
	}
}
