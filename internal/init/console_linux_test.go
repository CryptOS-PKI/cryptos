//go:build linux

package init

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
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRouteVerboseLogsTurnsOffTheKmsgRateLimit(t *testing.T) {
	dir := t.TempDir()
	sysctl := filepath.Join(dir, "printk_devkmsg")
	kmsg := filepath.Join(dir, "kmsg")
	if err := os.WriteFile(sysctl, []byte("ratelimit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kmsg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prev := log.Writer()
	t.Cleanup(func() { log.SetOutput(prev) })

	routeVerboseLogsTo(sysctl, kmsg)

	got, err := os.ReadFile(sysctl)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "on" {
		t.Fatalf("printk_devkmsg = %q, want %q so no boot line is dropped", got, "on")
	}
	log.Print("listeners up")
	logged, err := os.ReadFile(kmsg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "listeners up") {
		t.Fatalf("log line did not reach kmsg: %q", logged)
	}
}

func TestRouteVerboseLogsStillRoutesWhenTheSysctlIsMissing(t *testing.T) {
	dir := t.TempDir()
	kmsg := filepath.Join(dir, "kmsg")
	if err := os.WriteFile(kmsg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prev := log.Writer()
	t.Cleanup(func() { log.SetOutput(prev) })

	routeVerboseLogsTo(filepath.Join(dir, "missing", "printk_devkmsg"), kmsg)

	log.Print("state key mode: tpm")
	logged, err := os.ReadFile(kmsg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "state key mode: tpm") {
		t.Fatalf("log line did not reach kmsg: %q", logged)
	}
}
