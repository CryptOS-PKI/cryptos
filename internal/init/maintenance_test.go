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
	"os"
	"path/filepath"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/console"
)

func TestStateDeviceMissing_NoPartition(t *testing.T) {
	// A label that cannot exist -> resolveStateDevice fails -> missing == true.
	if !stateDeviceMissing("cryptos-state-does-not-exist-xyz") {
		t.Error("stateDeviceMissing should be true when no matching partition exists")
	}
}

// Adoption compares the fingerprint the maintenance listener presents with the
// node console, so maintenance publishes that certificate where the console
// reads it, and removes it when the listener goes away.
func TestNewMaintenanceCertPublishesWhatTheListenerPresents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mgmt.crt")

	cert, cleanup, err := newMaintenanceCert(path)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != "localhost" {
		t.Fatalf("maintenance cert = %+v, want a parsed leaf for localhost", cert.Leaf)
	}
	if got, want := console.ManagementFingerprint(path), console.Fingerprint(cert.Leaf.Raw); got != want {
		t.Fatalf("published fingerprint = %q, want the presented certificate's %q", got, want)
	}
	if console.ManagementCASigned(path) {
		t.Fatal("the maintenance certificate reads as CA-signed")
	}

	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("published certificate left behind after cleanup: %v", err)
	}
}
