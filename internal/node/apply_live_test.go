package node

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
	"context"
	"testing"
)

// The signer reads pki.allow_unsynced_clock from the stored config on every
// signing request and nothing reads it at boot, so switching the override on
// or off alone takes effect at once and must not ask for a reboot.
func TestConfigStoreApply_AllowUnsyncedClockIsLive(t *testing.T) {
	ctx := context.Background()
	fs, cs := seededStore(t, protocolsOffSeed)

	for _, on := range []bool{true, false} {
		current, err := cs.Current(ctx)
		if err != nil {
			t.Fatalf("Current: %v", err)
		}
		current.Pki.AllowUnsyncedClock = on
		resp, err := cs.Apply(ctx, current)
		if err != nil {
			t.Fatalf("Apply (allow_unsynced_clock=%t): %v", on, err)
		}
		if resp.GetRequiresReboot() {
			t.Errorf("setting only allow_unsynced_clock=%t answered requires_reboot", on)
		}
		if got := storedConfig(t, fs).PKI.AllowUnsyncedClock; got != on {
			t.Errorf("stored allow_unsynced_clock = %t, want %t", got, on)
		}
	}
}
