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
	"context"
	"errors"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

type countingEraser struct{ erased int }

func (e *countingEraser) Erase(context.Context) error {
	e.erased++
	return nil
}

// The resetter backs both the console Reset and RemoteReset. It reads the CA
// CN per call, so a node whose CA certificate is installed after its current
// boot accepts the correct CN without a reboot first.
func TestNodeResetter_HonoursACACNInstalledAfterBoot(t *testing.T) {
	cn := ""
	dev := &countingEraser{}
	rebooted := false
	r := nodeResetter{
		caCN:       func() string { return cn },
		device:     dev,
		clearStage: func() error { return nil },
		reboot:     func() { rebooted = true },
	}

	if err := r.Reset(context.Background(), testCACN); !errors.Is(err, reset.ErrNoCAIdentity) {
		t.Fatalf("before the CA certificate is installed: err = %v, want ErrNoCAIdentity", err)
	}
	if dev.erased != 0 || rebooted {
		t.Fatalf("a node with no CA identity was wiped: erased=%d rebooted=%v", dev.erased, rebooted)
	}

	cn = testCACN
	if err := r.Reset(context.Background(), "Some Other CA"); !errors.Is(err, reset.ErrConfirmMismatch) {
		t.Fatalf("wrong CN: err = %v, want ErrConfirmMismatch", err)
	}
	if err := r.Reset(context.Background(), testCACN); err != nil {
		t.Fatalf("after the CA certificate is installed: %v", err)
	}
	if dev.erased != 1 || !rebooted {
		t.Errorf("erased=%d rebooted=%v, want one erase and a reboot", dev.erased, rebooted)
	}
}
