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
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/console"
)

func TestRunRendersSnapshot(t *testing.T) {
	var buf bytes.Buffer
	tick := make(chan time.Time, 1)
	tick <- time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	snap := func(context.Context) (console.View, error) {
		cancel() // one render then stop
		return console.View{RootCN: "Interborough Root CA G1", Role: "ROOT", NodeStatus: "ESTABLISHED", TPM: "SEALED"}, nil
	}
	run(ctx, snap, &buf, tick)
	if !bytes.Contains(buf.Bytes(), []byte("Interborough Root CA G1")) {
		t.Fatalf("run did not render the dashboard:\n%s", buf.String())
	}
}

func TestRunRendersDegradedOnError(t *testing.T) {
	var buf bytes.Buffer
	tick := make(chan time.Time, 1)
	tick <- time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	snap := func(context.Context) (console.View, error) {
		cancel()
		return console.View{Degraded: true}, errors.New("dial failed")
	}
	run(ctx, snap, &buf, tick)
	if !bytes.Contains(buf.Bytes(), []byte("degraded")) {
		t.Fatalf("run did not render degraded:\n%s", buf.String())
	}
}
