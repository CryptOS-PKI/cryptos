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
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/console"
)

// servingSnap returns a snapshot func that always reports an established root
// node with the given Root CN, so the console is in the serving state where
// reset is offered.
func servingSnap(cn string) func(context.Context) (console.View, error) {
	return func(context.Context) (console.View, error) {
		return console.View{RootCN: cn, Role: "ROOT", NodeStatus: "ESTABLISHED"}, nil
	}
}

func TestResetOnMatchingCN(t *testing.T) {
	const cn = "Interborough Root CA G1"
	var buf bytes.Buffer
	keys := make(chan byte, 64)
	var gotCN string
	called := 0
	resetFn := func(_ context.Context, confirm string) error {
		gotCN = confirm
		called++
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())

	// ^R opens the confirm screen, type the exact CN, Enter submits.
	keys <- 0x12 // ^R
	for _, b := range []byte(cn) {
		keys <- b
	}
	keys <- '\r'

	done := make(chan struct{})
	go func() { runConsole(ctx, servingSnap(cn), resetFn, &buf, nil, keys); close(done) }()
	waitFor(t, func() bool { return called == 1 })
	cancel()
	<-done

	if gotCN != cn {
		t.Fatalf("Reset called with %q, want %q", gotCN, cn)
	}
	if !strings.Contains(buf.String(), "Resetting") {
		t.Fatalf("resetting screen not rendered:\n%s", buf.String())
	}
}

func TestResetNotCalledOnMismatch(t *testing.T) {
	const cn = "Interborough Root CA G1"
	var buf bytes.Buffer
	keys := make(chan byte, 64)
	called := 0
	resetFn := func(_ context.Context, _ string) error { called++; return nil }
	ctx, cancel := context.WithCancel(context.Background())

	keys <- 0x12 // ^R
	for _, b := range []byte("WRONG NAME") {
		keys <- b
	}
	keys <- '\r'

	done := make(chan struct{})
	go func() { runConsole(ctx, servingSnap(cn), resetFn, &buf, nil, keys); close(done) }()
	// Give the loop time to process the keys, then stop.
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	if called != 0 {
		t.Fatalf("Reset must not be called on a CN mismatch, called=%d", called)
	}
}

func TestEscCancelsConfirm(t *testing.T) {
	const cn = "Interborough Root CA G1"
	var buf bytes.Buffer
	keys := make(chan byte, 64)
	called := 0
	resetFn := func(_ context.Context, _ string) error { called++; return nil }
	ctx, cancel := context.WithCancel(context.Background())

	keys <- 0x12 // ^R opens confirm
	keys <- 'a'  // type something
	keys <- 0x1b // Esc cancels back to dashboard
	// A subsequent Enter must NOT submit a reset (we are back on the dashboard).
	keys <- '\r'

	done := make(chan struct{})
	go func() { runConsole(ctx, servingSnap(cn), resetFn, &buf, nil, keys); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	if called != 0 {
		t.Fatalf("Esc must abort the ceremony, Reset called=%d", called)
	}
}

// waitFor polls cond until true or a short deadline, failing the test on
// timeout so a hung loop does not stall the suite.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
