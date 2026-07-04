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
	"context"
	"io"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/console"
)

// ctrlR is the byte the terminal sends for Ctrl-R; it arms the reset ceremony.
const ctrlR = 0x12

// escKey and ctrlC abort the reset ceremony back to the dashboard.
const (
	escKey = 0x1b
	ctrlC  = 0x03
)

// snapFunc takes a dashboard snapshot.
type snapFunc func(context.Context) (console.View, error)

// resetFunc calls the node's Reset RPC with the operator-typed Root CN.
type resetFunc func(ctx context.Context, confirmCN string) error

// run drives the dashboard-only poll-and-render loop with no key handling. It
// exists for callers and tests that only exercise the rendering path.
func run(ctx context.Context, snap snapFunc, out io.Writer, tick <-chan time.Time) {
	runConsole(ctx, snap, nil, out, tick, nil)
}

// runConsole drives the console: it polls the node and redraws the dashboard on
// every tick, and it handles keyboard input. In the serving state, Ctrl-R opens
// the destructive reset confirmation; the operator retypes the Root CA CN and
// presses Enter. Only an exact match calls resetFn; Esc or Ctrl-C aborts back
// to the dashboard. keys and tick may be nil (a nil channel simply never
// fires), so tests can drive either path in isolation.
func runConsole(ctx context.Context, snap snapFunc, resetFn resetFunc, out io.Writer, tick <-chan time.Time, keys <-chan byte) {
	// confirming holds the reset ceremony state, or nil on the dashboard.
	var confirming *console.ConfirmState
	// rootCN is the CN the last snapshot reported; the confirm compares against it.
	var rootCN string
	// resetting latches once a Reset call succeeds so ticks stop redrawing over
	// the "resetting" screen while the node reboots.
	resetting := false

	drawDashboard := func() {
		v, _ := snap(ctx)
		rootCN = v.RootCN
		_, _ = io.WriteString(out, console.RenderDashboard(v))
	}
	drawConfirm := func() {
		_, _ = io.WriteString(out, console.RenderResetConfirm(rootCN, confirming.Typed))
	}

	drawDashboard()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			if resetting {
				continue
			}
			if confirming == nil {
				drawDashboard()
			}
		case b, ok := <-keys:
			if !ok {
				keys = nil
				continue
			}
			if resetting {
				continue
			}
			if confirming == nil {
				// Only arm reset from a serving, non-degraded frame that has a
				// Root CN to name; an unprovisioned node has nothing to wipe.
				if b == ctrlR && resetFn != nil && rootCN != "" {
					confirming = &console.ConfirmState{}
					drawConfirm()
				}
				continue
			}
			// In the confirm ceremony.
			if b == escKey || b == ctrlC {
				confirming = nil
				drawDashboard()
				continue
			}
			if submit := confirming.Key(b); submit {
				if confirming.Typed == rootCN {
					if err := resetFn(ctx, confirming.Typed); err == nil {
						resetting = true
						_, _ = io.WriteString(out, console.RenderResetting())
					} else {
						// Reset was refused or failed; leave the ceremony and
						// return to the dashboard so the node keeps serving.
						confirming = nil
						drawDashboard()
					}
				} else {
					// Mismatch: abandon the ceremony without calling Reset.
					confirming = nil
					drawDashboard()
				}
				continue
			}
			drawConfirm()
		}
	}
}
