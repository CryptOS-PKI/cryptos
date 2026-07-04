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

// run drives the poll-and-render loop. It renders once immediately, then again
// on every tick until ctx is done. Each cycle takes a snapshot and renders the
// resulting dashboard frame to out. A snapshot error is not fatal: snap returns
// a degraded View alongside the error, so the loop always renders something and
// the operator sees a degraded frame rather than a frozen screen.
func run(ctx context.Context, snap func(context.Context) (console.View, error), out io.Writer, tick <-chan time.Time) {
	render := func() {
		v, _ := snap(ctx)
		_, _ = io.WriteString(out, console.RenderDashboard(v))
	}
	render()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			render()
		}
	}
}
