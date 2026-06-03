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
	"fmt"
)

// Step is one named bring-up action in the boot sequence.
type Step struct {
	// Name identifies the step in logs and error messages.
	Name string
	// Run performs the step. A non-nil error is fatal to boot.
	Run func(ctx context.Context) error
}

// Supervisor runs the ordered boot bring-up steps fail-closed: each step
// must succeed before the next runs, and the first failure aborts the
// sequence. PID 1 turns a Run error into reboot(2) — there is no
// recovery shell (spec §5).
type Supervisor struct {
	// Logf, if set, is called with a one-line message as each step starts
	// and when the sequence completes. Defaults to a no-op.
	Logf func(format string, args ...any)
}

// Run executes steps in order. It checks ctx before each step so a
// cancelled context aborts promptly, and wraps any failure with the
// offending step's name.
func (s Supervisor) Run(ctx context.Context, steps []Step) error {
	logf := s.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("init: aborted before step %q: %w", step.Name, err)
		}
		logf("init: starting %s", step.Name)
		if step.Run == nil {
			return fmt.Errorf("init: step %q has no Run function", step.Name)
		}
		if err := step.Run(ctx); err != nil {
			return fmt.Errorf("init: step %q failed: %w", step.Name, err)
		}
	}
	logf("init: bring-up complete (%d steps)", len(steps))
	return nil
}
