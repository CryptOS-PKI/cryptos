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
	"strings"
	"testing"
)

func TestSupervisor_RunsInOrder(t *testing.T) {
	var order []string
	step := func(name string) Step {
		return Step{Name: name, Run: func(context.Context) error {
			order = append(order, name)
			return nil
		}}
	}
	var logged int
	s := Supervisor{Logf: func(string, ...any) { logged++ }}
	if err := s.Run(context.Background(), []Step{step("a"), step("b"), step("c")}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Join(order, ",") != "a,b,c" {
		t.Errorf("order = %v, want a,b,c", order)
	}
	if logged == 0 {
		t.Error("Logf was never called")
	}
}

func TestSupervisor_StopsOnFirstError(t *testing.T) {
	var ran []string
	steps := []Step{
		{Name: "ok", Run: func(context.Context) error { ran = append(ran, "ok"); return nil }},
		{Name: "boom", Run: func(context.Context) error { ran = append(ran, "boom"); return errors.New("kaboom") }},
		{Name: "never", Run: func(context.Context) error { ran = append(ran, "never"); return nil }},
	}
	err := Supervisor{}.Run(context.Background(), steps)
	if err == nil {
		t.Fatal("Run = nil, want error")
	}
	if !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), "kaboom") {
		t.Errorf("error %q should name the step and wrap the cause", err)
	}
	if strings.Join(ran, ",") != "ok,boom" {
		t.Errorf("ran = %v, want ok,boom (stop after failure)", ran)
	}
}

func TestSupervisor_AbortsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran := false
	err := Supervisor{}.Run(ctx, []Step{{Name: "x", Run: func(context.Context) error { ran = true; return nil }}})
	if err == nil {
		t.Fatal("Run with cancelled ctx = nil, want error")
	}
	if ran {
		t.Error("step ran despite cancelled context")
	}
}

func TestSupervisor_NilRunIsError(t *testing.T) {
	err := Supervisor{}.Run(context.Background(), []Step{{Name: "bad"}})
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("Run with nil Run = %v, want error naming the step", err)
	}
}
