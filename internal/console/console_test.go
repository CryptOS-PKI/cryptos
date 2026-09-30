package console_test

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
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/console"
)

func TestBannerHasWordmark(t *testing.T) {
	b := console.Banner()
	if !strings.Contains(b, "CryptOS") || !strings.Contains(b, "PKI") {
		t.Fatalf("banner missing wordmark:\n%s", b)
	}
	// The classic shield uses the point at the bottom.
	if !strings.Contains(b, "'-'") {
		t.Fatalf("banner missing shield point:\n%s", b)
	}
}

func TestRendererBanner(t *testing.T) {
	var buf bytes.Buffer
	if err := console.NewRenderer(&buf).Banner(); err != nil {
		t.Fatal(err)
	}
	if buf.String() != console.Banner() {
		t.Fatalf("Banner() writer output differs from Banner() string")
	}
}

func TestRendererStep(t *testing.T) {
	cases := []struct {
		name  string
		state console.StepState
		want  string
	}{
		{"state volume", console.StepOK, "   [ok]  state volume\n"},
		{"network", console.StepRunning, "   [..]  network\n"},
		{"management API", console.StepFail, "   [!!]  management API\n"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := console.NewRenderer(&buf).Step(c.name, c.state); err != nil {
			t.Fatal(err)
		}
		if buf.String() != c.want {
			t.Fatalf("Step(%q,%v) = %q, want %q", c.name, c.state, buf.String(), c.want)
		}
	}
}
