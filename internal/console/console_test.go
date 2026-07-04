package console_test

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
