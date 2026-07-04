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
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/console"
)

func TestHumanUptime(t *testing.T) {
	got := console.HumanUptime(74*time.Hour + 14*time.Minute + 9*time.Second)
	if got != "3d 02h 14m" {
		t.Fatalf("HumanUptime = %q, want %q", got, "3d 02h 14m")
	}
}

func TestRenderDashboardServing(t *testing.T) {
	v := console.View{
		RootCN: "Interborough Root CA G1", Role: "ROOT", NodeStatus: "ESTABLISHED",
		TPM: "SEALED", Uptime: 74 * time.Hour, Version: "phase-1-dev", Fleet: console.FleetConnected,
	}
	out := console.RenderDashboard(v)
	for _, want := range []string{"CryptOS PKI", "ROOT", "Interborough Root CA G1", "ESTABLISHED", "SEALED", "connected", "^R"} {
		if !strings.Contains(out, want) {
			t.Fatalf("serving dashboard missing %q:\n%s", want, out)
		}
	}
	// No network/crypto identifiers on screen.
	for _, banned := range []string{"10.0.0", "sha256", "SHA256", "serial"} {
		if strings.Contains(out, banned) {
			t.Fatalf("dashboard leaked identifier %q:\n%s", banned, out)
		}
	}
}

func TestRenderDashboardMaintenanceAndDegraded(t *testing.T) {
	m := console.RenderDashboard(console.View{Maintenance: true, Version: "phase-1-dev"})
	if !strings.Contains(m, "MAINTENANCE") || !strings.Contains(m, "config apply") {
		t.Fatalf("maintenance screen wrong:\n%s", m)
	}
	if strings.Contains(m, "^R") {
		t.Fatalf("maintenance must not offer reset:\n%s", m)
	}
	d := console.RenderDashboard(console.View{Degraded: true, RootCN: "Interborough Root CA G1", Role: "ROOT"})
	if !strings.Contains(d, "degraded") {
		t.Fatalf("degraded screen missing marker:\n%s", d)
	}
}

func TestFleetLabel(t *testing.T) {
	cases := map[console.FleetState]string{
		console.FleetNotEnrolled: "not enrolled", console.FleetConnected: "connected", console.FleetDisconnected: "disconnected",
	}
	for st, want := range cases {
		out := console.RenderDashboard(console.View{Fleet: st, RootCN: "x", Role: "ROOT", NodeStatus: "ESTABLISHED", TPM: "SEALED"})
		if !strings.Contains(out, want) {
			t.Fatalf("fleet %v missing %q", st, want)
		}
	}
}
