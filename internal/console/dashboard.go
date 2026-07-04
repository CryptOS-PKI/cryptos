package console

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
	"fmt"
	"strings"
	"time"
)

// clearHome resets the screen: clear (2J) then move the cursor home (H).
const clearHome = "\x1b[2J\x1b[H"

// frameWidth is the inner width (between the border bars) of the dashboard box.
const frameWidth = 56

// FleetState is the node's Fleet Manager relationship, shown on the dashboard.
type FleetState int

const (
	// FleetNotEnrolled means no Fleet Manager endpoint is configured.
	FleetNotEnrolled FleetState = iota
	// FleetConnected means the node is reaching its Fleet Manager.
	FleetConnected
	// FleetDisconnected means an endpoint is configured but unreachable.
	FleetDisconnected
)

// fleetLabel maps a FleetState to its short display string.
func fleetLabel(s FleetState) string {
	switch s {
	case FleetConnected:
		return "connected"
	case FleetDisconnected:
		return "disconnected"
	default:
		return "not enrolled"
	}
}

// View is the rendered dashboard's data. It carries only the approved field
// cut: operational status, never network or crypto identifiers.
type View struct {
	RootCN      string
	Role        string
	NodeStatus  string
	TPM         string
	Uptime      time.Duration
	Version     string
	Fleet       FleetState
	Maintenance bool
	Degraded    bool
}

// HumanUptime renders a duration in "3d 02h 14m" form.
func HumanUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d / (24 * time.Hour))
	rem := d % (24 * time.Hour)
	hours := int(rem / time.Hour)
	rem %= time.Hour
	mins := int(rem / time.Minute)
	return fmt.Sprintf("%dd %02dh %02dm", days, hours, mins)
}

// RenderDashboard returns the full framed screen: an ANSI clear + home prefix
// followed by the approved layout. The maintenance and degraded variants are
// keyed off v.Maintenance and v.Degraded; otherwise the serving frame is drawn.
func RenderDashboard(v View) string {
	if v.Maintenance {
		return renderMaintenance(v)
	}
	if v.Degraded {
		return renderDegraded(v)
	}
	return renderServing(v)
}

// border builds a full-width horizontal rule with the given end runes.
func border(left, fill, right string) string {
	return left + strings.Repeat(fill, frameWidth) + right
}

// row wraps inner content in the box side bars, padded to the frame width.
func row(inner string) string {
	if len(inner) > frameWidth {
		inner = inner[:frameWidth]
	}
	return "|" + inner + strings.Repeat(" ", frameWidth-len(inner)) + "|"
}

// header builds the top border with the "CryptOS PKI" wordmark and a role tag.
func header(role string) string {
	if role == "" {
		role = "NODE"
	}
	title := " CryptOS PKI "
	tag := " " + role + " "
	// ".<title padded with dashes>-<tag>."
	dashes := frameWidth - len(title) - len(tag)
	if dashes < 1 {
		dashes = 1
	}
	return "." + title + strings.Repeat("-", dashes) + tag + "."
}

// field builds a two-column "label value" content line.
func field(label, value string) string {
	return fmt.Sprintf("   %-15s %s", label, value)
}

// renderServing draws the live status dashboard.
func renderServing(v View) string {
	var b strings.Builder
	b.WriteString(clearHome)
	b.WriteString(header(v.Role) + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row("   "+v.RootCN) + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row(field("Node", v.NodeStatus)) + "\n")
	b.WriteString(row(field("Fleet Manager", fleetLabel(v.Fleet))) + "\n")
	b.WriteString(row(field("TPM", v.TPM)) + "\n")
	b.WriteString(row(field("Uptime", HumanUptime(v.Uptime))) + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(border(":", "-", ":") + "\n")
	b.WriteString(footer("  ^R  reset (destroys this CA)", "v "+v.Version) + "\n")
	b.WriteString(border("'", "-", "'") + "\n")
	return b.String()
}

// renderDegraded keeps the header but shows a degraded status line. The node is
// still serving, so the reset affordance is retained.
func renderDegraded(v View) string {
	var b strings.Builder
	b.WriteString(clearHome)
	b.WriteString(header(v.Role) + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row("   "+v.RootCN) + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row(field("Node", "degraded (reconnecting)")) + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(border(":", "-", ":") + "\n")
	b.WriteString(footer("  ^R  reset (destroys this CA)", "v "+v.Version) + "\n")
	b.WriteString(border("'", "-", "'") + "\n")
	return b.String()
}

// renderMaintenance draws the awaiting-configuration screen. No reset is offered.
func renderMaintenance(v View) string {
	var b strings.Builder
	b.WriteString(clearHome)
	b.WriteString(header("MAINTENANCE") + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row("   Awaiting configuration") + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row("   Run: cryptosctl config apply") + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(border(":", "-", ":") + "\n")
	b.WriteString(footer("  MAINTENANCE MODE", "v "+v.Version) + "\n")
	b.WriteString(border("'", "-", "'") + "\n")
	return b.String()
}

// footer builds the bottom content line with a left hint and a right-aligned tag.
func footer(left, right string) string {
	space := frameWidth - len(left) - len(right)
	if space < 1 {
		space = 1
	}
	return "|" + left + strings.Repeat(" ", space) + right + "|"
}
