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

import "strings"

// ConfirmState is the pure state machine behind the reset confirmation prompt.
// It accumulates the operator's typed Root CN and reports when a line is
// submitted. It holds no terminal or transport state, so it is fully
// unit-testable without a tty.
type ConfirmState struct {
	// Typed is the operator-entered text so far.
	Typed string
}

// Key feeds one input byte into the state machine and reports whether the line
// was submitted (Enter). Printable bytes are appended; backspace/delete trims
// the last byte; CR or LF submits. Any other control byte is ignored so a
// stray escape sequence cannot corrupt the buffer.
func (c *ConfirmState) Key(b byte) (submit bool) {
	switch {
	case b == '\r' || b == '\n':
		return true
	case b == 0x7f || b == 0x08: // DEL or BS
		if len(c.Typed) > 0 {
			c.Typed = c.Typed[:len(c.Typed)-1]
		}
		return false
	case b >= 0x20 && b < 0x7f: // printable ASCII
		c.Typed += string(b)
		return false
	default:
		return false
	}
}

// RenderResetConfirm returns the destructive-reset confirmation screen: an ANSI
// clear+home, a prominent warning that the reset erases the CA, the exact Root
// CN the operator must retype, and the buffer typed so far. Esc or ^C aborts
// back to the dashboard, so the footer names both.
func RenderResetConfirm(rootCN, typed string) string {
	var b strings.Builder
	b.WriteString(clearHome)
	b.WriteString(header("RESET") + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row("   WARNING: this DESTROYS this CA.") + "\n")
	b.WriteString(row("   The signing key material is erased") + "\n")
	b.WriteString(row("   and the node reboots to be re-set up.") + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row("   Type the Root CA CN to confirm:") + "\n")
	b.WriteString(row("   "+rootCN) + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row("   > "+typed) + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(border(":", "-", ":") + "\n")
	b.WriteString(footer("  Enter confirm    Esc/^C cancel", "") + "\n")
	b.WriteString(border("'", "-", "'") + "\n")
	return b.String()
}

// RenderResetting returns the screen shown once a Reset call succeeds. The node
// wipes and reboots, so the socket connection drops moments later.
func RenderResetting() string {
	var b strings.Builder
	b.WriteString(clearHome)
	b.WriteString(header("RESET") + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(row("   Resetting. Erasing key material") + "\n")
	b.WriteString(row("   and rebooting into setup...") + "\n")
	b.WriteString(row("") + "\n")
	b.WriteString(border(":", "-", ":") + "\n")
	b.WriteString(footer("  RESET IN PROGRESS", "") + "\n")
	b.WriteString(border("'", "-", "'") + "\n")
	return b.String()
}
