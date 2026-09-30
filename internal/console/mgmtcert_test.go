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
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos/internal/console"
)

func TestFingerprintGroupsUppercaseHex(t *testing.T) {
	der := []byte("any certificate bytes")
	sum := sha256.Sum256(der)
	got := console.Fingerprint(der)

	groups := strings.Split(got, " ")
	if len(groups) != 16 {
		t.Fatalf("Fingerprint = %q, want 16 space-separated groups", got)
	}
	if want := strings.ToUpper(hex.EncodeToString(sum[:])); strings.Join(groups, "") != want {
		t.Fatalf("Fingerprint = %q, want the SHA-256 %s", got, want)
	}
}

func TestManagementFingerprintReadsTheCertFile(t *testing.T) {
	certPEM := leafPEM(t, "192.0.2.10")
	block, _ := pem.Decode([]byte(certPEM))
	path := filepath.Join(t.TempDir(), "mgmt.crt")
	if err := os.WriteFile(path, []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	if got, want := console.ManagementFingerprint(path), console.Fingerprint(block.Bytes); got != want {
		t.Fatalf("ManagementFingerprint = %q, want %q", got, want)
	}
}

// A missing or unreadable file means the node has not published its
// certificate yet; the dashboard shows nothing rather than a wrong value.
func TestManagementFingerprintEmptyWithoutAValidCert(t *testing.T) {
	dir := t.TempDir()
	if got := console.ManagementFingerprint(filepath.Join(dir, "absent.crt")); got != "" {
		t.Fatalf("missing file: got %q, want empty", got)
	}
	junk := filepath.Join(dir, "junk.crt")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := console.ManagementFingerprint(junk); got != "" {
		t.Fatalf("junk file: got %q, want empty", got)
	}
}

func servingView(fp string) console.View {
	return console.View{
		RootCN: "ACME Root CA G1", Role: "ROOT", NodeStatus: "ESTABLISHED",
		TPM: "SEALED", Uptime: time.Hour, Version: "1.0", Fleet: console.FleetConnected,
		MgmtFingerprint: fp,
	}
}

func TestRenderDashboardShowsTheManagementFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	groups := strings.Split(fp, " ")

	for _, size := range []struct{ cols, rows int }{{64, 24}, {40, 24}, {80, 30}} {
		lines := screenLines(console.RenderDashboard(servingView(fp), size.cols, size.rows))
		plain := strings.Join(lines, "\n")
		if !strings.Contains(plain, "Mgmt SHA-256") {
			t.Fatalf("%dx%d: no management cert label:\n%s", size.cols, size.rows, plain)
		}
		// The fingerprint wraps across lines, but every group is shown in order.
		var seen []string
		for _, f := range strings.Fields(plain) {
			if len(seen) < len(groups) && f == groups[len(seen)] {
				seen = append(seen, f)
			}
		}
		if len(seen) != len(groups) {
			t.Fatalf("%dx%d: fingerprint groups missing (saw %d of %d):\n%s", size.cols, size.rows, len(seen), len(groups), plain)
		}
		if len(lines) != size.rows {
			t.Fatalf("%dx%d: frame has %d lines", size.cols, size.rows, len(lines))
		}
		for i, ln := range lines {
			if len(ln) != size.cols {
				t.Fatalf("%dx%d: line %d is %d wide: %q", size.cols, size.rows, i, len(ln), ln)
			}
		}
	}
}

func TestRenderCompactShowsTheManagementFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	plain := stripSGR(console.RenderDashboard(servingView(fp), 30, 10))
	if !strings.Contains(plain, "Mgmt SHA-256") || !strings.Contains(plain, strings.Split(fp, " ")[15]) {
		t.Fatalf("compact render missing the fingerprint:\n%s", plain)
	}
}

func TestRenderDashboardOmitsFingerprintWhenUnknownOrNotServing(t *testing.T) {
	if plain := stripSGR(console.RenderDashboard(servingView(""), 64, 24)); strings.Contains(plain, "Mgmt SHA-256") {
		t.Fatalf("label shown with no fingerprint:\n%s", plain)
	}
	fp := console.Fingerprint([]byte("mgmt cert"))
	for _, v := range []console.View{
		{Maintenance: true, MgmtFingerprint: fp},
		{Degraded: true, RootCN: "ACME Root CA G1", Role: "ROOT", MgmtFingerprint: fp},
	} {
		if plain := stripSGR(console.RenderDashboard(v, 64, 24)); strings.Contains(plain, "Mgmt SHA-256") {
			t.Fatalf("fingerprint shown outside the serving frame:\n%s", plain)
		}
	}
}

// awaitingCeremonyView is an installed Root node that has not run its
// ceremony yet.
func awaitingCeremonyView(fp string) console.View {
	return console.View{
		Role: "ROOT", NodeStatus: "maintenance", TPM: "SEALED", Version: "1.0",
		Maintenance: true, AwaitingCeremony: true, MgmtFingerprint: fp,
	}
}

// fingerprintBlock returns the rendered lines from the "Mgmt SHA-256" label
// through the last fingerprint group, trimmed of the frame and centering.
func fingerprintBlock(lines []string, lastGroup string) []string {
	var block []string
	for _, ln := range lines {
		ln = strings.Trim(ln, "| ")
		if len(block) == 0 && !strings.HasPrefix(ln, "Mgmt SHA-256") {
			continue
		}
		block = append(block, ln)
		if strings.HasSuffix(ln, lastGroup) {
			break
		}
	}
	return block
}

func TestRenderDashboardAwaitingCeremonyShowsTheFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	groups := strings.Split(fp, " ")
	last := groups[len(groups)-1]

	for _, size := range []struct{ cols, rows int }{{64, 24}, {40, 24}, {80, 30}} {
		lines := screenLines(console.RenderDashboard(awaitingCeremonyView(fp), size.cols, size.rows))
		plain := strings.Join(lines, "\n")

		got := fingerprintBlock(lines, last)
		want := fingerprintBlock(screenLines(console.RenderDashboard(servingView(fp), size.cols, size.rows)), last)
		if len(got) == 0 || strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%dx%d: fingerprint not shown as after the ceremony:\ngot:\n%s\nwant:\n%s\nscreen:\n%s",
				size.cols, size.rows, strings.Join(got, "\n"), strings.Join(want, "\n"), plain)
		}
		if !strings.Contains(plain, "Fetch trust, then start the ceremony") {
			t.Fatalf("%dx%d: no next-step hint:\n%s", size.cols, size.rows, plain)
		}
		if strings.Contains(plain, "config apply") {
			t.Fatalf("%dx%d: installed node told to apply a config:\n%s", size.cols, size.rows, plain)
		}
		if strings.Contains(plain, "^R") {
			t.Fatalf("%dx%d: a node with no CA must not offer reset:\n%s", size.cols, size.rows, plain)
		}
		if len(lines) != size.rows {
			t.Fatalf("%dx%d: frame has %d lines", size.cols, size.rows, len(lines))
		}
		for i, ln := range lines {
			if len(ln) != size.cols {
				t.Fatalf("%dx%d: line %d is %d wide: %q", size.cols, size.rows, i, len(ln), ln)
			}
		}
	}
}

func TestRenderCompactAwaitingCeremonyShowsTheFingerprint(t *testing.T) {
	fp := console.Fingerprint([]byte("mgmt cert"))
	plain := stripSGR(console.RenderDashboard(awaitingCeremonyView(fp), 30, 10))
	for _, want := range []string{"Mgmt SHA-256", strings.Split(fp, " ")[15], "Fetch trust, then start the ceremony"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("compact render missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "config apply") || strings.Contains(plain, "^R") {
		t.Fatalf("compact render shows the wrong hint:\n%s", plain)
	}
}
