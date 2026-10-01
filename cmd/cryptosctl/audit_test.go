package main

/*
Copyright The CryptOS Authors.

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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/audit"
	"github.com/CryptOS-PKI/cryptos-node/internal/bootstrap"
	cgrpc "github.com/CryptOS-PKI/cryptos-node/internal/grpc"
)

var auditT0 = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

// auditLogWith writes the given (method, actor) entries a minute apart and
// returns the log and its directory.
func auditLogWith(t *testing.T, entries ...[2]string) (*audit.Logger, string) {
	t.Helper()
	seed := make([]byte, audit.SeedLength)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dir := t.TempDir()
	log, err := audit.Open(dir, seed)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i, e := range entries {
		ev := &nodev1.AuditEvent{
			RpcMethod:    "/cryptos.node.v1.NodeService/" + e[0],
			ActorSubject: e[1],
			Outcome:      nodev1.Outcome_OUTCOME_OK,
			Ts:           timestamppb.New(auditT0.Add(time.Duration(i) * time.Minute)),
		}
		if e[0] == "RevokeCertificate" {
			ev.Details = map[string]string{audit.DetailSerial: "1a2b"}
		}
		if err := log.Append(ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	return log, dir
}

func startAuditServer(t *testing.T, log cgrpc.AuditLog) *testServer {
	t.Helper()
	return startTestServerWith(t, func(cfg *cgrpc.ServerConfig, clientCert *x509.Certificate) {
		cfg.AuditLog = log
		fp := sha256.Sum256(clientCert.Raw)
		trust, err := bootstrap.LoadTrust("", hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatalf("LoadTrust: %v", err)
		}
		cfg.Trust = trust
	})
}

var sampleAuditEntries = [][2]string{
	{"StartCeremony", "CN=admin,O=Example"},
	{"ApplyConfig", "CN=admin,O=Example"},
	{"IssueLeaf", "CN=operator-a,O=Example"},
	{"RevokeCertificate", "CN=operator-a,O=Example"},
	{"ExportCAKey", "CN=admin,O=Example"},
	{"Reboot", "CN=admin,O=Example"},
}

func TestAuditList_HumanTable(t *testing.T) {
	log, _ := auditLogWith(t, sampleAuditEntries...)
	ts := startAuditServer(t, log)
	out, err := ts.run(t, "audit", "list")
	if err != nil {
		t.Fatalf("audit list: %v (out=%s)", err, out)
	}
	for _, want := range []string{
		"SEQ", "TIME", "ACTOR", "EVENT", "OUTCOME", "SUMMARY",
		"2026-06-03T12:00:00Z", "StartCeremony", "ran the first-boot ceremony",
		"ApplyConfig", "IssueLeaf", "CN=operator-a,O=Example",
		"RevokeCertificate", "revoked a certificate: 1a2b",
		"ExportCAKey", "Reboot", "ok",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("audit list output is missing %q:\n%s", want, out)
		}
	}
}

func TestAuditList_Filters(t *testing.T) {
	log, _ := auditLogWith(t, sampleAuditEntries...)
	ts := startAuditServer(t, log)
	out, err := ts.run(t, "audit", "list", "--type", "RevokeCertificate", "--actor", "operator-a",
		"--since", auditT0.Format(time.RFC3339), "--until", auditT0.Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("audit list: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "RevokeCertificate") || strings.Contains(out, "IssueLeaf") || strings.Contains(out, "StartCeremony") {
		t.Errorf("filtered list = \n%s\nwant only the revocation", out)
	}
}

// A mistyped --type is an error, not an empty listing.
func TestAuditList_UnknownTypeIsAnError(t *testing.T) {
	log, _ := auditLogWith(t, sampleAuditEntries...)
	ts := startAuditServer(t, log)
	out, err := ts.run(t, "audit", "list", "--type", "RevokeCert")
	if err == nil || !strings.Contains(err.Error(), "RevokeCert") || strings.Contains(out, "(no audit entries)") {
		t.Fatalf("audit list --type RevokeCert: err %v, out %q; want an error naming the type", err, out)
	}
	for _, typ := range []string{"RevokeCertificate", "/cryptos.node.v1.NodeService/RevokeCertificate"} {
		out, err := ts.run(t, "audit", "list", "--type", typ)
		if err != nil || !strings.Contains(out, "revoked a certificate") {
			t.Errorf("audit list --type %s: err %v, out %q; want the revocation", typ, err, out)
		}
	}
}

func TestAuditList_PagingFlags(t *testing.T) {
	log, _ := auditLogWith(t, sampleAuditEntries...)
	ts := startAuditServer(t, log)

	out, err := ts.run(t, "-o", "json", "audit", "list", "--page-size", "2")
	if err != nil {
		t.Fatalf("audit list: %v (out=%s)", err, out)
	}
	var page struct {
		Entries []struct {
			Event struct {
				Seq string `json:"seq"`
			} `json:"event"`
			Summary string `json:"summary"`
		} `json:"entries"`
		NextPageToken string `json:"next_page_token"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("-o json is not JSON: %v (out=%s)", err, out)
	}
	if len(page.Entries) != 2 || page.NextPageToken == "" {
		t.Fatalf("first page = %d entries, token %q; want 2 and a token", len(page.Entries), page.NextPageToken)
	}

	out, err = ts.run(t, "-o", "json", "audit", "list", "--page-size", "2", "--page-token", page.NextPageToken)
	if err != nil {
		t.Fatalf("audit list --page-token: %v (out=%s)", err, out)
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("-o json is not JSON: %v", err)
	}
	if len(page.Entries) != 2 || page.Entries[0].Event.Seq != "3" {
		t.Fatalf("second page = %+v, want seqs 3 and 4", page.Entries)
	}

	out, err = ts.run(t, "-o", "json", "audit", "list", "--page-size", "2", "--all")
	if err != nil {
		t.Fatalf("audit list --all: %v (out=%s)", err, out)
	}
	page.NextPageToken = ""
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("-o json is not JSON: %v", err)
	}
	if len(page.Entries) != len(sampleAuditEntries) || page.NextPageToken != "" {
		t.Fatalf("--all = %d entries, token %q; want every entry and no token", len(page.Entries), page.NextPageToken)
	}

	// Human output points at the next page.
	out, err = ts.run(t, "audit", "list", "--page-size", "2")
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if !strings.Contains(out, "--page-token") {
		t.Errorf("a partial human listing does not say how to get the next page:\n%s", out)
	}
}

func TestAuditList_YAML(t *testing.T) {
	log, _ := auditLogWith(t, sampleAuditEntries[:2]...)
	ts := startAuditServer(t, log)
	out, err := ts.run(t, "-o", "yaml", "audit", "list")
	if err != nil {
		t.Fatalf("audit list -o yaml: %v (out=%s)", err, out)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("-o yaml is not YAML: %v (out=%s)", err, out)
	}
	if entries, ok := doc["entries"].([]any); !ok || len(entries) != 2 {
		t.Fatalf("-o yaml entries = %v, want 2", doc["entries"])
	}
}

func TestAuditList_RejectsABadTime(t *testing.T) {
	log, _ := auditLogWith(t, sampleAuditEntries[:1]...)
	ts := startAuditServer(t, log)
	if out, err := ts.run(t, "audit", "list", "--since", "last tuesday"); err == nil {
		t.Fatalf("audit list accepted --since 'last tuesday': %s", out)
	}
}

func TestAuditVerify_Intact(t *testing.T) {
	log, _ := auditLogWith(t, sampleAuditEntries...)
	ts := startAuditServer(t, log)
	out, err := ts.run(t, "audit", "verify")
	if err != nil {
		t.Fatalf("audit verify on an intact log: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "intact") || !strings.Contains(out, "6 entries") {
		t.Errorf("audit verify output = %q, want it to report an intact chain of 6 entries", out)
	}
}

func TestAuditVerify_BrokenChainFails(t *testing.T) {
	log, dir := auditLogWith(t, sampleAuditEntries...)
	files, err := filepath.Glob(filepath.Join(dir, "*.log"))
	if err != nil || len(files) != 1 {
		t.Fatalf("log files %v err %v", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	lines[3] = strings.Replace(lines[3], "operator-a", "operator-z", 1)
	if err := os.WriteFile(files[0], []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ts := startAuditServer(t, log)

	out, err := ts.run(t, "audit", "verify")
	if err == nil {
		t.Fatalf("audit verify succeeded on a tampered log: %s", out)
	}
	if !strings.Contains(out+err.Error(), "4") || !strings.Contains(out, "broken") {
		t.Errorf("audit verify output = %q, err %v; want it to report the chain broken at seq 4", out, err)
	}

	out, err = ts.run(t, "-o", "json", "audit", "verify")
	if err == nil {
		t.Fatal("audit verify -o json succeeded on a tampered log")
	}
	jsonPart := out[:strings.LastIndex(out, "}")+1]
	var doc map[string]any
	if jerr := json.Unmarshal([]byte(jsonPart), &doc); jerr != nil {
		t.Fatalf("-o json is not JSON: %v (out=%s)", jerr, out)
	}
	if doc["first_broken_sequence"] != "4" || doc["intact"] == true {
		t.Errorf("-o json = %v, want first_broken_sequence 4 and not intact", doc)
	}
}
