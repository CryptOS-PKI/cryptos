package init

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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/revocation"
	"github.com/CryptOS-PKI/cryptos-node/internal/storage/etcd"
	"github.com/CryptOS-PKI/cryptos-node/internal/timesync"
)

func TestTimeSourceFor(t *testing.T) {
	cases := []struct {
		name        string
		configured  []string
		lease       string
		wantServers string
		wantSource  nodev1.TimeSource
	}{
		{"machine config wins over the lease", []string{"time.example.org"}, "192.0.2.1\n", "time.example.org", nodev1.TimeSource_TIME_SOURCE_MACHINE_CONFIG},
		{"lease when config is empty", nil, "192.0.2.1\n192.0.2.2\n", "192.0.2.1,192.0.2.2", nodev1.TimeSource_TIME_SOURCE_DHCP_LEASE},
		{"lease values are validated", nil, "192.0.2.1\n0.0.0.0\nnot-an-ip\n2001:db8::1\n224.0.1.1\n192.0.2.1\n", "192.0.2.1", nodev1.TimeSource_TIME_SOURCE_DHCP_LEASE},
		{"lease is capped at three", nil, "192.0.2.1\n192.0.2.2\n192.0.2.3\n192.0.2.4\n", "192.0.2.1,192.0.2.2,192.0.2.3", nodev1.TimeSource_TIME_SOURCE_DHCP_LEASE},
		{"lease with surrounding whitespace", nil, "  192.0.2.1  \n\n", "192.0.2.1", nodev1.TimeSource_TIME_SOURCE_DHCP_LEASE},
		{"neither", nil, "", "", nodev1.TimeSource_TIME_SOURCE_NONE},
		{"empty lease entries only", nil, "0.0.0.0\n", "", nodev1.TimeSource_TIME_SOURCE_NONE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			servers, src := timeSourceFor(config.Network{NTPServers: tc.configured}, []byte(tc.lease))
			if got := strings.Join(servers, ","); got != tc.wantServers || src != tc.wantSource {
				t.Fatalf("timeSourceFor = %q %v, want %q %v", got, src, tc.wantServers, tc.wantSource)
			}
		})
	}
}

// The option 42 file the kernel writes under ip=dhcp may be absent (no lease,
// or a kernel without it); that is "no lease", not an error.
func TestReadLease(t *testing.T) {
	dir := t.TempDir()
	if got, err := readLease(filepath.Join(dir, "missing")); err != nil || got != nil {
		t.Fatalf("missing lease file = %q, %v; want nothing and no error", got, err)
	}
	path := filepath.Join(dir, "ntp_servers")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if got, err := readLease(path); err != nil || string(got) != "192.0.2.1\n" {
		t.Fatalf("readLease = %q, %v", got, err)
	}
}

func TestParseBuildTime(t *testing.T) {
	if got := parseBuildTime("2026-09-25T00:00:00Z"); !got.Equal(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("parseBuildTime = %v", got)
	}
	if got := parseBuildTime("unknown"); !got.IsZero() {
		t.Fatalf("parseBuildTime(unknown) = %v, want zero", got)
	}
}

// unsyncedEngine is a time-sync engine with a configured source that has not
// synced: the signing gate is closed.
func unsyncedEngine(t *testing.T) *timesync.Engine {
	t.Helper()
	floor, err := timesync.OpenFloor(filepath.Join(t.TempDir(), clockFloorFile), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := timesync.New(timesync.Config{
		Servers: []string{"192.0.2.1"},
		Source:  nodev1.TimeSource_TIME_SOURCE_MACHINE_CONFIG,
		Clock:   timesync.SystemClock(),
		Floor:   floor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.SignAllowed() {
		t.Fatal("an unsynced engine must close the gate")
	}
	return e
}

// gateFixture is a soft CA behind a clock-gated signer, plus a revoker over
// the same CA key loader.
type gateFixture struct {
	signer    *node.CASigner
	revoker   *nodeRevoker
	responder *ocspResponder
	ctx       context.Context
}

func newGateFixture(t *testing.T, e *timesync.Engine) gateFixture {
	t.Helper()
	f, responder, ctx := newOCSPResponderFixture(t, 0)
	load := func(context.Context) (crypto.Signer, func(), error) { return f.caKey, func() {}, nil }
	issuer := func(context.Context) (*x509.Certificate, error) { return f.issuer, nil }
	cfg := &config.Config{PKI: config.PKI{Profiles: []config.CertificateProfile{{
		Name: "leaf", KeyAlg: config.RootKeyECDSAP384, ValidityDays: 30,
		KeyUsage: []string{"digital_signature"}, ExtKeyUsage: []string{"server_auth"},
		SANs: config.SubjectAltNames{DNS: []string{"leaf.example.org"}},
	}}}}
	signer := wireClockGate(node.NewCASigner(load, issuer, func(context.Context) (*config.Config, error) { return cfg, nil }), e)

	srv, err := etcd.Open(t.TempDir())
	if err != nil {
		t.Fatalf("etcd.Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("etcd.Client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	revStore := revocation.NewStore(cli)
	r := &nodeRevoker{store: revStore, crlBuilder: revocation.NewCRLBuilder(revStore, time.Hour), load: load, issuer: issuer}
	return gateFixture{signer: signer, revoker: r, responder: responder, ctx: ctx}
}

func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.org"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// With the clock unsynced the gate refuses certificate signing, but CRL and
// OCSP generation, which share the same CA key loader, keep working: a
// stale-looking CRL is better than none, and revocation must keep flowing.
func TestClockGateNeverGatesCRLOrOCSP(t *testing.T) {
	g := newGateFixture(t, unsyncedEngine(t))
	_, err := g.signer.IssueLeaf(g.ctx, testCSR(t), "leaf")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("IssueLeaf on an unsynced clock = %v, want FailedPrecondition", err)
	}
	der, err := g.revoker.buildCRL(g.ctx)
	if err != nil {
		t.Fatalf("buildCRL on an unsynced clock: %v", err)
	}
	if _, err := x509.ParseRevocationList(der); err != nil {
		t.Fatalf("CRL does not parse: %v", err)
	}
	if _, _, err := g.responder.ensure(g.ctx); err != nil {
		t.Fatalf("OCSP responder on an unsynced clock: %v", err)
	}
}

// With no time source the gate never closes, and every certificate issued
// raises the clock floor.
func TestClockGateOpensWithNoTimeSource(t *testing.T) {
	floor, err := timesync.OpenFloor(filepath.Join(t.TempDir(), clockFloorFile), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := timesync.New(timesync.Config{Clock: timesync.SystemClock(), Floor: floor})
	if err != nil {
		t.Fatal(err)
	}
	g := newGateFixture(t, e)
	before := floor.Get()
	if _, err := g.signer.IssueLeaf(g.ctx, testCSR(t), "leaf"); err != nil {
		t.Fatalf("IssueLeaf with no time source: %v", err)
	}
	if !floor.Get().After(before) {
		t.Fatal("issuing did not raise the clock floor")
	}
}
