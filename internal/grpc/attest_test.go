package grpc

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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	stdgrpc "google.golang.org/grpc"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// fakeAttester is a fake Attester for the Attest handler tests.
type fakeAttester struct {
	gotNonce []byte
	sig      []byte
	pub      []byte
	err      error
}

func (f *fakeAttester) SignNonce(_ context.Context, nonce []byte) ([]byte, []byte, error) {
	f.gotNonce = nonce
	return f.sig, f.pub, f.err
}

// TestAttest_UnimplementedWhenNoAttester verifies that with a nil Attester
// (the maintenance servers) the RPC refuses with Unimplemented.
func TestAttest_UnimplementedWhenNoAttester(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.Attest(context.Background(), &cryptosv1.AttestRequest{Nonce: []byte("nonce")}); status.Code(err) != codes.Unimplemented {
		t.Errorf("Attest code = %v, want Unimplemented", status.Code(err))
	}
}

// TestAttest_LocalPassthrough verifies that with an Attester wired and a nil
// Trust (local, no peer) the handler passes the nonce through and maps the
// signature + identity public key fields onto the response.
func TestAttest_LocalPassthrough(t *testing.T) {
	att := &fakeAttester{sig: []byte("sig"), pub: []byte("pub")}
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
		Attester:  att,
		// Trust nil: not required for the local-passthrough path.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp, err := srv.Attest(context.Background(), &cryptosv1.AttestRequest{Nonce: []byte("nonce1")})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if string(att.gotNonce) != "nonce1" {
		t.Fatalf("attester got nonce=%q", att.gotNonce)
	}
	if string(resp.GetSignature()) != "sig" || string(resp.GetIdentityPubDer()) != "pub" {
		t.Fatalf("Attest response = %v", resp)
	}
}

// TestAttest_RejectsEmptyNonce verifies InvalidArgument for an empty nonce
// even with an Attester wired.
func TestAttest_RejectsEmptyNonce(t *testing.T) {
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
		Attester:  &fakeAttester{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.Attest(context.Background(), &cryptosv1.AttestRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("Attest(empty nonce) code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestAttest_MismatchIsPermissionDenied verifies that with a Trust pinned to
// one cert, a peer presenting a different cert is denied before the attester
// is consulted.
func TestAttest_MismatchIsPermissionDenied(t *testing.T) {
	att := &fakeAttester{sig: []byte("sig"), pub: []byte("pub")}
	trust := trustForCert(t, authzTestCert(t))
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
		Attester:  att,
		Trust:     trust,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := authzMTLSContext(authzTestCert(t)) // a different cert than the trust
	if _, err := srv.Attest(ctx, &cryptosv1.AttestRequest{Nonce: []byte("nonce")}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("Attest code = %v, want PermissionDenied", status.Code(err))
	}
	if att.gotNonce != nil {
		t.Fatalf("attester was consulted despite a denied caller")
	}
}

// TestAttestationMessage_KnownAnswer pins the exact bytes the node signs, so
// any verifier (the Fleet Manager) can be checked against the same vector.
func TestAttestationMessage_KnownAnswer(t *testing.T) {
	got := AttestationMessage([]byte{0xde, 0xad, 0xbe, 0xef})
	want := append([]byte("CryptOS-PKI attestation v1\x00"), 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef)
	if !bytes.Equal(got, want) {
		t.Fatalf("AttestationMessage = %x, want %x", got, want)
	}
}

// TestAttestationMessage_NeverDERSequence checks the signed message can't be
// read as the DER SEQUENCE every X.509 and OCSP to-be-signed body is, for any
// nonce, including one that is itself a DER SEQUENCE.
func TestAttestationMessage_NeverDERSequence(t *testing.T) {
	for _, nonce := range [][]byte{{0x00}, {0x30, 0x00}, bytes.Repeat([]byte{0x30}, 300)} {
		msg := AttestationMessage(nonce)
		var rv asn1.RawValue
		if _, err := asn1.Unmarshal(msg, &rv); err == nil && rv.Class == asn1.ClassUniversal && (rv.Tag == asn1.TagSequence || rv.Tag == asn1.TagSet) {
			t.Fatalf("AttestationMessage(%x) parses as a universal SEQUENCE/SET", nonce)
		}
		if msg[0] == 0x30 || msg[0] == 0x31 {
			t.Fatalf("AttestationMessage(%x) starts with DER SEQUENCE/SET tag 0x%02x", nonce, msg[0])
		}
	}
}

// TestAttest_AuditRecordsWhatWasAttested verifies the audit entry names the
// attestation context and identifies the nonce by length and SHA-256, without
// the nonce itself.
func TestAttest_AuditRecordsWhatWasAttested(t *testing.T) {
	auditor := &mockAuditor{}
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   auditor,
		Attester:  &fakeAttester{sig: []byte("sig"), pub: []byte("pub")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	nonce := []byte("fleet-manager-challenge-nonce")
	_, err = srv.unaryAudit(context.Background(), &cryptosv1.AttestRequest{Nonce: nonce},
		&stdgrpc.UnaryServerInfo{FullMethod: "/cryptos.v1.NodeService/Attest"},
		func(ctx context.Context, r interface{}) (interface{}, error) {
			return srv.Attest(ctx, r.(*cryptosv1.AttestRequest))
		})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	events := auditor.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	d := events[0].GetDetails()
	sum := sha256.Sum256(nonce)
	if d["attest_context"] != AttestationContext || d["nonce_bytes"] != "29" || d["nonce_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("audit details = %v", d)
	}
	for k, v := range d {
		if bytes.Contains([]byte(v), nonce) {
			t.Fatalf("audit detail %s carries the nonce", k)
		}
	}
}
