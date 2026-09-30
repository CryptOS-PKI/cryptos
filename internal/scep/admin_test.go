package scep

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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"regexp"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func TestMintScepChallengeShape(t *testing.T) {
	f := newFixture(t)
	pw, ch := f.mint("cisco-device", 10*time.Minute, "SW1.Example.com.")
	if !regexp.MustCompile(`^[A-Z2-7]{32}$`).MatchString(pw) {
		t.Fatalf("challenge %q is not 32 base32 characters (160 bits, typeable at a device prompt)", pw)
	}
	if ch.GetProfile() != "cisco-device" || ch.GetCreatedByCn() != "admin.example.com" || ch.GetId() == "" {
		t.Fatalf("challenge = %v", ch)
	}
	if len(ch.GetBoundNames()) != 1 || ch.GetBoundNames()[0] != "sw1.example.com" {
		t.Fatalf("bound names = %v, want them normalized", ch.GetBoundNames())
	}
	if got := ch.GetExpiresAt().AsTime().Sub(ch.GetCreatedAt().AsTime()); got != 10*time.Minute {
		t.Fatalf("TTL = %s, want 10m", got)
	}
	pw2, _ := f.mint("cisco-device", 0)
	if pw2 == pw {
		t.Fatal("two mints returned the same challenge")
	}
	list, err := f.srv.ListScepChallenges(f.ctx, &cryptosv1.ListScepChallengesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetChallenges()) != 2 {
		t.Fatalf("listed %d challenges, want 2", len(list.GetChallenges()))
	}
	if list.GetChallenges()[0].GetId() != ch.GetId() {
		t.Fatal("the list is not soonest-to-expire first")
	}
	if d := list.GetChallenges()[1].GetExpiresAt().AsTime().Sub(list.GetChallenges()[1].GetCreatedAt().AsTime()); d != DefaultChallengeTTL {
		t.Fatalf("a zero TTL gave %s, want %s", d, DefaultChallengeTTL)
	}
}

func TestMintScepChallengeRejections(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name string
		req  *cryptosv1.MintScepChallengeRequest
	}{
		{"no profile with several configured", &cryptosv1.MintScepChallengeRequest{}},
		{"unknown profile", &cryptosv1.MintScepChallengeRequest{Profile: "nope"}},
		{"ttl over seven days", &cryptosv1.MintScepChallengeRequest{Profile: "cisco-device", TtlSeconds: 604801}},
		{"bound name outside the allowlist", &cryptosv1.MintScepChallengeRequest{Profile: "cisco-device", BoundNames: []string{"sw.example.org"}}},
		{"bound name that is an IP", &cryptosv1.MintScepChallengeRequest{Profile: "cisco-device", BoundNames: []string{"10.0.0.1"}}},
		{"bound wildcard", &cryptosv1.MintScepChallengeRequest{Profile: "cisco-device", BoundNames: []string{"*.example.com"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.srv.MintScepChallenge(f.ctx, tc.req, "admin"); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("MintScepChallenge = %v, want InvalidArgument", err)
			}
		})
	}
	if _, err := f.srv.MintScepChallenge(f.ctx, &cryptosv1.MintScepChallengeRequest{Profile: "cisco-device", TtlSeconds: 604800}, "admin"); err != nil {
		t.Fatalf("a seven-day TTL is the maximum and must pass: %v", err)
	}
}

func TestMintScepChallengeSingleProfileDefault(t *testing.T) {
	f := newFixtureWith(t, []Profile{{Name: "cisco-device", MinRSABits: 2048}})
	resp, err := f.srv.MintScepChallenge(f.ctx, &cryptosv1.MintScepChallengeRequest{}, "admin")
	if err != nil {
		t.Fatalf("MintScepChallenge with the only profile implied: %v", err)
	}
	if resp.GetChallenge().GetProfile() != "cisco-device" {
		t.Fatalf("profile = %q", resp.GetChallenge().GetProfile())
	}
}

func TestListAndRevokeSkipExpiredChallenges(t *testing.T) {
	f := newFixture(t)
	_, short := f.mint("cisco-device", time.Minute)
	_, long := f.mint("cisco-device", time.Hour)
	f.clock.advance(2 * time.Minute)
	list, _ := f.srv.ListScepChallenges(f.ctx, &cryptosv1.ListScepChallengesRequest{})
	if len(list.GetChallenges()) != 1 || list.GetChallenges()[0].GetId() != long.GetId() {
		t.Fatalf("list = %v, want only the unexpired challenge", list.GetChallenges())
	}
	if _, err := f.srv.RevokeScepChallenge(f.ctx, &cryptosv1.RevokeScepChallengeRequest{Id: short.GetId()}); status.Code(err) != codes.NotFound {
		t.Fatalf("revoking an expired challenge = %v, want NotFound", err)
	}
	if _, err := f.srv.RevokeScepChallenge(f.ctx, &cryptosv1.RevokeScepChallengeRequest{Id: long.GetId()}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := f.srv.RevokeScepChallenge(f.ctx, &cryptosv1.RevokeScepChallengeRequest{Id: long.GetId()}); status.Code(err) != codes.NotFound {
		t.Fatalf("revoking twice = %v, want NotFound", err)
	}
	if _, err := f.srv.RevokeScepChallenge(f.ctx, &cryptosv1.RevokeScepChallengeRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("revoking without an id = %v, want InvalidArgument", err)
	}
}

func TestQueueRPCsOnUnknownIDs(t *testing.T) {
	f := newFixture(t)
	if _, err := f.srv.ApproveScepEnrollment(f.ctx, &cryptosv1.ApproveScepEnrollmentRequest{Id: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("Approve unknown = %v", err)
	}
	if _, err := f.srv.RejectScepEnrollment(f.ctx, &cryptosv1.RejectScepEnrollmentRequest{Id: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("Reject unknown = %v", err)
	}
	if _, err := f.srv.ApproveScepEnrollment(f.ctx, &cryptosv1.ApproveScepEnrollmentRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Approve without an id = %v", err)
	}
}

func TestChallengePasswordAttribute(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sw.example.com"}, DNSNames: []string{"sw.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	parse := func(der []byte) string {
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("the test request does not verify: %v", err)
		}
		pw, err := challengePassword(csr)
		if err != nil {
			t.Fatalf("challengePassword: %v", err)
		}
		return pw
	}
	if pw := parse(plain); pw != "" {
		t.Fatalf("a request without the attribute gave %q", pw)
	}
	if pw := parse(withChallenge(t, plain, "ABCDEF234567", key)); pw != "ABCDEF234567" {
		t.Fatalf("challengePassword = %q", pw)
	}
	twice := withChallenge(t, withChallenge(t, plain, "ONE", key), "TWO", key)
	csr, _ := x509.ParseCertificateRequest(twice)
	if _, err := challengePassword(csr); err == nil {
		t.Fatal("two challengePassword attributes must be refused")
	}
}
