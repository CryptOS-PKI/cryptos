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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/status"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/cms"
)

func get(t *testing.T, f *fixture, query string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(f.http.URL + PathPKIClient + "?" + query)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func TestGetCACapsAdvertisesOnlyWhatIsImplemented(t *testing.T) {
	f := newFixture(t)
	resp, body := get(t, f, "operation=GetCACaps")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("GetCACaps: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	got := strings.Fields(string(body))
	want := []string{"AES", "POSTPKIOperation", "Renewal", "SHA-256", "SHA-512"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	for _, refused := range []string{"DES3", "SHA-1", "GetNextCACert", "SCEPStandard"} {
		if strings.Contains(string(body), refused) {
			t.Fatalf("capabilities advertise %s, which is not implemented", refused)
		}
	}
}

func TestGetCACertReturnsTheCAAndTheRA(t *testing.T) {
	f := newFixture(t)
	resp, body := get(t, f, "operation=GetCACert")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCACert: %d %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-x509-ca-ra-cert" {
		t.Fatalf("Content-Type = %q", ct)
	}
	sd, err := cms.ParseSignedData(body)
	if err != nil {
		t.Fatalf("GetCACert body: %v", err)
	}
	if len(sd.Certificates) != 2 || len(sd.SignerInfos) != 0 {
		t.Fatalf("GetCACert carries %d certificates and %d signers, want 2 and 0", len(sd.Certificates), len(sd.SignerInfos))
	}
	caCert, _ := x509.ParseCertificate(sd.Certificates[0])
	ra, _ := x509.ParseCertificate(sd.Certificates[1])
	if !caCert.Equal(f.ca.cert) {
		t.Fatal("the first certificate is not the CA")
	}
	if ra.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment || ra.IsCA {
		t.Fatalf("RA key usage = %v, IsCA = %t", ra.KeyUsage, ra.IsCA)
	}
	if k, ok := ra.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 3072 {
		t.Fatalf("RA key = %T, want RSA 3072", ra.PublicKey)
	}
	if err := ra.CheckSignatureFrom(f.ca.cert); err != nil {
		t.Fatalf("the RA is not issued by the CA: %v", err)
	}
}

func TestUnknownAndMissingOperations(t *testing.T) {
	f := newFixture(t)
	for q, want := range map[string]int{
		"":                        http.StatusBadRequest,
		"operation=Nope":          http.StatusBadRequest,
		"operation=GetNextCACert": http.StatusNotImplemented,
		"operation=PKIOperation":  http.StatusBadRequest,
	} {
		if resp, _ := get(t, f, q); resp.StatusCode != want {
			t.Errorf("GET ?%s = %d, want %d", q, resp.StatusCode, want)
		}
	}
	resp, err := http.Post(f.http.URL+PathSCEP+"?operation=PKIOperation", contentTypePKIMessage, strings.NewReader("not a pkiMessage"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a malformed message = %d, want 400", resp.StatusCode)
	}
}

func TestPKCSReqIssuesWithAOneTimeChallenge(t *testing.T) {
	f := newFixture(t)
	pw, ch := f.mint("cisco-device", time.Hour)
	d := newDevice(t, 2048)

	rep := f.enrol(t, d, "tx-issue", pw, "switch01.example.com")
	wantStatus(t, rep, StatusSuccess)
	if len(rep.certs) != 1 {
		t.Fatalf("SUCCESS carries %d certificates, want the issued one", len(rep.certs))
	}
	leaf := rep.certs[0]
	if !leaf.PublicKey.(*rsa.PublicKey).Equal(&d.key.PublicKey) {
		t.Fatal("the issued certificate is not for the device key")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "switch01.example.com" {
		t.Fatalf("SANs = %v, want the subject name", leaf.DNSNames)
	}
	if rep.txID != "tx-issue" {
		t.Fatalf("transactionID echo = %q", rep.txID)
	}
	if !rep.signer.Equal(f.raCert()) {
		t.Fatal("the CertRep is not signed by the RA")
	}

	listed, err := f.srv.ListScepChallenges(f.ctx, &nodev1.ListScepChallengesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.GetChallenges()) != 0 {
		t.Fatal("a consumed challenge is still listed")
	}

	ev := f.audit.last()
	if ev.GetRpcMethod() != "scep/PKCSReq" || ev.GetDetails()["challenge_id"] != ch.GetId() ||
		ev.GetDetails()["serial_hex"] != leaf.SerialNumber.Text(16) || ev.GetDetails()["profile"] != "cisco-device" {
		t.Fatalf("audit entry = %v", ev)
	}
	if strings.Contains(ev.String(), pw) || strings.Contains(f.logText(), pw) {
		t.Fatal("the challenge password reached the audit log or the logs")
	}
}

func TestPKCSReqOverGET(t *testing.T) {
	f := newFixture(t)
	pw, _ := f.mint("cisco-device", time.Hour)
	d := newDevice(t, 2048)
	msg := f.message(t, MessageTypePKCSReq, d.csr(t, "ap1.example.com", nil, pw), msgOpts{signer: d.cert, signerKey: d.key, txID: "tx-get"})
	resp, body := get(t, f, "operation=PKIOperation&message="+url.QueryEscape(base64.StdEncoding.EncodeToString(msg)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET PKIOperation: %d %s", resp.StatusCode, body)
	}
	wantStatus(t, parseCertRep(t, body, d.key, d.cert), StatusSuccess)
}

func TestPKCSReqChallengeFailures(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t, 2048)

	t.Run("no challenge", func(t *testing.T) {
		wantFailure(t, f.enrol(t, d, "tx-none", "", "sw.example.com"), FailBadRequest)
	})
	t.Run("never minted", func(t *testing.T) {
		wantFailure(t, f.enrol(t, d, "tx-bogus", "NOTAREALCHALLENGE", "sw.example.com"), FailBadRequest)
	})
	t.Run("reused", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour)
		wantStatus(t, f.enrol(t, d, "tx-first", pw, "sw1.example.com"), StatusSuccess)
		other := newDevice(t, 2048)
		wantFailure(t, f.enrol(t, other, "tx-second", pw, "sw2.example.com"), FailBadRequest)
	})
	t.Run("expired", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour)
		f.clock.advance(time.Hour + time.Second)
		defer f.clock.advance(-time.Hour - time.Second)
		wantFailure(t, f.enrol(t, newDevice(t, 2048), "tx-expired", pw, "sw3.example.com"), FailBadRequest)
	})
	t.Run("revoked", func(t *testing.T) {
		pw, ch := f.mint("cisco-device", time.Hour)
		if _, err := f.srv.RevokeScepChallenge(f.ctx, &nodev1.RevokeScepChallengeRequest{Id: ch.GetId()}); err != nil {
			t.Fatal(err)
		}
		wantFailure(t, f.enrol(t, newDevice(t, 2048), "tx-revoked", pw, "sw4.example.com"), FailBadRequest)
	})
}

// A failed request is forgotten, so the same device (and the same
// transactionID, which clients derive from the key) can try again once the
// operator mints a fresh challenge.
func TestPKCSReqFailureIsNotRemembered(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t, 2048)
	wantFailure(t, f.enrol(t, d, "tx-retry", "WRONG", "sw.example.com"), FailBadRequest)
	pw, _ := f.mint("cisco-device", time.Hour)
	wantStatus(t, f.enrol(t, d, "tx-retry", pw, "sw.example.com"), StatusSuccess)
}

func TestPKCSReqNamePolicy(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name  string
		bound []string
		cn    string
		dns   []string
	}{
		{"outside the allowlist", nil, "sw.example.org", nil},
		{"a SAN outside the allowlist", nil, "sw.example.com", []string{"sw.evil.test"}},
		{"a suffix look-alike", nil, "sw.badexample.com", nil},
		{"not a hostname", nil, "switch01", nil},
		{"a wildcard", nil, "*.example.com", nil},
		{"outside the bound names", []string{"sw1.example.com"}, "sw2.example.com", nil},
		{"one SAN outside the bound names", []string{"sw1.example.com"}, "sw1.example.com", []string{"sw9.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pw, _ := f.mint("cisco-device", time.Hour, tc.bound...)
			wantFailure(t, f.enrol(t, newDevice(t, 2048), "tx-"+tc.name, pw, tc.cn, tc.dns...), FailBadRequest)
		})
	}
	t.Run("inside the bound names", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour, "sw1.example.com", "sw1-mgmt.example.com")
		wantStatus(t, f.enrol(t, newDevice(t, 2048), "tx-bound-ok", pw, "sw1.example.com", "sw1-mgmt.example.com"), StatusSuccess)
	})
}

func TestPKCSReqIPSANIsRefused(t *testing.T) {
	f := newFixture(t)
	pw, _ := f.mint("cisco-device", time.Hour)
	d := newDevice(t, 2048)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkixName("sw.example.com"), IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)}, SignatureAlgorithm: x509.SHA256WithRSA,
	}, d.key)
	if err != nil {
		t.Fatal(err)
	}
	msg := f.message(t, MessageTypePKCSReq, withChallenge(t, der, pw, d.key), msgOpts{signer: d.cert, signerKey: d.key, txID: "tx-ip"})
	wantFailure(t, f.post(t, msg, d.key, d.cert), FailBadRequest)
}

func TestPKCSReqKeyFloorPerProfile(t *testing.T) {
	f := newFixture(t)
	t.Run("2048 on the default-floor profile", func(t *testing.T) {
		pw, _ := f.mint("strict-device", time.Hour)
		wantFailure(t, f.enrol(t, newDevice(t, 2048), "tx-2048-strict", pw, "mdm1.example.com"), FailBadRequest)
	})
	t.Run("3072 on the default-floor profile", func(t *testing.T) {
		pw, _ := f.mint("strict-device", time.Hour)
		wantStatus(t, f.enrol(t, newDevice(t, 3072), "tx-3072-strict", pw, "mdm2.example.com"), StatusSuccess)
	})
	t.Run("3072 on the 2048 profile", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour)
		wantStatus(t, f.enrol(t, newDevice(t, 3072), "tx-3072-cisco", pw, "sw5.example.com"), StatusSuccess)
	})
	t.Run("1024 anywhere", func(t *testing.T) {
		pw, _ := f.mint("cisco-device", time.Hour)
		wantFailure(t, f.enrol(t, newDevice(t, 1024), "tx-1024", pw, "sw6.example.com"), FailBadRequest)
	})
}

func TestPKCSReqRetransmitIsIdempotent(t *testing.T) {
	f := newFixture(t)
	pw, _ := f.mint("cisco-device", time.Hour)
	d := newDevice(t, 2048)
	msg := f.message(t, MessageTypePKCSReq, d.csr(t, "sw.example.com", nil, pw), msgOpts{signer: d.cert, signerKey: d.key, txID: "tx-again"})

	first := f.post(t, msg, d.key, d.cert)
	wantStatus(t, first, StatusSuccess)
	second := f.post(t, msg, d.key, d.cert)
	wantStatus(t, second, StatusSuccess)
	if !first.certs[0].Equal(second.certs[0]) {
		t.Fatal("a retransmitted PKCSReq was issued a second certificate")
	}
	if len(f.ca.issued) != 1 {
		t.Fatalf("the CA issued %d certificates for one transaction", len(f.ca.issued))
	}

	thief := newDevice(t, 2048)
	pw2, _ := f.mint("cisco-device", time.Hour)
	wantFailure(t, f.enrol(t, thief, "tx-again", pw2, "sw.example.com"), FailBadRequest)
}

func TestPKCSReqPendingThenApproved(t *testing.T) {
	f := newFixture(t)
	pw, ch := f.mint("approved-device", time.Hour, "sw7.example.com")
	d := newDevice(t, 2048)
	wantStatus(t, f.enrol(t, d, "tx-pending", pw, "sw7.example.com"), StatusPending)
	wantStatus(t, f.poll(t, d, "tx-pending"), StatusPending)

	list, err := f.srv.ListScepEnrollments(f.ctx, &nodev1.ListScepEnrollmentsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetEnrollments()) != 1 {
		t.Fatalf("queue = %v, want one enrolment", list.GetEnrollments())
	}
	e := list.GetEnrollments()[0]
	if e.GetTransactionId() != "tx-pending" || e.GetProfile() != "approved-device" || e.GetChallengeId() != ch.GetId() ||
		e.GetKeyAlg() != "RSA-2048" || !strings.Contains(e.GetCsrPem(), "CERTIFICATE REQUEST") || !strings.Contains(e.GetSubjectDn(), "sw7.example.com") {
		t.Fatalf("enrolment = %v", e)
	}
	if other, _ := f.srv.ListScepEnrollments(f.ctx, &nodev1.ListScepEnrollmentsRequest{Profile: "cisco-device"}); len(other.GetEnrollments()) != 0 {
		t.Fatal("the profile filter does not filter")
	}

	approved, err := f.srv.ApproveScepEnrollment(f.ctx, &nodev1.ApproveScepEnrollmentRequest{Id: e.GetId()})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	rep := f.poll(t, d, "tx-pending")
	wantStatus(t, rep, StatusSuccess)
	if rep.certs[0].SerialNumber.Text(16) != approved.GetSerialHex() {
		t.Fatal("the poll did not return the approved certificate")
	}
	if list, _ := f.srv.ListScepEnrollments(f.ctx, &nodev1.ListScepEnrollmentsRequest{}); len(list.GetEnrollments()) != 0 {
		t.Fatal("an approved enrolment stayed in the queue")
	}
	if _, err := f.srv.ApproveScepEnrollment(f.ctx, &nodev1.ApproveScepEnrollmentRequest{Id: e.GetId()}); statusCode(err) != "NotFound" {
		t.Fatalf("a second approve = %v, want NotFound", err)
	}
	wantStatus(t, f.enrol(t, d, "tx-pending", "", "sw7.example.com"), StatusSuccess)
}

func TestPKCSReqPendingThenRejected(t *testing.T) {
	f := newFixture(t)
	pw, _ := f.mint("approved-device", time.Hour)
	d := newDevice(t, 2048)
	wantStatus(t, f.enrol(t, d, "tx-reject", pw, "sw8.example.com"), StatusPending)
	list, _ := f.srv.ListScepEnrollments(f.ctx, &nodev1.ListScepEnrollmentsRequest{})
	if _, err := f.srv.RejectScepEnrollment(f.ctx, &nodev1.RejectScepEnrollmentRequest{Id: list.GetEnrollments()[0].GetId(), Reason: "not ours"}); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	wantFailure(t, f.poll(t, d, "tx-reject"), FailBadRequest)
	if len(f.ca.issued) != 0 {
		t.Fatal("a rejected enrolment was issued")
	}
}

// Approval re-checks the request against the policy in force, and a request
// that no longer passes stays queued for rejection.
func TestApproveRechecksThePolicy(t *testing.T) {
	f := newFixture(t)
	pw, _ := f.mint("approved-device", time.Hour)
	d := newDevice(t, 2048)
	wantStatus(t, f.enrol(t, d, "tx-recheck", pw, "sw9.example.com"), StatusPending)
	list, _ := f.srv.ListScepEnrollments(f.ctx, &nodev1.ListScepEnrollmentsRequest{})
	id := list.GetEnrollments()[0].GetId()

	f.srv.opts.AllowedSuffixes = []string{"example.net"}
	if _, err := f.srv.ApproveScepEnrollment(f.ctx, &nodev1.ApproveScepEnrollmentRequest{Id: id}); statusCode(err) != "FailedPrecondition" {
		t.Fatalf("approve against a tightened allowlist = %v, want FailedPrecondition", err)
	}
	if list, _ := f.srv.ListScepEnrollments(f.ctx, &nodev1.ListScepEnrollmentsRequest{}); len(list.GetEnrollments()) != 1 {
		t.Fatal("a refused approval took the enrolment out of the queue")
	}
	wantStatus(t, f.poll(t, d, "tx-recheck"), StatusPending)
}

func TestCertPollFailures(t *testing.T) {
	f := newFixture(t)
	d := newDevice(t, 2048)
	wantFailure(t, f.poll(t, d, "tx-unknown"), FailBadCertID)

	pw, _ := f.mint("approved-device", time.Hour)
	wantStatus(t, f.enrol(t, d, "tx-owned", pw, "sw10.example.com"), StatusPending)
	wantFailure(t, f.poll(t, newDevice(t, 2048), "tx-owned"), FailBadRequest)
}

// renewer is a device holding a certificate this CA issued.
func renewer(t *testing.T, f *fixture, profile string, names ...string) *device {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &device{key: key, cert: f.ca.sign(t, &key.PublicKey, profile, names...)}
}

func TestRenewalReq(t *testing.T) {
	f := newFixture(t)
	old := renewer(t, f, "cisco-device", "sw11.example.com")

	renew := func(t *testing.T, signer *device, txID, cn string, dns ...string) certRep {
		t.Helper()
		next := newDevice(t, 2048)
		msg := f.message(t, MessageTypeRenewalReq, next.csr(t, cn, dns, ""), msgOpts{signer: signer.cert, signerKey: signer.key, txID: txID})
		return f.post(t, msg, signer.key, signer.cert)
	}

	t.Run("same names", func(t *testing.T) {
		rep := renew(t, old, "tx-renew", "sw11.example.com")
		wantStatus(t, rep, StatusSuccess)
		if rep.certs[0].DNSNames[0] != "sw11.example.com" {
			t.Fatalf("renewed names = %v", rep.certs[0].DNSNames)
		}
		if ev := f.audit.last(); ev.GetRpcMethod() != "scep/RenewalReq" || ev.GetDetails()["profile"] != "cisco-device" {
			t.Fatalf("audit = %v", ev)
		}
	})
	t.Run("different names", func(t *testing.T) {
		wantFailure(t, renew(t, old, "tx-renew-names", "sw11.example.com", "other.example.com"), FailBadRequest)
	})
	t.Run("names outside the allowlist stay pinned, not re-checked", func(t *testing.T) {
		legacy := renewer(t, f, "cisco-device", "legacy.example.org")
		wantStatus(t, renew(t, legacy, "tx-renew-legacy", "legacy.example.org"), StatusSuccess)
	})
	t.Run("revoked", func(t *testing.T) {
		gone := renewer(t, f, "cisco-device", "sw12.example.com")
		f.ca.revoked[gone.cert.SerialNumber.Text(16)] = true
		wantFailure(t, renew(t, gone, "tx-renew-revoked", "sw12.example.com"), FailBadRequest)
	})
	t.Run("not issued by this CA", func(t *testing.T) {
		stranger := newTestCA(t, "Another CA")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		d := &device{key: key, cert: stranger.sign(t, &key.PublicKey, "cisco-device", "sw13.example.com")}
		wantFailure(t, renew(t, d, "tx-renew-stranger", "sw13.example.com"), FailBadRequest)
	})
	t.Run("self-signed", func(t *testing.T) {
		wantFailure(t, renew(t, newDevice(t, 2048), "tx-renew-self", "scep-client.example.com"), FailBadRequest)
	})
	t.Run("expired", func(t *testing.T) {
		f.clock.advance(60 * 24 * time.Hour)
		defer f.clock.advance(-60 * 24 * time.Hour)
		wantFailure(t, renew(t, old, "tx-renew-expired", "sw11.example.com"), FailBadTime)
	})
	t.Run("issued under a profile SCEP does not serve", func(t *testing.T) {
		web := renewer(t, f, "web-server", "www.example.com")
		wantFailure(t, renew(t, web, "tx-renew-web", "www.example.com"), FailBadRequest)
	})
	t.Run("key below the profile floor", func(t *testing.T) {
		strict := renewer(t, f, "strict-device", "mdm3.example.com")
		wantFailure(t, renew(t, strict, "tx-renew-floor", "mdm3.example.com"), FailBadRequest)
	})
}

func TestGetCertAndGetCRL(t *testing.T) {
	f := newFixture(t)
	holder := renewer(t, f, "cisco-device", "sw14.example.com")
	target := renewer(t, f, "cisco-device", "sw15.example.com")

	ias := func(serialHolder *x509.Certificate) []byte {
		b, _ := asn1.Marshal(issuerAndSerial{Issuer: asn1.RawValue{FullBytes: f.ca.cert.RawSubject}, SerialNumber: serialHolder.SerialNumber})
		return b
	}
	send := func(t *testing.T, mt MessageType, signer *device, content []byte) certRep {
		t.Helper()
		msg := f.message(t, mt, content, msgOpts{signer: signer.cert, signerKey: signer.key, txID: "tx-" + mt.String()})
		return f.post(t, msg, signer.key, signer.cert)
	}

	rep := send(t, MessageTypeGetCert, holder, ias(target.cert))
	wantStatus(t, rep, StatusSuccess)
	if !rep.certs[0].Equal(target.cert) {
		t.Fatal("GetCert returned the wrong certificate")
	}

	unknown, _ := asn1.Marshal(issuerAndSerial{Issuer: asn1.RawValue{FullBytes: f.ca.cert.RawSubject}, SerialNumber: new(big.Int).Lsh(holder.cert.SerialNumber, 8)})
	wantFailure(t, send(t, MessageTypeGetCert, holder, unknown), FailBadCertID)

	otherIssuer, _ := asn1.Marshal(issuerAndSerial{Issuer: asn1.RawValue{FullBytes: target.cert.RawSubject}, SerialNumber: target.cert.SerialNumber})
	wantFailure(t, send(t, MessageTypeGetCert, holder, otherIssuer), FailBadCertID)

	wantFailure(t, send(t, MessageTypeGetCert, newDevice(t, 2048), ias(target.cert)), FailBadRequest)

	crl := send(t, MessageTypeGetCRL, holder, ias(target.cert))
	wantStatus(t, crl, StatusSuccess)
	if len(crl.crls) != 1 {
		t.Fatalf("GetCRL carries %d CRLs", len(crl.crls))
	}
	if _, err := x509.ParseRevocationList(crl.crls[0]); err != nil {
		t.Fatalf("GetCRL CRL: %v", err)
	}
	wantFailure(t, send(t, MessageTypeGetCRL, newDevice(t, 2048), ias(target.cert)), FailBadRequest)
}

func TestMessageIntegrityFailures(t *testing.T) {
	f := newFixture(t)
	pw, _ := f.mint("cisco-device", time.Hour)
	d := newDevice(t, 2048)

	t.Run("tampered signature", func(t *testing.T) {
		msg := f.message(t, MessageTypePKCSReq, d.csr(t, "sw.example.com", nil, pw), msgOpts{signer: d.cert, signerKey: d.key, txID: "tx-tamper"})
		msg[len(msg)-5] ^= 0xff
		wantFailure(t, f.post(t, msg, d.key, d.cert), FailBadMessageCheck)
	})
	t.Run("encrypted to a stranger", func(t *testing.T) {
		stranger := newDevice(t, 2048)
		msg := f.message(t, MessageTypePKCSReq, d.csr(t, "sw.example.com", nil, pw), msgOpts{signer: d.cert, signerKey: d.key, txID: "tx-stranger", recipient: stranger.cert})
		wantFailure(t, f.post(t, msg, d.key, d.cert), FailBadMessageCheck)
	})
	t.Run("unsupported message type", func(t *testing.T) {
		msg := f.message(t, MessageType(99), []byte{0x30, 0x00}, msgOpts{signer: d.cert, signerKey: d.key, txID: "tx-99"})
		wantFailure(t, f.post(t, msg, d.key, d.cert), FailBadRequest)
	})
	t.Run("an ECDSA signer cannot be encrypted to", func(t *testing.T) {
		ek, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: d.cert.SerialNumber, Subject: pkixName("ec"), NotBefore: d.cert.NotBefore, NotAfter: d.cert.NotAfter}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ek.PublicKey, ek)
		ec, _ := x509.ParseCertificate(der)
		msg := f.message(t, MessageTypePKCSReq, d.csr(t, "sw.example.com", nil, pw), msgOpts{signer: ec, signerKey: ek, txID: "tx-ec"})
		resp, err := http.Post(f.http.URL+PathSCEP+"?operation=PKIOperation", contentTypePKIMessage, bytes.NewReader(msg))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		wantFailure(t, parseCertRep(t, body, nil, nil), FailBadAlg)
	})
	t.Run("AES-128 is mirrored", func(t *testing.T) {
		pw2, _ := f.mint("cisco-device", time.Hour)
		msg := f.message(t, MessageTypePKCSReq, d.csr(t, "sw.example.com", nil, pw2), msgOpts{signer: d.cert, signerKey: d.key, txID: "tx-aes128", alg: cms.AES128CBC})
		wantStatus(t, f.post(t, msg, d.key, d.cert), StatusSuccess)
	})
}

// During an RA rotation both RAs decrypt: a device that cached the old RA
// from GetCACert still enrols, and the reply is signed by the RA it used.
func TestRARotationOverlap(t *testing.T) {
	f := newFixture(t)
	oldRA := f.raCert()

	f.clock.advance(336 * 24 * time.Hour)
	defer f.clock.advance(-336 * 24 * time.Hour)
	if err := f.ras.Ensure(f.ctx); err != nil {
		t.Fatalf("Ensure in the overlap: %v", err)
	}
	newRA := f.raCert()
	if newRA.Equal(oldRA) {
		t.Fatal("no successor RA was minted inside the overlap")
	}
	if n := len(f.ras.All()); n != 2 {
		t.Fatalf("%d usable RAs during the overlap, want 2", n)
	}
	_, body := get(t, f, "operation=GetCACert")
	sd, _ := cms.ParseSignedData(body)
	offered, _ := x509.ParseCertificate(sd.Certificates[1])
	if !offered.Equal(newRA) {
		t.Fatal("GetCACert does not offer the new RA during the overlap")
	}

	d := newDevice(t, 2048)
	pw, _ := f.mint("cisco-device", time.Hour)
	msg := f.message(t, MessageTypePKCSReq, d.csr(t, "sw16.example.com", nil, pw), msgOpts{signer: d.cert, signerKey: d.key, txID: "tx-old-ra", recipient: oldRA})
	rep := f.post(t, msg, d.key, d.cert)
	wantStatus(t, rep, StatusSuccess)
	if !rep.signer.Equal(oldRA) {
		t.Fatal("the reply to a request for the old RA is not signed by the old RA")
	}

	if err := f.ras.Ensure(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.ras.All()); n != 2 {
		t.Fatalf("a second Ensure in the overlap left %d RAs, want 2 (no extra mint)", n)
	}

	f.clock.advance(30 * 24 * time.Hour)
	defer f.clock.advance(-30 * 24 * time.Hour)
	if err := f.ras.Ensure(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.ras.All()); n != 1 {
		t.Fatalf("%d usable RAs after the old one expired, want 1", n)
	}
	d2 := newDevice(t, 2048)
	pw2, _ := f.mint("cisco-device", time.Hour)
	msg = f.message(t, MessageTypePKCSReq, d2.csr(t, "sw17.example.com", nil, pw2), msgOpts{signer: d2.cert, signerKey: d2.key, txID: "tx-expired-ra", recipient: oldRA})
	wantFailure(t, f.post(t, msg, d2.key, d2.cert), FailBadMessageCheck)
}

func TestRAPersistsAcrossRestart(t *testing.T) {
	f := newFixture(t)
	first := f.raCert()
	again, err := NewRAManager(f.store, f.ca.mintRA, func(context.Context) (*x509.Certificate, error) { return f.ca.cert, nil }, RAOptions{Validity: 365 * 24 * time.Hour, Overlap: 30 * 24 * time.Hour, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	again.keygen = func() (*rsa.PrivateKey, error) { t.Fatal("a restart minted a new RA"); return nil, nil }
	if err := again.Ensure(f.ctx); err != nil {
		t.Fatal(err)
	}
	ra, _ := again.Current()
	if !ra.Cert.Equal(first) {
		t.Fatal("a restart did not reload the stored RA")
	}
}

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

func statusCode(err error) string { return status.Code(err).String() }

// A PKCSReq with no challenge, signed by a certificate this CA issued, is the
// pre-RFC 8894 renewal form that sscep and Cisco IOS rollover send. It gets
// the RenewalReq rules.
func TestPKCSReqSignedByTheCurrentCertificateIsARenewal(t *testing.T) {
	f := newFixture(t)
	old := renewer(t, f, "cisco-device", "sw20.example.com")
	send := func(t *testing.T, signer *device, txID, cn, challenge string) certRep {
		t.Helper()
		next := newDevice(t, 2048)
		msg := f.message(t, MessageTypePKCSReq, next.csr(t, cn, nil, challenge), msgOpts{signer: signer.cert, signerKey: signer.key, txID: txID})
		return f.post(t, msg, signer.key, signer.cert)
	}

	wantStatus(t, send(t, old, "tx-legacy-renew", "sw20.example.com", ""), StatusSuccess)
	if ev := f.audit.last(); ev.GetDetails()["authorized_by"] != "certificate" || ev.GetDetails()["challenge_id"] != "" {
		t.Fatalf("audit = %v, want a certificate-authorized renewal", ev)
	}
	wantFailure(t, send(t, old, "tx-legacy-names", "sw21.example.com", ""), FailBadRequest)

	gone := renewer(t, f, "cisco-device", "sw22.example.com")
	f.ca.revoked[gone.cert.SerialNumber.Text(16)] = true
	wantFailure(t, send(t, gone, "tx-legacy-revoked", "sw22.example.com", ""), FailBadRequest)

	// Cisco IOS rollover may repeat the original challenge: signed by a
	// current certificate it is still a renewal, names pinned, and the
	// challenge is neither needed nor consumed.
	pw, ch := f.mint("cisco-device", time.Hour)
	wantFailure(t, send(t, old, "tx-legacy-challenge-names", "sw23.example.com", pw), FailBadRequest)
	wantStatus(t, send(t, old, "tx-legacy-challenge", "sw20.example.com", pw), StatusSuccess)
	if ev := f.audit.last(); ev.GetDetails()["authorized_by"] != "certificate" {
		t.Fatalf("audit = %v, want a certificate-authorized renewal", ev)
	}
	if list, _ := f.srv.ListScepChallenges(f.ctx, &nodev1.ListScepChallengesRequest{}); len(list.GetChallenges()) != 1 || list.GetChallenges()[0].GetId() != ch.GetId() {
		t.Fatal("a renewal consumed the challenge it carried")
	}

	// Signed by some other CA's certificate, only the challenge counts.
	stranger := newTestCA(t, "Manufacturer CA")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	factory := &device{key: key, cert: stranger.sign(t, &key.PublicKey, "factory", "factory-id.example.net")}
	wantStatus(t, send(t, factory, "tx-factory", "sw24.example.com", pw), StatusSuccess)
	if ev := f.audit.last(); ev.GetDetails()["authorized_by"] != "challenge" {
		t.Fatalf("audit = %v, want a challenge-authorized enrolment", ev)
	}
}

// After a CA key rotation the stored RA no longer chains to the CA, so a new
// one is minted; near the CA's own expiry, where a successor could not
// outlive the current RA, none is stored.
func TestRAFollowsTheCA(t *testing.T) {
	f := newFixture(t)
	before := f.raCert()
	f.ca = newTestCA(t, "Test Issuing CA")
	if err := f.ras.Ensure(f.ctx); err != nil {
		t.Fatal(err)
	}
	after := f.raCert()
	if after.Equal(before) || after.CheckSignatureFrom(f.ca.cert) != nil {
		t.Fatal("no RA under the rotated CA key was minted")
	}

	nearExpiry := time.Until(f.ca.cert.NotAfter) - 10*24*time.Hour
	f.clock.advance(nearExpiry)
	defer f.clock.advance(-nearExpiry)
	for range 2 {
		if err := f.ras.Ensure(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.ras.All()); n != 1 {
		t.Fatalf("%d RAs near the CA's expiry, want 1", n)
	}
	if !strings.Contains(f.logText(), "would not outlive the current RA") {
		t.Fatal("the capped successor was not reported")
	}
}
