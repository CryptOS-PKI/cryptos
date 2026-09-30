package scep

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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/cms"
	"github.com/CryptOS-PKI/cryptos/internal/storage/etcd"
)

// testCA is an issuing CA for the tests, ECDSA P-384 like a real node.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu      sync.Mutex
	issued  map[string]issuedCert
	revoked map[string]bool
}

type issuedCert struct {
	der     []byte
	profile string
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	now := time.Now().UTC()
	der, _, err := ca.Sign(ca.Profile{
		Subject:   pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(5 * 365 * 24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, &key.PublicKey, nil, key)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{cert: cert, key: key, issued: map[string]issuedCert{}, revoked: map[string]bool{}}
}

func (c *testCA) issue(_ context.Context, csrDER []byte, profile string, names []string, minRSABits int) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	der, _, err := ca.Sign(ca.Profile{
		Subject:       csr.Subject,
		NotBefore:     now,
		NotAfter:      now.Add(365 * 24 * time.Hour),
		KeyUsage:      x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:      names,
		MinRSAKeyBits: minRSABits,
	}, csr.PublicKey, c.cert, c.key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	c.mu.Lock()
	c.issued[cert.SerialNumber.Text(16)] = issuedCert{der: der, profile: profile}
	c.mu.Unlock()
	return der, nil
}

func (c *testCA) chain(context.Context) ([]*x509.Certificate, error) {
	return []*x509.Certificate{c.cert}, nil
}

func (c *testCA) isRevoked(_ context.Context, serial string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.revoked[serial], nil
}

func (c *testCA) lookup(_ context.Context, serial string) ([]byte, string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ic, ok := c.issued[serial]
	return ic.der, ic.profile, ok, nil
}

func (c *testCA) crl(context.Context) ([]byte, error) {
	now := time.Now().UTC()
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
	}, c.cert, c.key)
}

func (c *testCA) mintRA(_ context.Context, pub *rsa.PublicKey, notBefore, notAfter time.Time) ([]byte, error) {
	der, _, err := ca.Sign(ca.Profile{
		Subject:   pkix.Name{CommonName: c.cert.Subject.CommonName + " SCEP RA"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}, pub, c.cert, c.key)
	return der, err
}

// sign issues a certificate over pub directly, for a renewal signer that
// never went through SCEP.
func (c *testCA) sign(t *testing.T, pub crypto.PublicKey, profile string, names ...string) *x509.Certificate {
	t.Helper()
	now := time.Now().UTC()
	der, _, err := ca.Sign(ca.Profile{
		Subject:       pkix.Name{CommonName: names[0]},
		NotBefore:     now.Add(-time.Minute),
		NotAfter:      now.Add(30 * 24 * time.Hour),
		KeyUsage:      x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:      names,
		MinRSAKeyBits: 2048,
	}, pub, c.cert, c.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	c.mu.Lock()
	c.issued[cert.SerialNumber.Text(16)] = issuedCert{der: der, profile: profile}
	c.mu.Unlock()
	return cert
}

type memAuditor struct {
	mu     sync.Mutex
	events []*cryptosv1.AuditEvent
}

func (a *memAuditor) Append(e *cryptosv1.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *memAuditor) last() *cryptosv1.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return nil
	}
	return a.events[len(a.events)-1]
}

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// fixture is a running SCEP server over a test CA and an embedded etcd.
type fixture struct {
	t      *testing.T
	ctx    context.Context
	ca     *testCA
	store  *Store
	ras    *RAManager
	srv    *Server
	http   *httptest.Server
	audit  *memAuditor
	clock  *clock
	logs   *bytes.Buffer
	logsMu *sync.Mutex
}

// Profiles used across the tests: a Cisco profile at the 2048 floor, a
// default-floor profile, and one that holds enrolments for approval.
func testProfiles() []Profile {
	return []Profile{
		{Name: "cisco-device", MinRSABits: 2048},
		{Name: "strict-device"},
		{Name: "approved-device", MinRSABits: 2048, RequireApproval: true},
	}
}

// raKeys are RSA 3072 keys generated once for the whole package, so each
// fixture does not spend a second generating its RA key. Each fixture hands
// them out in order, so the RAs of one fixture never share a key.
var (
	raKeysOnce sync.Once
	raKeys     []*rsa.PrivateKey
)

func testRAKeygen(t *testing.T) func() (*rsa.PrivateKey, error) {
	t.Helper()
	raKeysOnce.Do(func() {
		for i := 0; i < 3; i++ {
			k, err := rsa.GenerateKey(rand.Reader, RAKeyBits)
			if err != nil {
				panic(err)
			}
			raKeys = append(raKeys, k)
		}
	})
	next := 0
	return func() (*rsa.PrivateKey, error) {
		k := raKeys[next%len(raKeys)]
		next++
		return k, nil
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, testProfiles())
}

func newFixtureWith(t *testing.T, profiles []Profile) *fixture {
	t.Helper()
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	f := &fixture{t: t, ctx: ctx, ca: newTestCA(t, "Test Issuing CA"), store: NewStore(cli), audit: &memAuditor{},
		clock: &clock{now: time.Now().UTC()}, logs: &bytes.Buffer{}, logsMu: &sync.Mutex{}}
	logf := func(format string, args ...any) {
		f.logsMu.Lock()
		defer f.logsMu.Unlock()
		fmt.Fprintf(f.logs, format+"\n", args...)
	}
	mint := func(ctx context.Context, pub *rsa.PublicKey, notBefore, notAfter time.Time) ([]byte, error) {
		return f.ca.mintRA(ctx, pub, notBefore, notAfter)
	}
	f.ras, err = NewRAManager(f.store, mint, func(context.Context) (*x509.Certificate, error) { return f.ca.cert, nil },
		RAOptions{Validity: 365 * 24 * time.Hour, Overlap: 30 * 24 * time.Hour, Now: f.clock.Now, Logf: logf})
	if err != nil {
		t.Fatalf("NewRAManager: %v", err)
	}
	f.ras.keygen = testRAKeygen(t)
	if err := f.ras.Ensure(ctx); err != nil {
		t.Fatalf("RA Ensure: %v", err)
	}
	f.srv, err = NewServer(f.store, f.ras, Deps{
		Issue: f.ca.issue, CAChain: f.ca.chain, Revoked: f.ca.isRevoked, Issued: f.ca.lookup, CRL: f.ca.crl, Auditor: f.audit,
	}, Options{Profiles: profiles, AllowedSuffixes: []string{"example.com"}, Now: f.clock.Now, Logf: logf})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	f.http = httptest.NewServer(f.srv.Routes())
	t.Cleanup(f.http.Close)
	return f
}

func (f *fixture) logText() string {
	f.logsMu.Lock()
	defer f.logsMu.Unlock()
	return f.logs.String()
}

func (f *fixture) raCert() *x509.Certificate {
	ra, ok := f.ras.Current()
	if !ok {
		f.t.Fatal("no RA")
	}
	return ra.Cert
}

func (f *fixture) mint(profile string, ttl time.Duration, bound ...string) (string, *cryptosv1.ScepChallenge) {
	f.t.Helper()
	resp, err := f.srv.MintScepChallenge(f.ctx, &cryptosv1.MintScepChallengeRequest{
		Profile: profile, TtlSeconds: uint32(ttl / time.Second), BoundNames: bound,
	}, "admin.example.com")
	if err != nil {
		f.t.Fatalf("MintScepChallenge: %v", err)
	}
	return resp.GetChallengePassword(), resp.GetChallenge()
}

// device is a SCEP client: an RSA key with a self-signed certificate over it.
type device struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// newDevice returns a device with a fresh key of the given size.
func newDevice(t *testing.T, bits int) *device {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	return deviceFor(t, key, "scep-client")
}

func deviceFor(t *testing.T, key *rsa.PrivateKey, cn string) *device {
	t.Helper()
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &device{key: key, cert: cert}
}

// csr builds a PKCS#10 request for the device key with a challengePassword
// attribute, which crypto/x509 cannot write, so it is spliced into the request
// info and the request re-signed.
func (d *device) csr(t *testing.T, cn string, dnsNames []string, challenge string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: dnsNames, SignatureAlgorithm: x509.SHA256WithRSA,
	}, d.key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if challenge == "" {
		return der
	}
	return withChallenge(t, der, challenge, d.key)
}

func withChallenge(t *testing.T, csrDER []byte, challenge string, key *rsa.PrivateKey) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Version int
		Subject asn1.RawValue
		SPKI    asn1.RawValue
		Attrs   asn1.RawValue
	}
	if _, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &info); err != nil {
		t.Fatal(err)
	}
	attr, err := asn1.Marshal(struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{oidChallengePassword, []asn1.RawValue{{Tag: asn1.TagPrintableString, Bytes: []byte(challenge)}}})
	if err != nil {
		t.Fatal(err)
	}
	attrs := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(append([]byte(nil), info.Attrs.Bytes...), attr...)}
	tbs, err := asn1.Marshal(struct {
		Version int
		Subject asn1.RawValue
		SPKI    asn1.RawValue
		Attrs   asn1.RawValue
	}{info.Version, info.Subject, info.SPKI, attrs})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		TBS    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue}, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// msgOpts shapes one pkiMessage.
type msgOpts struct {
	signer    *x509.Certificate
	signerKey crypto.Signer
	recipient *x509.Certificate
	txID      string
	alg       cms.ContentEncryption
	hash      crypto.Hash
}

// message builds a pkiMessage of type mt around content.
func (f *fixture) message(t *testing.T, mt MessageType, content []byte, o msgOpts) []byte {
	t.Helper()
	if o.recipient == nil {
		o.recipient = f.raCert()
	}
	if o.alg == 0 {
		o.alg = cms.AES256CBC
	}
	if o.hash == 0 {
		o.hash = crypto.SHA256
	}
	env, err := cms.Encrypt(content, []*x509.Certificate{o.recipient}, o.alg, cms.EncryptOptions{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	signer := cms.Signer{Certificate: o.signer, Key: o.signerKey, Hash: o.hash}
	for _, a := range []struct {
		oid asn1.ObjectIdentifier
		v   any
	}{
		{oidMessageType, printable(strconv.Itoa(int(mt)))},
		{oidTransactionID, printable(o.txID)},
		{oidSenderNonce, nonce},
	} {
		attr, err := cms.NewAttribute(a.oid, a.v)
		if err != nil {
			t.Fatal(err)
		}
		signer.Attributes = append(signer.Attributes, attr)
	}
	msg, err := cms.Sign(cms.OIDData, env, []cms.Signer{signer}, cms.SignOptions{Certificates: [][]byte{o.signer.Raw}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return msg
}

// certRep is a parsed CertRep.
type certRep struct {
	status   PKIStatus
	failInfo FailInfo
	txID     string
	recNonce []byte
	signer   *x509.Certificate
	certs    []*x509.Certificate
	crls     [][]byte
}

// post sends a PKIOperation and parses the CertRep, decrypting it with key.
func (f *fixture) post(t *testing.T, msg []byte, key *rsa.PrivateKey, signer *x509.Certificate) certRep {
	t.Helper()
	resp, err := http.Post(f.http.URL+PathPKIClient+"?operation=PKIOperation", contentTypePKIMessage, bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PKIOperation status %d: %s", resp.StatusCode, body.String())
	}
	if ct := resp.Header.Get("Content-Type"); ct != contentTypePKIMessage {
		t.Fatalf("Content-Type = %q, want %q", ct, contentTypePKIMessage)
	}
	return parseCertRep(t, body.Bytes(), key, signer)
}

func parseCertRep(t *testing.T, der []byte, key *rsa.PrivateKey, deviceCert *x509.Certificate) certRep {
	t.Helper()
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		t.Fatalf("CertRep does not parse: %v", err)
	}
	opts := cms.VerifyOptions{}
	if sd.Content == nil {
		opts.Content = []byte{}
	}
	signers, err := sd.Verify(opts)
	if err != nil {
		t.Fatalf("CertRep does not verify: %v", err)
	}
	si := sd.SignerInfos[0]
	var rep certRep
	rep.signer = signers[0]
	var mt, st string
	if err := si.SignedAttribute(oidMessageType, &mt); err != nil || mt != "3" {
		t.Fatalf("messageType = %q (%v), want 3", mt, err)
	}
	if err := si.SignedAttribute(oidPKIStatus, &st); err != nil {
		t.Fatalf("pkiStatus: %v", err)
	}
	n, _ := strconv.Atoi(st)
	rep.status = PKIStatus(n)
	if err := si.SignedAttribute(oidTransactionID, &rep.txID); err != nil {
		t.Fatalf("transactionID: %v", err)
	}
	if err := si.SignedAttribute(oidRecipientNonce, &rep.recNonce); err != nil {
		t.Fatalf("recipientNonce: %v", err)
	}
	var sn []byte
	if err := si.SignedAttribute(oidSenderNonce, &sn); err != nil || len(sn) != nonceLen {
		t.Fatalf("senderNonce = %x (%v), want %d bytes", sn, err, nonceLen)
	}
	if rep.status == StatusFailure {
		var fi string
		if err := si.SignedAttribute(oidFailInfo, &fi); err != nil {
			t.Fatalf("failInfo: %v", err)
		}
		n, _ := strconv.Atoi(fi)
		rep.failInfo = FailInfo(n)
		return rep
	}
	if rep.status != StatusSuccess {
		if sd.Content != nil {
			t.Fatal("a PENDING CertRep carries a pkcsPKIEnvelope")
		}
		return rep
	}
	env, err := cms.ParseEnvelopedData(sd.Content)
	if err != nil {
		t.Fatalf("CertRep envelope: %v", err)
	}
	plain, err := env.Decrypt(deviceCert, key)
	if err != nil {
		t.Fatalf("CertRep decrypt: %v", err)
	}
	inner, err := cms.ParseSignedData(plain)
	if err != nil {
		t.Fatalf("CertRep degenerate: %v", err)
	}
	for _, c := range inner.Certificates {
		cert, err := x509.ParseCertificate(c)
		if err != nil {
			t.Fatal(err)
		}
		rep.certs = append(rep.certs, cert)
	}
	rep.crls = inner.CRLs
	return rep
}

// enrol sends a PKCSReq for the device and returns the CertRep.
func (f *fixture) enrol(t *testing.T, d *device, txID, challenge, cn string, dns ...string) certRep {
	t.Helper()
	msg := f.message(t, MessageTypePKCSReq, d.csr(t, cn, dns, challenge), msgOpts{signer: d.cert, signerKey: d.key, txID: txID})
	return f.post(t, msg, d.key, d.cert)
}

func (f *fixture) poll(t *testing.T, d *device, txID string) certRep {
	t.Helper()
	ias, _ := asn1.Marshal(struct {
		Issuer  asn1.RawValue
		Subject asn1.RawValue
	}{asn1.RawValue{FullBytes: f.ca.cert.RawSubject}, asn1.RawValue{FullBytes: d.cert.RawSubject}})
	msg := f.message(t, MessageTypeCertPoll, ias, msgOpts{signer: d.cert, signerKey: d.key, txID: txID})
	return f.post(t, msg, d.key, d.cert)
}

func wantStatus(t *testing.T, rep certRep, st PKIStatus) {
	t.Helper()
	if rep.status != st {
		if rep.status == StatusFailure {
			t.Fatalf("pkiStatus = FAILURE %s, want %s", rep.failInfo, st)
		}
		t.Fatalf("pkiStatus = %s, want %s", rep.status, st)
	}
}

func wantFailure(t *testing.T, rep certRep, fi FailInfo) {
	t.Helper()
	if rep.status != StatusFailure {
		t.Fatalf("pkiStatus = %s, want FAILURE %s", rep.status, fi)
	}
	if rep.failInfo != fi {
		t.Fatalf("failInfo = %s, want %s", rep.failInfo, fi)
	}
}
