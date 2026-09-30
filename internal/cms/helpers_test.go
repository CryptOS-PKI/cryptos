package cms

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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"
)

// Key generation dominates the suite's run time (RSA 3072 especially), so each
// shape is generated once and shared. Every test still gets its own
// certificates.
var (
	keyOnce sync.Once
	keys    struct {
		rsa2048   *rsa.PrivateKey
		rsa2048b  *rsa.PrivateKey
		rsa3072   *rsa.PrivateKey
		p256      *ecdsa.PrivateKey
		p384      *ecdsa.PrivateKey
		caKey     *ecdsa.PrivateKey
		keyGenErr error
	}
)

func testKeys(t *testing.T) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		gen := func(bits int) *rsa.PrivateKey {
			k, e := rsa.GenerateKey(rand.Reader, bits)
			if e != nil && err == nil {
				err = e
			}
			return k
		}
		genEC := func(c elliptic.Curve) *ecdsa.PrivateKey {
			k, e := ecdsa.GenerateKey(c, rand.Reader)
			if e != nil && err == nil {
				err = e
			}
			return k
		}
		keys.rsa2048 = gen(2048)
		keys.rsa2048b = gen(2048)
		keys.rsa3072 = gen(3072)
		keys.p256 = genEC(elliptic.P256())
		keys.p384 = genEC(elliptic.P384())
		keys.caKey = genEC(elliptic.P384())
		keys.keyGenErr = err
	})
	if keys.keyGenErr != nil {
		t.Fatalf("generate test keys: %v", keys.keyGenErr)
	}
}

var serialCounter struct {
	sync.Mutex
	n int64
}

func nextSerial() *big.Int {
	serialCounter.Lock()
	defer serialCounter.Unlock()
	serialCounter.n++
	return big.NewInt(1000 + serialCounter.n)
}

// testCA is a throwaway CA that issues the signer and recipient certificates,
// so the tests exercise certificates that exist rather than hand-built blobs.
type testCA struct {
	key  crypto.Signer
	cert *x509.Certificate
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	testKeys(t)
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: "CMS Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, keys.caKey.Public(), keys.caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	return &testCA{key: keys.caKey, cert: cert}
}

// issue signs a certificate for pub. withSKI controls whether the certificate
// carries a SubjectKeyIdentifier, which the SKI signer and recipient
// identifiers depend on.
func (c *testCA) issue(t *testing.T, cn string, pub crypto.PublicKey, withSKI bool) *x509.Certificate {
	t.Helper()
	return c.issueWith(t, cn, pub, withSKI, nextSerial())
}

// issueSerial issues with a chosen serial, to build a certificate that
// collides with another on issuer and serial number.
func (c *testCA) issueSerial(t *testing.T, cn string, pub crypto.PublicKey, serial *big.Int) *x509.Certificate {
	t.Helper()
	return c.issueWith(t, cn, pub, false, serial)
}

func (c *testCA) issueWith(t *testing.T, cn string, pub crypto.PublicKey, withSKI bool, serial *big.Int) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if withSKI {
		spki, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("marshal public key: %v", err)
		}
		// RFC 5280 section 4.2.1.2 method (1): an identifier, not a security digest.
		sum := sha1.Sum(spki)
		tmpl.SubjectKeyId = sum[:]
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatalf("issue %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", cn, err)
	}
	if !withSKI && len(cert.SubjectKeyId) != 0 {
		t.Fatalf("%s unexpectedly carries a SubjectKeyId", cn)
	}
	return cert
}

// selfSigned mints the kind of throwaway certificate a SCEP client signs its
// first request with.
func selfSigned(t *testing.T, cn string, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("self-signed %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", cn, err)
	}
	return cert
}

// testCRL issues an empty CRL from the CA.
func (c *testCA) crl(t *testing.T) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, c.cert, c.key)
	if err != nil {
		t.Fatalf("crl: %v", err)
	}
	return der
}

// decrypterOnly hides the concrete key type so the tests prove Decrypt only
// needs the crypto.Decrypter interface a TPM-held key presents.
type decrypterOnly struct{ inner crypto.Decrypter }

func (d decrypterOnly) Public() crypto.PublicKey { return d.inner.Public() }

func (d decrypterOnly) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.inner.Decrypt(r, msg, opts)
}

// signerOnly does the same for signing.
type signerOnly struct{ inner crypto.Signer }

func (s signerOnly) Public() crypto.PublicKey { return s.inner.Public() }

func (s signerOnly) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(r, digest, opts)
}
