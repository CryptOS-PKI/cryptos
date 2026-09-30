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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/CryptOS-PKI/cryptos/internal/ca"
	"github.com/CryptOS-PKI/cryptos/internal/config"
	"github.com/CryptOS-PKI/cryptos/internal/node"
	"github.com/CryptOS-PKI/cryptos/internal/revocation"
	"github.com/CryptOS-PKI/cryptos/internal/scep"
)

// scepRAEnsureInterval is how often a running node re-checks its SCEP RA
// certificates, so a successor is minted when the overlap starts without a
// reboot.
const scepRAEnsureInterval = time.Hour

// scepListenPort is the port the SCEP listener binds: the configured one, or
// by default the plain-HTTP CRL/OCSP port, so Cisco's default enrolment URL
// (http://<ca>/cgi-bin/pkiclient.exe) works as written.
func scepListenPort(c *config.Config) uint32 {
	return nonzero(c.PKI.SCEP.HTTPPort, nonzero(c.PKI.RevocationHTTPPort, defaultRevocationHTTPPort))
}

// scepSharesRevocationListener reports whether SCEP is served on the CRL/OCSP
// listener rather than one of its own: when that listener runs (a revocation
// base URL is set) and both use the same port, as they do by default.
func scepSharesRevocationListener(c *config.Config) bool {
	return c.PKI.SCEP != nil && c.PKI.RevocationBaseURL != "" &&
		scepListenPort(c) == nonzero(c.PKI.RevocationHTTPPort, defaultRevocationHTTPPort)
}

// scepOptions maps the validated pki.scep block onto scep.Options.
func scepOptions(c *config.SCEP) scep.Options {
	opts := scep.Options{AllowedSuffixes: c.AllowedIdentifierSuffixes, Logf: log.Printf}
	for _, p := range c.Profiles {
		opts.Profiles = append(opts.Profiles, scep.Profile{
			Name:            p.Profile,
			MinRSABits:      p.RSAFloor(),
			RequireApproval: p.RequireApproval,
		})
	}
	return opts
}

// scepRAProfile is the ca.Profile for an RA certificate: an end-entity
// certificate whose key decrypts SCEP requests and signs SCEP replies.
func scepRAProfile(issuer *x509.Certificate, notBefore, notAfter time.Time) ca.Profile {
	return ca.Profile{
		Subject:   pkix.Name{CommonName: issuer.Subject.CommonName + " SCEP RA"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
}

// scepMintRA returns the RA-signing closure. The CA key is loaded for the
// signature and released straight after, as for the OCSP responder.
func scepMintRA(load node.KeyLoader, issuer node.IssuerFunc) scep.MintRAFunc {
	return func(ctx context.Context, pub *rsa.PublicKey, notBefore, notAfter time.Time) ([]byte, error) {
		signer, closeFn, err := load(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load the CA key for the SCEP RA: %w", err)
		}
		if closeFn != nil {
			defer closeFn()
		}
		issuerCert, err := issuer(ctx)
		if err != nil {
			return nil, fmt.Errorf("init: load the issuer for the SCEP RA: %w", err)
		}
		if issuerCert == nil {
			return nil, errors.New("init: no issuer certificate for the SCEP RA")
		}
		der, _, err := ca.Sign(scepRAProfile(issuerCert, notBefore, notAfter), pub, issuerCert, signer)
		return der, err
	}
}

// scepIssuer issues through the CA signer with the profile's RSA floor, so
// the profile decides the extensions and the certificate is recorded for
// revocation before SCEP hands it out.
func scepIssuer(signer *node.CASigner) scep.IssueFunc {
	return func(ctx context.Context, csrDER []byte, profile string, names []string, minRSABits int) ([]byte, error) {
		chain, _, err := signer.IssueLeafForNamesMinRSA(ctx, csrDER, profile, names, minRSABits)
		if err != nil {
			return nil, err
		}
		return chain[0], nil
	}
}

func scepCAChain(issuer node.IssuerFunc) scep.CAChainFunc {
	return func(ctx context.Context) ([]*x509.Certificate, error) {
		cert, err := issuer(ctx)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, errors.New("init: this node has no CA certificate")
		}
		return []*x509.Certificate{cert}, nil
	}
}

func scepIssued(store *revocation.Store) scep.IssuedFunc {
	return func(ctx context.Context, serialHex string) ([]byte, string, bool, error) {
		rec, ok, err := store.GetIssued(ctx, serialHex)
		if err != nil || !ok {
			return nil, "", ok, err
		}
		return rec.DER, rec.ProfileName, true, nil
	}
}

func scepRevoked(store *revocation.Store) scep.RevokedFunc {
	return func(ctx context.Context, serialHex string) (bool, error) {
		_, revoked, err := store.GetRevoked(ctx, serialHex)
		return revoked, err
	}
}

// newSCEPServer builds the SCEP responder for this boot, or returns nil when
// pki.scep is off or SCEP cannot be set up. The RA is ensured here, before
// any listener starts, so GetCACert has an RA to offer from the first
// request.
func newSCEPServer(ctx context.Context, cfg *config.Config, cli *clientv3.Client, load node.KeyLoader, issuer node.IssuerFunc,
	signer *node.CASigner, revStore *revocation.Store, revoker *nodeRevoker, auditor scep.Auditor) (*scep.Server, *scep.RAManager) {
	if cfg.PKI.SCEP == nil {
		return nil, nil
	}
	s := cfg.PKI.SCEP
	store := scep.NewStore(cli)
	ras, err := scep.NewRAManager(store, scepMintRA(load, issuer), scep.IssuerCertFunc(issuer), scep.RAOptions{
		Validity: s.RA.Validity(), Overlap: s.RA.Overlap(), Logf: log.Printf,
	})
	if err != nil {
		log.Printf("SCEP: off this boot: %v", err)
		return nil, nil
	}
	if err := ras.Ensure(ctx); err != nil {
		log.Printf("SCEP: off this boot: the RA certificate could not be set up: %v", err)
		return nil, nil
	}
	srv, err := scep.NewServer(store, ras, scep.Deps{
		Issue:   scepIssuer(signer),
		CAChain: scepCAChain(issuer),
		Revoked: scepRevoked(revStore),
		Issued:  scepIssued(revStore),
		CRL:     revoker.crlFn(),
		Auditor: auditor,
	}, scepOptions(s))
	if err != nil {
		log.Printf("SCEP: off this boot: %v", err)
		return nil, nil
	}
	floors := make([]string, 0, len(s.Profiles))
	for _, p := range s.Profiles {
		floors = append(floors, fmt.Sprintf("%s(rsa>=%d approval=%t)", p.Profile, p.RSAFloor(), p.RequireApproval))
	}
	log.Printf("SCEP: ready: profiles=%v allowlist=%v RA validity=%s overlap=%s",
		floors, s.AllowedIdentifierSuffixes, s.RA.Validity(), s.RA.Overlap())
	return srv, ras
}

// superviseSCEPRA re-checks the RA certificates on a timer, so the successor
// is minted when the rotation overlap begins and an expired RA is dropped,
// without a reboot.
func superviseSCEPRA(ctx context.Context, ras *scep.RAManager) {
	t := time.NewTicker(scepRAEnsureInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := ras.Ensure(ctx); err != nil {
				log.Printf("SCEP: RA check failed: %v (the current RA stays in use)", err)
			}
		}
	}
}
