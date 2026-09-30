package grpc

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
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

type fakeRenewer struct {
	csr      []byte
	csrCalls int
	gotChain [][]byte
	identity *cryptosv1.Identity
}

func (f *fakeRenewer) RenewalCSR(context.Context) ([]byte, error) {
	f.csrCalls++
	return f.csr, nil
}

func (f *fakeRenewer) AcceptRenewal(_ context.Context, chainDER [][]byte) (*cryptosv1.Identity, error) {
	f.gotChain = chainDER
	return f.identity, nil
}

// TestRenewer_UnimplementedWhenNil verifies that with a nil Renewer (a Root and
// the maintenance servers) both re-certification RPCs refuse with Unimplemented.
func TestRenewer_UnimplementedWhenNil(t *testing.T) {
	srv, err := New(ServerConfig{TLSConfig: newFixtures(t).serverConf, Auditor: &mockAuditor{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.GetRenewalCSR(context.Background(), &cryptosv1.GetRenewalCSRRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("GetRenewalCSR code = %v, want Unimplemented", status.Code(err))
	}
	if _, err := srv.SubmitRenewedCertificate(context.Background(), &cryptosv1.SubmitRenewedCertificateRequest{ChainDer: [][]byte{[]byte("x")}}); status.Code(err) != codes.Unimplemented {
		t.Errorf("SubmitRenewedCertificate code = %v, want Unimplemented", status.Code(err))
	}
}

// TestRenewer_GetAndSubmit verifies the handlers pass through to the renewer
// for an authorized (local, no peer) caller.
func TestRenewer_GetAndSubmit(t *testing.T) {
	rn := &fakeRenewer{csr: []byte("renewal-csr"), identity: &cryptosv1.Identity{ChainPem: "RENEWED"}}
	srv, err := New(ServerConfig{TLSConfig: newFixtures(t).serverConf, Auditor: &mockAuditor{}, Renewer: rn})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := srv.GetRenewalCSR(context.Background(), &cryptosv1.GetRenewalCSRRequest{})
	if err != nil {
		t.Fatalf("GetRenewalCSR: %v", err)
	}
	if string(got.GetCsrDer()) != "renewal-csr" {
		t.Fatalf("GetRenewalCSR csr = %q", got.GetCsrDer())
	}
	resp, err := srv.SubmitRenewedCertificate(context.Background(), &cryptosv1.SubmitRenewedCertificateRequest{ChainDer: [][]byte{[]byte("leaf"), []byte("parent")}})
	if err != nil {
		t.Fatalf("SubmitRenewedCertificate: %v", err)
	}
	if len(rn.gotChain) != 2 || resp.GetIdentity().GetChainPem() != "RENEWED" {
		t.Fatalf("SubmitRenewedCertificate chain=%d identity=%v", len(rn.gotChain), resp.GetIdentity())
	}
}

// TestRenewer_RejectEmptyChain verifies InvalidArgument for an empty chain_der
// before the renewer is touched.
func TestRenewer_RejectEmptyChain(t *testing.T) {
	rn := &fakeRenewer{}
	srv, err := New(ServerConfig{TLSConfig: newFixtures(t).serverConf, Auditor: &mockAuditor{}, Renewer: rn})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.SubmitRenewedCertificate(context.Background(), &cryptosv1.SubmitRenewedCertificateRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("SubmitRenewedCertificate(empty) code = %v, want InvalidArgument", status.Code(err))
	}
	if rn.gotChain != nil {
		t.Fatal("renewer was consulted despite an empty chain")
	}
}

// TestRenewer_NonAdminIsPermissionDenied verifies that a peer presenting a
// certificate that is not the pinned admin is denied on BOTH RPCs (the CSR is
// signed with the CA key, so fetching it is admin-only too) before the renewer
// is consulted.
func TestRenewer_NonAdminIsPermissionDenied(t *testing.T) {
	rn := &fakeRenewer{identity: &cryptosv1.Identity{}}
	srv, err := New(ServerConfig{
		TLSConfig: newFixtures(t).serverConf,
		Auditor:   &mockAuditor{},
		Renewer:   rn,
		Trust:     trustForCert(t, authzTestCert(t)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := authzMTLSContext(authzTestCert(t)) // a different cert than the trust
	if _, err := srv.GetRenewalCSR(ctx, &cryptosv1.GetRenewalCSRRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("GetRenewalCSR code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := srv.SubmitRenewedCertificate(ctx, &cryptosv1.SubmitRenewedCertificateRequest{ChainDer: [][]byte{[]byte("leaf")}}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("SubmitRenewedCertificate code = %v, want PermissionDenied", status.Code(err))
	}
	if rn.csrCalls != 0 || rn.gotChain != nil {
		t.Fatal("renewer was consulted despite a denied caller")
	}
}
