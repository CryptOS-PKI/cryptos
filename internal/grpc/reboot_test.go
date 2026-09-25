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
	"crypto/x509"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

// mockRebooter records what the Reboot handler passed through.
type mockRebooter struct {
	err      error
	called   bool
	cn       string
	powerOff bool
}

func (m *mockRebooter) Reboot(_ context.Context, confirmCommonName string, powerOff bool) error {
	m.called = true
	m.cn = confirmCommonName
	m.powerOff = powerOff

	return m.err
}

func serverWithRebooter(t *testing.T, rb Rebooter, admin *x509.Certificate) *Server {
	t.Helper()

	srv, err := New(ServerConfig{
		Auditor:   &mockAuditor{},
		Rebooter:  rb,
		TLSConfig: mtlsTLSConfig(t),
		Trust:     trustForCert(t, admin),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return srv
}

func TestReboot_UnimplementedWithoutARebooter(t *testing.T) {
	srv, err := New(ServerConfig{Auditor: &mockAuditor{}, TLSConfig: mtlsTLSConfig(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = srv.Reboot(context.Background(), &cryptosv1.RebootRequest{ConfirmCaCn: "Interborough Root CA"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}

// A reboot takes the CA offline, so a caller that is not the bootstrap admin
// is refused before the rebooter is consulted.
func TestReboot_NonAdminIsDenied(t *testing.T) {
	admin := authzTestCert(t)
	rb := &mockRebooter{}
	srv := serverWithRebooter(t, rb, admin)

	_, err := srv.Reboot(authzMTLSContext(authzTestCert(t)), &cryptosv1.RebootRequest{ConfirmCaCn: "Interborough Root CA"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if rb.called {
		t.Error("the node was rebooted for a non-admin caller")
	}
}

func TestReboot_WrongCNIsPermissionDenied(t *testing.T) {
	admin := authzTestCert(t)
	rb := &mockRebooter{err: reset.ErrConfirmMismatch}
	srv := serverWithRebooter(t, rb, admin)

	_, err := srv.Reboot(authzMTLSContext(admin), &cryptosv1.RebootRequest{ConfirmCaCn: "WRONG"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if rb.cn != "WRONG" {
		t.Errorf("confirm CN = %q, want it passed through for the constant-time compare", rb.cn)
	}
}

func TestReboot_AcceptsTheRightCNAndPassesPowerOff(t *testing.T) {
	admin := authzTestCert(t)
	rb := &mockRebooter{}
	srv := serverWithRebooter(t, rb, admin)

	resp, err := srv.Reboot(authzMTLSContext(admin), &cryptosv1.RebootRequest{ConfirmCaCn: "Interborough Root CA", PowerOff: true})
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if !resp.GetRebooting() {
		t.Error("rebooting must be true so the caller knows the dropped connection is expected")
	}
	if rb.cn != "Interborough Root CA" || !rb.powerOff {
		t.Errorf("rebooter got cn=%q powerOff=%t", rb.cn, rb.powerOff)
	}
}

func TestReboot_RebooterFailureIsInternal(t *testing.T) {
	admin := authzTestCert(t)
	srv := serverWithRebooter(t, &mockRebooter{err: errors.New("boom")}, admin)

	_, err := srv.Reboot(authzMTLSContext(admin), &cryptosv1.RebootRequest{ConfirmCaCn: "Interborough Root CA"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

func TestReboot_NoCAIdentityIsFailedPrecondition(t *testing.T) {
	admin := authzTestCert(t)
	rb := &mockRebooter{err: reset.ErrNoCAIdentity}
	srv := serverWithRebooter(t, rb, admin)

	_, err := srv.Reboot(authzMTLSContext(admin), &cryptosv1.RebootRequest{ConfirmCaCn: "Interborough Root CA"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
}
