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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

// mockUpgrader records what the handler passed through, so the tests can
// assert the thing that matters most: that an unauthorized or malformed call
// never reaches the code that writes to the ESP.
type mockUpgrader struct {
	stageErr    error
	rollbackErr error
	activateErr error
	statusErr   error

	staged      bool
	stagedImage []byte
	stagedSig   []byte
	rolledBack  bool
	activated   bool
	activatedCN string
}

func (m *mockUpgrader) Stage(_ context.Context, image, signature []byte) (*cryptosv1.ImageStatus, error) {
	m.staged = true
	m.stagedImage = image
	m.stagedSig = signature
	if m.stageErr != nil {
		return nil, m.stageErr
	}

	return &cryptosv1.ImageStatus{ActiveSha256: hexDigest(image), RebootPending: true}, nil
}

func (m *mockUpgrader) Rollback(context.Context) (*cryptosv1.ImageStatus, error) {
	m.rolledBack = true
	if m.rollbackErr != nil {
		return nil, m.rollbackErr
	}

	return &cryptosv1.ImageStatus{RebootPending: true}, nil
}

func (m *mockUpgrader) Activate(_ context.Context, confirmCommonName string) error {
	m.activated = true
	m.activatedCN = confirmCommonName

	return m.activateErr
}

func (m *mockUpgrader) Status(context.Context) (*cryptosv1.ImageStatus, error) {
	if m.statusErr != nil {
		return nil, m.statusErr
	}

	return &cryptosv1.ImageStatus{RunningSha256: "aa", ActiveSha256: "aa"}, nil
}

func hexDigest(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// stageStream is a client-streaming server stream fed from a fixed script.
type stageStream struct {
	ctx  context.Context
	msgs []*cryptosv1.StageImageRequest
	recv int
	resp *cryptosv1.StageImageResponse
}

func (s *stageStream) Context() context.Context { return s.ctx }

func (s *stageStream) Recv() (*cryptosv1.StageImageRequest, error) {
	if s.recv >= len(s.msgs) {
		return nil, io.EOF
	}
	m := s.msgs[s.recv]
	s.recv++

	return m, nil
}

func (s *stageStream) SendAndClose(resp *cryptosv1.StageImageResponse) error {
	s.resp = resp

	return nil
}

func (s *stageStream) SetHeader(metadata.MD) error  { return nil }
func (s *stageStream) SendHeader(metadata.MD) error { return nil }
func (s *stageStream) SetTrailer(metadata.MD)       {}
func (s *stageStream) SendMsg(any) error            { return nil }
func (s *stageStream) RecvMsg(any) error            { return nil }

func begin(sig []byte, size uint64, sha string) *cryptosv1.StageImageRequest {
	return &cryptosv1.StageImageRequest{
		Payload: &cryptosv1.StageImageRequest_Begin{
			Begin: &cryptosv1.StageImageBegin{Sha256: sha, Signature: sig, SizeBytes: size},
		},
	}
}

func chunk(b []byte) *cryptosv1.StageImageRequest {
	return &cryptosv1.StageImageRequest{Payload: &cryptosv1.StageImageRequest_Chunk{Chunk: b}}
}

// serverWithUpgrader mirrors how the mTLS listener is wired in internal/init:
// the upgrader plus the pinned bootstrap admin trust.
func serverWithUpgrader(t *testing.T, up ImageUpgrader, admin *x509.Certificate) *Server {
	t.Helper()

	srv, err := New(ServerConfig{
		Auditor:       &mockAuditor{},
		ImageUpgrader: up,
		TLSConfig:     mtlsTLSConfig(t),
		Trust:         trustForCert(t, admin),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return srv
}

// The upgrade #208 is for: an image arrives in chunks and is handed to the
// upgrader whole, and the caller is told a reboot is still needed.
func TestStageImage_AssemblesChunksAndReportsRebootPending(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	image := []byte("a unified kernel image, in pieces")
	st := &stageStream{
		ctx: authzMTLSContext(admin),
		msgs: []*cryptosv1.StageImageRequest{
			begin([]byte("sig"), uint64(len(image)), hexDigest(image)),
			chunk(image[:10]),
			chunk(image[10:]),
		},
	}

	if err := srv.StageImage(st); err != nil {
		t.Fatalf("StageImage: %v", err)
	}
	if got := string(up.stagedImage); got != string(image) {
		t.Errorf("staged image = %q, want the chunks reassembled in order", got)
	}
	if string(up.stagedSig) != "sig" {
		t.Errorf("staged signature = %q, want the one from the begin header", up.stagedSig)
	}
	if st.resp == nil || !st.resp.GetRequiresReboot() {
		t.Error("requires_reboot must be true: the staged image is not the running one")
	}
}

// A server with no upgrader wired (maintenance mode) refuses before auth is
// even considered.
func TestStageImage_UnimplementedWithoutAnUpgrader(t *testing.T) {
	srv, err := New(ServerConfig{Auditor: &mockAuditor{}, TLSConfig: mtlsTLSConfig(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = srv.StageImage(&stageStream{ctx: context.Background()})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}

// Writing the node's boot image is an admin operation. A caller who is not the
// pinned bootstrap admin must be denied before any image bytes are read, let
// alone handed to the ESP.
func TestStageImage_NonAdminIsDeniedBeforeReadingAnyBytes(t *testing.T) {
	admin := authzTestCert(t)
	other := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	st := &stageStream{
		ctx:  authzMTLSContext(other),
		msgs: []*cryptosv1.StageImageRequest{begin([]byte("sig"), 4, ""), chunk([]byte("evil"))},
	}
	if err := srv.StageImage(st); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if up.staged {
		t.Error("the upgrader was consulted for a non-admin caller")
	}
	if st.recv != 0 {
		t.Errorf("read %d messages from a denied caller, want 0", st.recv)
	}
}

// The header has to come first: without it there is no signature, so the image
// could not be verified and must not be accepted.
func TestStageImage_RefusesAStreamThatDoesNotBeginWithTheHeader(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	st := &stageStream{
		ctx:  authzMTLSContext(admin),
		msgs: []*cryptosv1.StageImageRequest{chunk([]byte("image"))},
	}
	if err := srv.StageImage(st); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if up.staged {
		t.Error("the upgrader was consulted for a stream with no begin header")
	}
}

// An empty signature is the same failure as a wrong one and is cheaper to
// catch here than after a few hundred megabytes have been uploaded.
func TestStageImage_RefusesAHeaderWithNoSignature(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	st := &stageStream{
		ctx:  authzMTLSContext(admin),
		msgs: []*cryptosv1.StageImageRequest{begin(nil, 5, ""), chunk([]byte("image"))},
	}
	if err := srv.StageImage(st); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if up.staged {
		t.Error("the upgrader was consulted for an unsigned transfer")
	}
}

// A truncated upload and a bad signature are different faults with different
// fixes, so the declared digest is checked separately and named in the error.
func TestStageImage_RefusesATruncatedUpload(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	image := []byte("the whole image")
	st := &stageStream{
		ctx: authzMTLSContext(admin),
		msgs: []*cryptosv1.StageImageRequest{
			begin([]byte("sig"), uint64(len(image)), hexDigest(image)),
			chunk(image[:5]),
		},
	}
	err := srv.StageImage(st)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if up.staged {
		t.Error("a truncated image was handed to the upgrader")
	}
}

// A sender that declares one size and streams more must not be able to grow
// the node's memory without bound.
func TestStageImage_RefusesMoreBytesThanDeclared(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	st := &stageStream{
		ctx: authzMTLSContext(admin),
		msgs: []*cryptosv1.StageImageRequest{
			begin([]byte("sig"), 4, ""),
			chunk([]byte("more than four bytes")),
		},
	}
	if err := srv.StageImage(st); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if up.staged {
		t.Error("the upgrader was consulted for an oversized transfer")
	}
}

// The declared size is checked before the upload rather than after it, so a
// hostile or mistaken caller cannot spend the node's memory to find out.
func TestStageImage_RefusesAnImplausiblySizedImageUpFront(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	st := &stageStream{
		ctx:  authzMTLSContext(admin),
		msgs: []*cryptosv1.StageImageRequest{begin([]byte("sig"), maxImageBytes+1, "")},
	}
	if err := srv.StageImage(st); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if st.recv != 1 {
		t.Errorf("read %d messages, want 1: the size is rejected before the upload", st.recv)
	}
}

// A signature the node cannot attribute is the caller's mistake -- most often
// a build signed with CI's per-run ephemeral key -- not a node fault, so it
// reads as InvalidArgument and not as an internal error an operator would go
// looking for on the node.
func TestStageImage_UnverifiableImageIsInvalidArgument(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{stageErr: fmt.Errorf("release key check: %w", ErrImageNotVerified)}
	srv := serverWithUpgrader(t, up, admin)

	image := []byte("image")
	st := &stageStream{
		ctx: authzMTLSContext(admin),
		msgs: []*cryptosv1.StageImageRequest{
			begin([]byte("sig"), uint64(len(image)), ""),
			chunk(image),
		},
	}
	if err := srv.StageImage(st); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// Anything else the upgrader reports is a node-side failure -- a full ESP, a
// mount that would not come up -- and must not be reported as bad input.
func TestStageImage_UpgraderFailureIsInternal(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{stageErr: errors.New("no space left on device")}
	srv := serverWithUpgrader(t, up, admin)

	image := []byte("image")
	st := &stageStream{
		ctx: authzMTLSContext(admin),
		msgs: []*cryptosv1.StageImageRequest{
			begin([]byte("sig"), uint64(len(image)), ""),
			chunk(image),
		},
	}
	if err := srv.StageImage(st); status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

func TestRollbackImage_RestoresAndRequiresReboot(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	resp, err := srv.RollbackImage(authzMTLSContext(admin), &cryptosv1.RollbackImageRequest{})
	if err != nil {
		t.Fatalf("RollbackImage: %v", err)
	}
	if !up.rolledBack {
		t.Error("the upgrader was not consulted")
	}
	if !resp.GetRequiresReboot() {
		t.Error("requires_reboot must be true: the restored image is not the running one")
	}
}

func TestRollbackImage_NothingRetainedIsFailedPrecondition(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{rollbackErr: ErrNoPreviousImage}
	srv := serverWithUpgrader(t, up, admin)

	_, err := srv.RollbackImage(authzMTLSContext(admin), &cryptosv1.RollbackImageRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestRollbackImage_NonAdminIsDenied(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	_, err := srv.RollbackImage(authzMTLSContext(authzTestCert(t)), &cryptosv1.RollbackImageRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if up.rolledBack {
		t.Error("the upgrader was consulted for a non-admin caller")
	}
}

// Rebooting an issuing CA takes every dependent system's certificate
// operations down with it, so it is confirmed the way the destructive RPCs
// are: by echoing the CA's common name.
func TestActivateImage_RequiresTheCACommonNameEcho(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{activateErr: reset.ErrConfirmMismatch}
	srv := serverWithUpgrader(t, up, admin)

	_, err := srv.ActivateImage(authzMTLSContext(admin), &cryptosv1.ActivateImageRequest{ConfirmCaCn: "WRONG"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if up.activatedCN != "WRONG" {
		t.Errorf("confirm CN = %q, want it passed through for the constant-time compare", up.activatedCN)
	}
}

func TestActivateImage_RebootsOnTheRightCN(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	resp, err := srv.ActivateImage(authzMTLSContext(admin), &cryptosv1.ActivateImageRequest{ConfirmCaCn: "Interborough Root CA"})
	if err != nil {
		t.Fatalf("ActivateImage: %v", err)
	}
	if !resp.GetRebooting() {
		t.Error("rebooting must be true so the caller knows the dropped connection is expected")
	}
	if up.activatedCN != "Interborough Root CA" {
		t.Errorf("confirm CN = %q", up.activatedCN)
	}
}

func TestActivateImage_NonAdminIsDenied(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{}
	srv := serverWithUpgrader(t, up, admin)

	_, err := srv.ActivateImage(authzMTLSContext(authzTestCert(t)), &cryptosv1.ActivateImageRequest{ConfirmCaCn: "Interborough Root CA"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if up.activated {
		t.Error("the node was rebooted for a non-admin caller")
	}
}

func TestGetImageStatus_ReportsWhatIsInstalled(t *testing.T) {
	admin := authzTestCert(t)
	srv := serverWithUpgrader(t, &mockUpgrader{}, admin)

	resp, err := srv.GetImageStatus(authzMTLSContext(admin), &cryptosv1.GetImageStatusRequest{})
	if err != nil {
		t.Fatalf("GetImageStatus: %v", err)
	}
	if resp.GetStatus().GetRunningSha256() == "" {
		t.Error("running_sha256 is empty")
	}
}

func TestGetImageStatus_UnimplementedWithoutAnUpgrader(t *testing.T) {
	srv, err := New(ServerConfig{Auditor: &mockAuditor{}, TLSConfig: mtlsTLSConfig(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = srv.GetImageStatus(context.Background(), &cryptosv1.GetImageStatusRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}

// A node with no CA identity yet cannot check the echo at all. That is a
// precondition, not a wrong CN, so the caller is not sent hunting for a typo.
func TestActivateImage_NoCAIdentityIsFailedPrecondition(t *testing.T) {
	admin := authzTestCert(t)
	up := &mockUpgrader{activateErr: reset.ErrNoCAIdentity}
	srv := serverWithUpgrader(t, up, admin)

	_, err := srv.ActivateImage(authzMTLSContext(admin), &cryptosv1.ActivateImageRequest{ConfirmCaCn: "Interborough Root CA"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), "no CA identity") {
		t.Errorf("message = %q, want it to say the node has no CA identity", status.Convert(err).Message())
	}
}
