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

// The Reboot RPC (#231): an operator-initiated, orderly reboot or power-off,
// so a config change that ApplyConfig reported as requires_reboot can take
// effect without a hypervisor hard reset.

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

// Rebooter schedules an orderly shutdown of a running node. It owns the
// constant-time compare of confirmCommonName against the node's CA CN
// (reset.ErrConfirmMismatch on a mismatch, taking no action) and returns
// before the node goes down, so the reply reaches the caller. It is wired on
// the mTLS and local servers of a running node; the maintenance servers leave
// it nil so Reboot returns Unimplemented there. Implemented in internal/init.
type Rebooter interface {
	Reboot(ctx context.Context, confirmCommonName string, powerOff bool) error
}

// Reboot handles cryptos.v1.NodeService/Reboot. It carries the same two
// guards as ActivateImage, for the same reason: rebooting an issuing CA takes
// every dependent system's certificate operations down with it, so the caller
// must be the bootstrap admin and must echo the CA common name.
func (s *Server) Reboot(ctx context.Context, req *cryptosv1.RebootRequest) (*cryptosv1.RebootResponse, error) {
	if s.cfg.Rebooter == nil {
		return nil, status.Error(codes.Unimplemented, "reboot is not available on this server")
	}
	if err := AuthorizeAdmin(ctx, s.cfg.Trust); err != nil {
		return nil, err
	}

	if err := s.cfg.Rebooter.Reboot(ctx, req.GetConfirmCaCn(), req.GetPowerOff()); err != nil {
		if errors.Is(err, reset.ErrConfirmMismatch) {
			return nil, status.Error(codes.PermissionDenied, "Reboot: confirmation CN does not match the CA CN")
		}
		return nil, status.Errorf(codes.Internal, "Reboot: %v", err)
	}

	return &cryptosv1.RebootResponse{Rebooting: true}, nil
}
