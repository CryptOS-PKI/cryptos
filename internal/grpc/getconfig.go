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

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetConfig handles cryptos.v1.NodeService/GetConfig. It returns the node's
// currently persisted machine config so a caller can fetch the full config,
// edit a subset, and apply the whole config back via ApplyConfig (a
// whole-config replace) without dropping untouched fields such as management.
//
// It is a read of the same config ConfigStore.Current backs for SetManagement;
// like SetManagement it is only available on a running node (ConfigStore !=
// nil) and returns Unimplemented in maintenance mode.
func (s *Server) GetConfig(ctx context.Context, _ *cryptosv1.GetConfigRequest) (*cryptosv1.GetConfigResponse, error) {
	if s.cfg.ConfigStore == nil {
		return nil, status.Error(codes.Unimplemented, "GetConfig not available in maintenance mode")
	}
	cur, err := s.cfg.ConfigStore.Current(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "GetConfig: read config: %v", err)
	}
	return &cryptosv1.GetConfigResponse{Config: cur}, nil
}
