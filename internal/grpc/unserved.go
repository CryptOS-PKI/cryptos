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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// The RFC 3161 TSA RPCs are in the api contract, but this build does not
// serve a time-stamp authority yet. Each answers Unimplemented until its
// server lands and replaces the stub here.

func (s *Server) ListTsaCertificates(context.Context, *cryptosv1.ListTsaCertificatesRequest) (*cryptosv1.ListTsaCertificatesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "the RFC 3161 time-stamp authority is not served by this build")
}
