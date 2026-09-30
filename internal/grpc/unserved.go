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

// The SCEP and RFC 3161 TSA RPCs are in the api contract, but this build does
// not serve either protocol yet. Each answers Unimplemented until its server
// lands and replaces the stub here.

func (s *Server) MintScepChallenge(context.Context, *cryptosv1.MintScepChallengeRequest) (*cryptosv1.MintScepChallengeResponse, error) {
	return nil, errSCEPUnserved
}

func (s *Server) ListScepChallenges(context.Context, *cryptosv1.ListScepChallengesRequest) (*cryptosv1.ListScepChallengesResponse, error) {
	return nil, errSCEPUnserved
}

func (s *Server) RevokeScepChallenge(context.Context, *cryptosv1.RevokeScepChallengeRequest) (*cryptosv1.RevokeScepChallengeResponse, error) {
	return nil, errSCEPUnserved
}

func (s *Server) ListScepEnrollments(context.Context, *cryptosv1.ListScepEnrollmentsRequest) (*cryptosv1.ListScepEnrollmentsResponse, error) {
	return nil, errSCEPUnserved
}

func (s *Server) ApproveScepEnrollment(context.Context, *cryptosv1.ApproveScepEnrollmentRequest) (*cryptosv1.ApproveScepEnrollmentResponse, error) {
	return nil, errSCEPUnserved
}

func (s *Server) RejectScepEnrollment(context.Context, *cryptosv1.RejectScepEnrollmentRequest) (*cryptosv1.RejectScepEnrollmentResponse, error) {
	return nil, errSCEPUnserved
}

func (s *Server) ListTsaCertificates(context.Context, *cryptosv1.ListTsaCertificatesRequest) (*cryptosv1.ListTsaCertificatesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "the RFC 3161 time-stamp authority is not served by this build")
}

var errSCEPUnserved = status.Error(codes.Unimplemented, "SCEP is not served by this build")
