package apiconformance_test

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
	"strings"
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestPkiCarriesScepBlock(t *testing.T) {
	pki := nodev1.File_cryptos_node_v1_config_proto.Messages().ByName("Pki")
	if pki == nil {
		t.Fatal("message Pki is not declared")
	}
	assertProtocolField(t, pki, "scep", protocolField{15, protoreflect.MessageKind, false, "cryptos.node.v1.Scep"})
}

func TestScepMirrorsNodeConfig(t *testing.T) {
	assertProtocolShape(t, nodev1.File_cryptos_node_v1_config_proto, "Scep", map[protoreflect.Name]protocolField{
		"enabled":                     {1, protoreflect.BoolKind, false, ""},
		"http_port":                   {2, protoreflect.Uint32Kind, false, ""},
		"profiles":                    {3, protoreflect.MessageKind, true, "cryptos.node.v1.ScepProfile"},
		"allowed_identifier_suffixes": {4, protoreflect.StringKind, true, ""},
		"ra":                          {5, protoreflect.MessageKind, false, "cryptos.node.v1.ScepRa"},
	})
	assertProtocolShape(t, nodev1.File_cryptos_node_v1_config_proto, "ScepProfile", map[protoreflect.Name]protocolField{
		"profile":          {1, protoreflect.StringKind, false, ""},
		"min_rsa_key_bits": {2, protoreflect.Uint32Kind, false, ""},
		"require_approval": {3, protoreflect.BoolKind, false, ""},
	})
	assertProtocolShape(t, nodev1.File_cryptos_node_v1_config_proto, "ScepRa", map[protoreflect.Name]protocolField{
		"validity_days":         {1, protoreflect.Uint32Kind, false, ""},
		"rotation_overlap_days": {2, protoreflect.Uint32Kind, false, ""},
	})
}

// Authorization is by one-time challenges only; a shared static challenge in
// the config would put one enrolment secret on every device.
func TestScepConfigHasNoStaticChallenge(t *testing.T) {
	for _, name := range []protoreflect.Name{"Scep", "ScepProfile", "ScepRa"} {
		md := nodev1.File_cryptos_node_v1_config_proto.Messages().ByName(name)
		if md == nil {
			t.Fatalf("message %s is not declared", name)
		}
		assertNoSecretFields(t, md)
	}
}

func TestServiceProtocolIncludesScep(t *testing.T) {
	ed := nodev1.File_cryptos_node_v1_status_proto.Enums().ByName("ServiceProtocol")
	if ed == nil {
		t.Fatal("enum ServiceProtocol is not declared")
	}
	v := ed.Values().ByName("SERVICE_PROTOCOL_SCEP")
	if v == nil {
		t.Fatal("ServiceProtocol.SERVICE_PROTOCOL_SCEP is not declared")
	}
	if v.Number() != 3 {
		t.Errorf("ServiceProtocol.SERVICE_PROTOCOL_SCEP = %d, want 3", v.Number())
	}
}

func TestNodeServiceDeclaresScepRPCs(t *testing.T) {
	svc := nodev1.File_cryptos_node_v1_node_proto.Services().ByName("NodeService")
	if svc == nil {
		t.Fatal("service NodeService is not declared")
	}
	for _, rpc := range []protoreflect.Name{
		"MintScepChallenge", "ListScepChallenges", "RevokeScepChallenge",
		"ListScepEnrollments", "ApproveScepEnrollment", "RejectScepEnrollment",
	} {
		m := svc.Methods().ByName(rpc)
		if m == nil {
			t.Errorf("NodeService.%s is not declared", rpc)
			continue
		}
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("NodeService.%s must be unary", rpc)
		}
		in, out := protoreflect.FullName("cryptos.node.v1."+rpc+"Request"), protoreflect.FullName("cryptos.node.v1."+rpc+"Response")
		if got := m.Input().FullName(); got != in {
			t.Errorf("NodeService.%s takes %s, want %s", rpc, got, in)
		}
		if got := m.Output().FullName(); got != out {
			t.Errorf("NodeService.%s returns %s, want %s", rpc, got, out)
		}
	}
}

func TestScepChallengeMessages(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_scep_proto
	assertProtocolShape(t, fd, "ScepChallenge", map[protoreflect.Name]protocolField{
		"id":            {1, protoreflect.StringKind, false, ""},
		"profile":       {2, protoreflect.StringKind, false, ""},
		"bound_names":   {3, protoreflect.StringKind, true, ""},
		"created_at":    {4, protoreflect.MessageKind, false, "google.protobuf.Timestamp"},
		"expires_at":    {5, protoreflect.MessageKind, false, "google.protobuf.Timestamp"},
		"created_by_cn": {6, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "MintScepChallengeRequest", map[protoreflect.Name]protocolField{
		"profile":     {1, protoreflect.StringKind, false, ""},
		"ttl_seconds": {2, protoreflect.Uint32Kind, false, ""},
		"bound_names": {3, protoreflect.StringKind, true, ""},
	})
	assertProtocolShape(t, fd, "MintScepChallengeResponse", map[protoreflect.Name]protocolField{
		"challenge_password": {1, protoreflect.StringKind, false, ""},
		"challenge":          {2, protoreflect.MessageKind, false, "cryptos.node.v1.ScepChallenge"},
	})
	assertProtocolShape(t, fd, "ListScepChallengesRequest", map[protoreflect.Name]protocolField{})
	assertProtocolShape(t, fd, "ListScepChallengesResponse", map[protoreflect.Name]protocolField{
		"challenges": {1, protoreflect.MessageKind, true, "cryptos.node.v1.ScepChallenge"},
	})
	assertProtocolShape(t, fd, "RevokeScepChallengeRequest", map[protoreflect.Name]protocolField{
		"id": {1, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "RevokeScepChallengeResponse", map[protoreflect.Name]protocolField{
		"challenge": {1, protoreflect.MessageKind, false, "cryptos.node.v1.ScepChallenge"},
	})
}

// The challenge is shown to the admin exactly once, at mint. A listing that
// carried it, or its digest, would let every reader enrol a device.
func TestScepChallengeNeverCarriesChallengeMaterial(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_scep_proto
	for _, name := range []protoreflect.Name{
		"ScepChallenge", "ListScepChallengesResponse", "RevokeScepChallengeResponse", "ScepEnrollment",
	} {
		md := fd.Messages().ByName(name)
		if md == nil {
			t.Errorf("message %s is not declared", name)
			continue
		}
		assertNoSecretFields(t, md)
	}
}

func TestScepEnrollmentMessages(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_scep_proto
	assertProtocolShape(t, fd, "ScepEnrollment", map[protoreflect.Name]protocolField{
		"id":             {1, protoreflect.StringKind, false, ""},
		"transaction_id": {2, protoreflect.StringKind, false, ""},
		"profile":        {3, protoreflect.StringKind, false, ""},
		"subject_dn":     {4, protoreflect.StringKind, false, ""},
		"dns_names":      {5, protoreflect.StringKind, true, ""},
		"ip_addresses":   {6, protoreflect.StringKind, true, ""},
		"key_alg":        {7, protoreflect.StringKind, false, ""},
		"csr_pem":        {8, protoreflect.StringKind, false, ""},
		"challenge_id":   {9, protoreflect.StringKind, false, ""},
		"received_at":    {10, protoreflect.MessageKind, false, "google.protobuf.Timestamp"},
	})
	assertProtocolShape(t, fd, "ListScepEnrollmentsRequest", map[protoreflect.Name]protocolField{
		"profile": {1, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "ListScepEnrollmentsResponse", map[protoreflect.Name]protocolField{
		"enrollments": {1, protoreflect.MessageKind, true, "cryptos.node.v1.ScepEnrollment"},
	})
	assertProtocolShape(t, fd, "ApproveScepEnrollmentRequest", map[protoreflect.Name]protocolField{
		"id": {1, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "ApproveScepEnrollmentResponse", map[protoreflect.Name]protocolField{
		"enrollment": {1, protoreflect.MessageKind, false, "cryptos.node.v1.ScepEnrollment"},
		"serial_hex": {2, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "RejectScepEnrollmentRequest", map[protoreflect.Name]protocolField{
		"id":     {1, protoreflect.StringKind, false, ""},
		"reason": {2, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "RejectScepEnrollmentResponse", map[protoreflect.Name]protocolField{
		"enrollment": {1, protoreflect.MessageKind, false, "cryptos.node.v1.ScepEnrollment"},
	})
}

func assertNoSecretFields(t *testing.T, md protoreflect.MessageDescriptor) {
	t.Helper()
	for i := range md.Fields().Len() {
		name := strings.ToLower(string(md.Fields().Get(i).Name()))
		for _, marker := range []string{"password", "secret", "hash", "digest", "sha256"} {
			if strings.Contains(name, marker) {
				t.Errorf("%s.%s looks like challenge material", md.Name(), name)
			}
		}
		if name == "challenge" && md.Fields().Get(i).Kind() != protoreflect.MessageKind {
			t.Errorf("%s.%s looks like challenge material", md.Name(), name)
		}
	}
}
