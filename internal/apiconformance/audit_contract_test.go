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
	"testing"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestNodeServiceDeclaresAuditRPCs(t *testing.T) {
	svc := nodev1.File_cryptos_node_v1_node_proto.Services().ByName("NodeService")
	if svc == nil {
		t.Fatal("service NodeService is not declared")
	}
	for name, io := range map[protoreflect.Name][2]protoreflect.FullName{
		"ListAuditEvents":  {"cryptos.node.v1.ListAuditEventsRequest", "cryptos.node.v1.ListAuditEventsResponse"},
		"VerifyAuditChain": {"cryptos.node.v1.VerifyAuditChainRequest", "cryptos.node.v1.VerifyAuditChainResponse"},
	} {
		m := svc.Methods().ByName(name)
		if m == nil {
			t.Errorf("NodeService.%s is not declared", name)
			continue
		}
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("NodeService.%s must be unary", name)
		}
		if got := m.Input().FullName(); got != io[0] {
			t.Errorf("NodeService.%s takes %s, want %s", name, got, io[0])
		}
		if got := m.Output().FullName(); got != io[1] {
			t.Errorf("NodeService.%s returns %s, want %s", name, got, io[1])
		}
	}
}

func TestAuditListMessages(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_audit_proto
	assertProtocolShape(t, fd, "AuditLogEntry", map[protoreflect.Name]protocolField{
		"event":        {1, protoreflect.MessageKind, false, "cryptos.node.v1.AuditEvent"},
		"entry_sha256": {2, protoreflect.BytesKind, false, ""},
		"target":       {3, protoreflect.StringKind, false, ""},
		"summary":      {4, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "ListAuditEventsRequest", map[protoreflect.Name]protocolField{
		"page_size":  {1, protoreflect.Int32Kind, false, ""},
		"page_token": {2, protoreflect.StringKind, false, ""},
		"from_time":  {3, protoreflect.StringKind, false, ""},
		"to_time":    {4, protoreflect.StringKind, false, ""},
		"event_type": {5, protoreflect.StringKind, false, ""},
		"actor":      {6, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "ListAuditEventsResponse", map[protoreflect.Name]protocolField{
		"entries":         {1, protoreflect.MessageKind, true, "cryptos.node.v1.AuditLogEntry"},
		"next_page_token": {2, protoreflect.StringKind, false, ""},
	})
}

func TestAuditVerifyMessages(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_audit_proto
	assertProtocolShape(t, fd, "VerifyAuditChainRequest", map[protoreflect.Name]protocolField{})
	assertProtocolShape(t, fd, "VerifyAuditChainResponse", map[protoreflect.Name]protocolField{
		"entry_count":           {1, protoreflect.Uint64Kind, false, ""},
		"intact":                {2, protoreflect.BoolKind, false, ""},
		"first_broken_sequence": {3, protoreflect.Uint64Kind, false, ""},
		"reason":                {4, protoreflect.StringKind, false, ""},
	})
}

// AuditLogEntry carries the stored AuditEvent as it is, so the fields the
// node signs and chains are pinned here too.
func TestAuditEventFieldsUnchanged(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_audit_proto
	assertProtocolShape(t, fd, "AuditEvent", map[protoreflect.Name]protocolField{
		"seq":                   {1, protoreflect.Uint64Kind, false, ""},
		"ts":                    {2, protoreflect.MessageKind, false, "google.protobuf.Timestamp"},
		"actor_subject":         {3, protoreflect.StringKind, false, ""},
		"rpc_method":            {4, protoreflect.StringKind, false, ""},
		"request_digest_sha256": {5, protoreflect.BytesKind, false, ""},
		"outcome":               {6, protoreflect.EnumKind, false, "cryptos.node.v1.Outcome"},
		"prev_entry_sha256":     {7, protoreflect.BytesKind, false, ""},
		"details":               {8, protoreflect.MessageKind, false, "cryptos.node.v1.AuditEvent.DetailsEntry"},
	})
}
