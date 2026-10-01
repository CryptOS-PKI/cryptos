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

type protocolField struct {
	num     protoreflect.FieldNumber
	kind    protoreflect.Kind
	list    bool
	typeRef protoreflect.FullName
}

func TestPkiCarriesProtocolBlocks(t *testing.T) {
	pki := nodev1.File_cryptos_node_v1_config_proto.Messages().ByName("Pki")
	if pki == nil {
		t.Fatal("message Pki is not declared")
	}
	for name, spec := range map[protoreflect.Name]protocolField{
		"acme": {13, protoreflect.MessageKind, false, "cryptos.node.v1.Acme"},
		"est":  {14, protoreflect.MessageKind, false, "cryptos.node.v1.Est"},
	} {
		assertProtocolField(t, pki, name, spec)
	}
}

func TestAcmeMirrorsNodeConfig(t *testing.T) {
	assertProtocolShape(t, nodev1.File_cryptos_node_v1_config_proto, "Acme", map[protoreflect.Name]protocolField{
		"enabled":                     {1, protoreflect.BoolKind, false, ""},
		"base_url":                    {2, protoreflect.StringKind, false, ""},
		"http_port":                   {3, protoreflect.Uint32Kind, false, ""},
		"profile":                     {4, protoreflect.StringKind, false, ""},
		"terms_of_service":            {5, protoreflect.StringKind, false, ""},
		"website":                     {6, protoreflect.StringKind, false, ""},
		"allow_anonymous_accounts":    {7, protoreflect.BoolKind, false, ""},
		"external_account_keys":       {8, protoreflect.MessageKind, true, "cryptos.node.v1.AcmeExternalAccountKey"},
		"allowed_identifier_suffixes": {9, protoreflect.StringKind, true, ""},
		"order_ttl_hours":             {10, protoreflect.Uint32Kind, false, ""},
	})
	assertProtocolShape(t, nodev1.File_cryptos_node_v1_config_proto, "AcmeExternalAccountKey", map[protoreflect.Name]protocolField{
		"key_id":          {1, protoreflect.StringKind, false, ""},
		"hmac_key_base64": {2, protoreflect.StringKind, false, ""},
	})
}

func TestEstMirrorsNodeConfig(t *testing.T) {
	assertProtocolShape(t, nodev1.File_cryptos_node_v1_config_proto, "Est", map[protoreflect.Name]protocolField{
		"enabled":                     {1, protoreflect.BoolKind, false, ""},
		"hostnames":                   {2, protoreflect.StringKind, true, ""},
		"http_port":                   {3, protoreflect.Uint32Kind, false, ""},
		"profile":                     {4, protoreflect.StringKind, false, ""},
		"label":                       {5, protoreflect.StringKind, false, ""},
		"realm":                       {6, protoreflect.StringKind, false, ""},
		"allowed_identifier_suffixes": {7, protoreflect.StringKind, true, ""},
		"allow_any_identifier":        {8, protoreflect.BoolKind, false, ""},
		"enroll_credentials":          {9, protoreflect.MessageKind, true, "cryptos.node.v1.EstEnrollCredential"},
	})
	assertProtocolShape(t, nodev1.File_cryptos_node_v1_config_proto, "EstEnrollCredential", map[protoreflect.Name]protocolField{
		"username":        {1, protoreflect.StringKind, false, ""},
		"password_sha256": {2, protoreflect.StringKind, false, ""},
	})
}

func TestNodeStatusReportsProtocolState(t *testing.T) {
	status := nodev1.File_cryptos_node_v1_status_proto.Messages().ByName("NodeStatus")
	if status == nil {
		t.Fatal("message NodeStatus is not declared")
	}
	for name, spec := range map[protoreflect.Name]protocolField{
		"protocols":             {11, protoreflect.MessageKind, true, "cryptos.node.v1.ProtocolStatus"},
		"config_reboot_pending": {12, protoreflect.BoolKind, false, ""},
	} {
		assertProtocolField(t, status, name, spec)
	}
	assertProtocolShape(t, nodev1.File_cryptos_node_v1_status_proto, "ProtocolStatus", map[protoreflect.Name]protocolField{
		"protocol":       {1, protoreflect.EnumKind, false, "cryptos.node.v1.ServiceProtocol"},
		"configured":     {2, protoreflect.BoolKind, false, ""},
		"running":        {3, protoreflect.BoolKind, false, ""},
		"reboot_pending": {4, protoreflect.BoolKind, false, ""},
	})
}

func TestServiceProtocolValues(t *testing.T) {
	ed := nodev1.File_cryptos_node_v1_status_proto.Enums().ByName("ServiceProtocol")
	if ed == nil {
		t.Fatal("enum ServiceProtocol is not declared")
	}
	for name, num := range map[protoreflect.Name]protoreflect.EnumNumber{
		"SERVICE_PROTOCOL_UNSPECIFIED": 0,
		"SERVICE_PROTOCOL_ACME":        1,
		"SERVICE_PROTOCOL_EST":         2,
	} {
		v := ed.Values().ByName(name)
		if v == nil {
			t.Errorf("ServiceProtocol.%s is not declared", name)
			continue
		}
		if v.Number() != num {
			t.Errorf("ServiceProtocol.%s = %d, want %d", name, v.Number(), num)
		}
	}
}

func assertProtocolShape(t *testing.T, fd protoreflect.FileDescriptor, name protoreflect.Name, want map[protoreflect.Name]protocolField) {
	t.Helper()
	md := fd.Messages().ByName(name)
	if md == nil {
		t.Fatalf("message %s is not declared", name)
	}
	if got := md.Fields().Len(); got != len(want) {
		t.Errorf("%s has %d fields, want %d", name, got, len(want))
	}
	for field, spec := range want {
		assertProtocolField(t, md, field, spec)
	}
}

func assertProtocolField(t *testing.T, md protoreflect.MessageDescriptor, name protoreflect.Name, spec protocolField) {
	t.Helper()
	fd := md.Fields().ByName(name)
	if fd == nil {
		t.Errorf("%s.%s is not declared", md.Name(), name)
		return
	}
	if fd.Number() != spec.num || fd.Kind() != spec.kind || fd.IsList() != spec.list {
		t.Errorf("%s.%s is field %d %v (list=%v), want %d %v (list=%v)",
			md.Name(), name, fd.Number(), fd.Kind(), fd.IsList(), spec.num, spec.kind, spec.list)
	}
	var ref protoreflect.FullName
	switch fd.Kind() {
	case protoreflect.MessageKind:
		ref = fd.Message().FullName()
	case protoreflect.EnumKind:
		ref = fd.Enum().FullName()
	}
	if ref != spec.typeRef {
		t.Errorf("%s.%s refers to %q, want %q", md.Name(), name, ref, spec.typeRef)
	}
}
