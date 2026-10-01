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

type fieldSpec struct {
	num  protoreflect.FieldNumber
	kind protoreflect.Kind
	list bool
}

func TestNodeServiceDeclaresGetIssuedCertificate(t *testing.T) {
	m := nodev1.File_cryptos_node_v1_node_proto.Services().ByName("NodeService").Methods().ByName("GetIssuedCertificate")
	if m == nil {
		t.Fatal("NodeService.GetIssuedCertificate is not declared")
	}
	if m.IsStreamingClient() || m.IsStreamingServer() {
		t.Error("NodeService.GetIssuedCertificate must be unary")
	}
	if got := m.Input().FullName(); got != "cryptos.node.v1.GetIssuedCertificateRequest" {
		t.Errorf("GetIssuedCertificate takes %s", got)
	}
	if got := m.Output().FullName(); got != "cryptos.node.v1.GetIssuedCertificateResponse" {
		t.Errorf("GetIssuedCertificate returns %s", got)
	}
}

func TestGetIssuedCertificateMessages(t *testing.T) {
	assertShape(t, "GetIssuedCertificateRequest", map[protoreflect.Name]fieldSpec{
		"serial_hex": {1, protoreflect.StringKind, false},
	})
	assertShape(t, "GetIssuedCertificateResponse", map[protoreflect.Name]fieldSpec{
		"certificate_der": {1, protoreflect.BytesKind, false},
		"chain_der":       {2, protoreflect.BytesKind, true},
		"status":          {3, protoreflect.StringKind, false},
		"revoked_at":      {4, protoreflect.StringKind, false},
	})
}

func assertShape(t *testing.T, name protoreflect.Name, want map[protoreflect.Name]fieldSpec) {
	t.Helper()
	md := nodev1.File_cryptos_node_v1_node_proto.Messages().ByName(name)
	if md == nil {
		t.Fatalf("message %s is not declared", name)
	}
	if got := md.Fields().Len(); got != len(want) {
		t.Errorf("%s has %d fields, want %d", name, got, len(want))
	}
	for field, spec := range want {
		fd := md.Fields().ByName(field)
		if fd == nil {
			t.Errorf("%s.%s is not declared", name, field)
			continue
		}
		if fd.Number() != spec.num || fd.Kind() != spec.kind || fd.IsList() != spec.list {
			t.Errorf("%s.%s is field %d %v (list=%v), want %d %v (list=%v)",
				name, field, fd.Number(), fd.Kind(), fd.IsList(), spec.num, spec.kind, spec.list)
		}
	}
}
