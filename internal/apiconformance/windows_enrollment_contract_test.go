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

func TestPkiCarriesWindowsEnrollmentBlock(t *testing.T) {
	pki := nodev1.File_cryptos_node_v1_config_proto.Messages().ByName("Pki")
	if pki == nil {
		t.Fatal("message Pki is not declared")
	}
	assertProtocolField(t, pki, "windows_enrollment", protocolField{17, protoreflect.MessageKind, false, "cryptos.node.v1.WindowsEnrollment"})
}

func TestWindowsEnrollmentMirrorsNodeConfig(t *testing.T) {
	fd := nodev1.File_cryptos_node_v1_config_proto
	assertProtocolShape(t, fd, "WindowsEnrollment", map[protoreflect.Name]protocolField{
		"enabled":            {1, protoreflect.BoolKind, false, ""},
		"hostnames":          {2, protoreflect.StringKind, true, ""},
		"https_port":         {3, protoreflect.Uint32Kind, false, ""},
		"policy_path":        {4, protoreflect.StringKind, false, ""},
		"enrollment_path":    {5, protoreflect.StringKind, false, ""},
		"renewal_path":       {6, protoreflect.StringKind, false, ""},
		"kerberos":           {7, protoreflect.MessageKind, false, "cryptos.node.v1.WindowsKerberos"},
		"ldap":               {8, protoreflect.MessageKind, false, "cryptos.node.v1.WindowsLdap"},
		"templates":          {9, protoreflect.MessageKind, true, "cryptos.node.v1.WindowsTemplate"},
		"omit_sid_extension": {10, protoreflect.BoolKind, false, ""},
	})
	assertProtocolShape(t, fd, "WindowsKerberos", map[protoreflect.Name]protocolField{
		"realm":             {1, protoreflect.StringKind, false, ""},
		"service_principal": {2, protoreflect.StringKind, false, ""},
		"keytab":            {3, protoreflect.BytesKind, false, ""},
	})
	assertProtocolShape(t, fd, "WindowsLdap", map[protoreflect.Name]protocolField{
		"urls":      {1, protoreflect.StringKind, true, ""},
		"bind":      {2, protoreflect.MessageKind, false, "cryptos.node.v1.WindowsLdapBind"},
		"base_dns":  {3, protoreflect.StringKind, true, ""},
		"trust_pem": {4, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "WindowsLdapBind", map[protoreflect.Name]protocolField{
		"mode":      {1, protoreflect.StringKind, false, ""},
		"bind_dn":   {2, protoreflect.StringKind, false, ""},
		"password":  {3, protoreflect.StringKind, false, ""},
		"principal": {4, protoreflect.StringKind, false, ""},
	})
	assertProtocolShape(t, fd, "WindowsTemplate", map[protoreflect.Name]protocolField{
		"name":                      {1, protoreflect.StringKind, false, ""},
		"profile":                   {2, protoreflect.StringKind, false, ""},
		"enrollment_type":           {3, protoreflect.StringKind, false, ""},
		"allow_certificate_renewal": {4, protoreflect.BoolKind, false, ""},
		"allowed_groups":            {5, protoreflect.StringKind, true, ""},
		"renewal_period_days":       {6, protoreflect.Uint32Kind, false, ""},
	})
}

// The SID extension is what lets a domain controller map a certificate to its
// account under strong certificate binding, so a block written without the
// switch must still carry it.
func TestWindowsEnrollmentAddsSidExtensionByDefault(t *testing.T) {
	if (&nodev1.WindowsEnrollment{}).GetOmitSidExtension() {
		t.Error("a zero WindowsEnrollment omits the SID extension, want it carried")
	}
}

func TestServiceProtocolIncludesWindowsEnrollment(t *testing.T) {
	ed := nodev1.File_cryptos_node_v1_status_proto.Enums().ByName("ServiceProtocol")
	if ed == nil {
		t.Fatal("enum ServiceProtocol is not declared")
	}
	v := ed.Values().ByName("SERVICE_PROTOCOL_WINDOWS_ENROLLMENT")
	if v == nil {
		t.Fatal("ServiceProtocol.SERVICE_PROTOCOL_WINDOWS_ENROLLMENT is not declared")
	}
	if v.Number() != 5 {
		t.Errorf("ServiceProtocol.SERVICE_PROTOCOL_WINDOWS_ENROLLMENT = %d, want 5", v.Number())
	}
}
