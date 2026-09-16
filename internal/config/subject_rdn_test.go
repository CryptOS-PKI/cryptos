package config

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

import "testing"

// The subject must survive the proto boundary intact in BOTH directions: the
// managed-state path serialises config to proto and back, so a dropped RDN
// there would silently change a CA's DN.
func TestSubjectProvinceLocalityRoundTripThroughProto(t *testing.T) {
	c := &Config{}
	c.PKI.RootSubject = Subject{
		CommonName:   "ACME Intermediate CA G1",
		Organization: "ACME",
		Country:      "US",
		Province:     "CA",
		Locality:     "Example City",
	}

	pb := c.ToProto()
	if pb.Pki.RootSubject.Province != "CA" {
		t.Fatalf("ToProto province = %q, want CA", pb.Pki.RootSubject.Province)
	}
	if pb.Pki.RootSubject.Locality != "Example City" {
		t.Fatalf("ToProto locality = %q, want Example City", pb.Pki.RootSubject.Locality)
	}

	back, err := FromProto(pb)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if got := back.PKI.RootSubject.Province; got != "CA" {
		t.Fatalf("FromProto province = %q, want CA", got)
	}
	if got := back.PKI.RootSubject.Locality; got != "Example City" {
		t.Fatalf("FromProto locality = %q, want Example City", got)
	}
}
