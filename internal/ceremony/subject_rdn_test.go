package ceremony

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
	"testing"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// A production CA DN needs state/province and locality, not just CN/O/C: the
// a real CA pair carries L=Example City, ST=<state>. RFC 5280 leaves
// these as ordinary RDNs, and pkix.Name models them, so the only question is
// whether config carries them through.
func TestSubjectFromConfigCarriesProvinceAndLocality(t *testing.T) {
	cfg := &config.Config{}
	cfg.PKI.RootSubject = config.Subject{
		CommonName:   "ACME Root CA G1",
		Organization: "ACME",
		Country:      "US",
		Province:     "CA",
		Locality:     "Example City",
	}

	n := subjectFromConfig(cfg)

	if len(n.Province) != 1 || n.Province[0] != "CA" {
		t.Fatalf("Province = %v, want [CA]", n.Province)
	}
	if len(n.Locality) != 1 || n.Locality[0] != "Example City" {
		t.Fatalf("Locality = %v, want [Example City]", n.Locality)
	}
}

// Empty RDNs stay absent rather than becoming empty strings in the DN, matching
// how Organization and Country already behave.
func TestSubjectFromConfigOmitsEmptyProvinceAndLocality(t *testing.T) {
	cfg := &config.Config{}
	cfg.PKI.RootSubject = config.Subject{CommonName: "Root Only"}

	n := subjectFromConfig(cfg)

	if len(n.Province) != 0 {
		t.Fatalf("Province = %v, want empty", n.Province)
	}
	if len(n.Locality) != 0 {
		t.Fatalf("Locality = %v, want empty", n.Locality)
	}
}
