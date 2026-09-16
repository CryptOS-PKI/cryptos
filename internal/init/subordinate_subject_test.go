package init

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

// A subordinate names its own CA the same way the Root does, so it must carry
// the same RDNs -- an intermediate that signs other CAs is displayed widely.
func TestSubordinateSubjectCarriesProvinceAndLocality(t *testing.T) {
	cfg := &config.Config{}
	cfg.PKI.RootSubject = config.Subject{
		CommonName: "ACME Intermediate CA G1",
		Country:    "US",
		Province:   "CA",
		Locality:   "Example City",
	}

	n := subordinateSubject(cfg)

	if len(n.Province) != 1 || n.Province[0] != "CA" {
		t.Fatalf("Province = %v, want [CA]", n.Province)
	}
	if len(n.Locality) != 1 || n.Locality[0] != "Example City" {
		t.Fatalf("Locality = %v, want [Example City]", n.Locality)
	}
}
