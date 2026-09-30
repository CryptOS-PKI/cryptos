package est

/*
Apache License 2.0

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
	"errors"
	"fmt"

	"github.com/CryptOS-PKI/cryptos/internal/cms"
)

// CertsOnlyPKCS7 builds the degenerate "certs-only" SignedData that EST uses
// to carry certificates (RFC 7030 sections 4.1.3 and 4.2.3; the structure is
// RFC 5652 section 5.2, which explicitly blesses a SignedData with no signers
// as the way to transport a certificate set). The encoding lives in
// internal/cms, shared with SCEP and RFC 3161.
//
// certs are DER certificates in the order they should appear, conventionally
// leaf first. At least one is required: an empty certs-only message is legal
// ASN.1 but means nothing to a client.
func CertsOnlyPKCS7(certs [][]byte) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("est: CertsOnlyPKCS7: at least one certificate is required")
	}
	out, err := cms.Degenerate(certs, nil)
	if err != nil {
		return nil, fmt.Errorf("est: CertsOnlyPKCS7: %w", err)
	}
	return out, nil
}

// ParseCertsOnlyPKCS7 extracts the DER certificates from a certs-only
// SignedData. It exists so the package can verify its own output in tests and
// so a caller can read a message it was handed; nothing on the serving path
// consumes CMS.
func ParseCertsOnlyPKCS7(der []byte) ([][]byte, error) {
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, fmt.Errorf("est: ParseCertsOnlyPKCS7: %w", err)
	}
	return sd.Certificates, nil
}
