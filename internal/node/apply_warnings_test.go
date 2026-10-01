package node

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
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/config"
)

// A profile whose validity_days already runs past the CA's notAfter is applied,
// with a warning naming it; the apply is not refused.
func TestConfigStoreApply_WarnsWhenProfileOutlivesCA(t *testing.T) {
	seed, err := config.Parse([]byte(applyValidateSeed))
	if err != nil {
		t.Fatalf("config.Parse(seed): %v", err)
	}
	caNotAfter := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	issuer := func(context.Context) (*x509.Certificate, error) {
		return &x509.Certificate{NotAfter: caNotAfter}, nil
	}

	fs := config.NewFileStore(t.TempDir())
	if _, err := fs.Write([]byte(applyValidateSeed)); err != nil {
		t.Fatalf("FileStore.Write (seed): %v", err)
	}
	resp, err := NewConfigStore(fs).WithIssuer(issuer).Apply(context.Background(), seed.ToProto())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	w := resp.GetWarnings()
	if len(w) != 1 || !strings.Contains(w[0], `"leaf-server"`) || !strings.Contains(w[0], caNotAfter.Format(time.DateOnly)) {
		t.Fatalf("warnings = %q, want one naming leaf-server and %s", w, caNotAfter.Format(time.DateOnly))
	}

	resp, err = NewConfigStore(fs).Apply(context.Background(), seed.ToProto())
	if err != nil {
		t.Fatalf("Apply without issuer: %v", err)
	}
	if len(resp.GetWarnings()) != 0 {
		t.Fatalf("warnings without an issuer = %q, want none", resp.GetWarnings())
	}
}
