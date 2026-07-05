package revocation

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
	"context"
	"errors"
	"testing"
)

func TestPreflightFailsOnUnresolvableHost(t *testing.T) {
	p := NewPreflight("http://pki.acme.example",
		func(host string) error { return errors.New("no such host") },
		func(url string) error { return nil })
	if err := p.Check(context.Background()); err == nil || p.OK() {
		t.Fatal("expected preflight failure on DNS error")
	}
}

func TestPreflightPassesWhenResolvableAndReachable(t *testing.T) {
	p := NewPreflight("http://pki.acme.example",
		func(host string) error { return nil },
		func(url string) error { return nil })
	if err := p.Check(context.Background()); err != nil || !p.OK() {
		t.Fatalf("expected pass, err=%v ok=%v", err, p.OK())
	}
}
