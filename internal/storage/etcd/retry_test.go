package etcd

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
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

// addrInUseErr builds the error shape the kernel produces for a losing bind,
// as embed.StartEtcd surfaces it (issue #189).
func addrInUseErr() error {
	return &net.OpError{
		Op:  "listen",
		Net: "tcp",
		Err: syscall.EADDRINUSE,
	}
}

func TestIsAddrInUseMatchesWrappedErrno(t *testing.T) {
	err := fmt.Errorf("etcd: StartEtcd: %w", addrInUseErr())
	if !isAddrInUse(err) {
		t.Fatalf("expected a wrapped EADDRINUSE to be retryable, got false for %v", err)
	}
}

func TestIsAddrInUseRejectsUnrelatedError(t *testing.T) {
	if isAddrInUse(fmt.Errorf("etcd: StartEtcd: %w", errors.New("data dir is corrupt"))) {
		t.Fatal("expected an unrelated error to be non-retryable")
	}
}

func TestIsAddrInUseRejectsNil(t *testing.T) {
	if isAddrInUse(nil) {
		t.Fatal("expected nil to be non-retryable")
	}
}

func TestRetryAddrInUseRetriesUntilStartSucceeds(t *testing.T) {
	calls := 0
	srv, err := retryAddrInUse(5, func() (*Server, error) {
		calls++
		if calls < 3 {
			return nil, fmt.Errorf("etcd: StartEtcd: %w", addrInUseErr())
		}
		return &Server{dataDir: "ok"}, nil
	})
	if err != nil {
		t.Fatalf("expected success after transient bind losses, got %v", err)
	}
	if srv == nil || srv.dataDir != "ok" {
		t.Fatalf("expected the successful Server to be returned, got %+v", srv)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

func TestRetryAddrInUseDoesNotRetryOtherErrors(t *testing.T) {
	calls := 0
	_, err := retryAddrInUse(5, func() (*Server, error) {
		calls++
		return nil, errors.New("data dir is corrupt")
	})
	if err == nil {
		t.Fatal("expected the non-retryable error to be returned")
	}
	if calls != 1 {
		t.Fatalf("a non-retryable error must not be retried; got %d attempts", calls)
	}
}

func TestRetryAddrInUseGivesUpAfterAttempts(t *testing.T) {
	calls := 0
	_, err := retryAddrInUse(3, func() (*Server, error) {
		calls++
		return nil, fmt.Errorf("etcd: StartEtcd: %w", addrInUseErr())
	})
	if err == nil {
		t.Fatal("expected an error once attempts are exhausted")
	}
	if calls != 3 {
		t.Fatalf("expected exactly 3 attempts, got %d", calls)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("expected the final error to wrap EADDRINUSE for diagnosis, got %v", err)
	}
}
