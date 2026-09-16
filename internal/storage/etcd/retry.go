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
	"syscall"
)

// maxPortAttempts bounds how many times Open re-picks ports after losing a
// bind race. Each attempt draws a fresh pair from the kernel, so a handful is
// ample: only a concurrent binder can take a port between pickFreePort's Close
// and etcd's bind, and it cannot keep winning against new ports (issue #189).
const maxPortAttempts = 5

// isAddrInUse reports whether err is a lost bind race, i.e. the port
// pickFreePort handed out was taken before the embedded etcd could bind it.
// Such an error says nothing about the caller's request and is safe to retry
// with a different port; any other error is returned to the caller as-is.
func isAddrInUse(err error) bool {
	return err != nil && errors.Is(err, syscall.EADDRINUSE)
}

// retryAddrInUse calls start until it succeeds, until it fails for a reason
// other than a lost bind race, or until attempts is exhausted. The error from
// the final attempt is wrapped so the underlying cause stays inspectable.
func retryAddrInUse(attempts int, start func() (*Server, error)) (*Server, error) {
	var err error
	for i := 0; i < attempts; i++ {
		var srv *Server
		srv, err = start()
		if err == nil {
			return srv, nil
		}
		if !isAddrInUse(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("etcd: no free port after %d attempts: %w", attempts, err)
}
