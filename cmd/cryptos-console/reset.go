package main

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
	"io"
)

// readKeys streams single bytes from r onto the returned channel until r
// returns an error (for example when the process is torn down) or ctx is done.
// It closes the channel on exit so runConsole can drop the key source. The read
// is blocking, so the caller passes stdin already in raw mode; each byte is a
// keystroke rather than a buffered line.
func readKeys(ctx context.Context, r io.Reader) <-chan byte {
	ch := make(chan byte, 16)
	go func() {
		defer close(ch)
		buf := make([]byte, 1)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				select {
				case ch <- buf[0]:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return ch
}
