package cms

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
	"bytes"
	"testing"
)

// toIndefiniteBER re-encodes a DER message the way a streaming encoder
// would: every constructed element gets an indefinite length, and the
// primitive OCTET STRING holding chunked is split into a constructed OCTET
// STRING of 7-byte pieces. It only has to handle DER input with single-byte
// tags, which is all this package produces.
func toIndefiniteBER(t *testing.T, der, chunked []byte) []byte {
	t.Helper()
	out, rest := rewriteBER(t, der, chunked)
	if len(rest) != 0 {
		t.Fatal("toIndefiniteBER: trailing bytes")
	}
	return out
}

func rewriteBER(t *testing.T, b, chunked []byte) (out, rest []byte) {
	t.Helper()
	if len(b) < 2 {
		t.Fatal("toIndefiniteBER: truncated")
	}
	tag := b[0]
	length, hdr := 0, 2
	if b[1] < 0x80 {
		length = int(b[1])
	} else {
		n := int(b[1] & 0x7f)
		for i := 0; i < n; i++ {
			length = length<<8 | int(b[2+i])
		}
		hdr = 2 + n
	}
	body := b[hdr : hdr+length]
	rest = b[hdr+length:]

	if tag == 0x04 && chunked != nil && bytes.Equal(body, chunked) {
		out = []byte{0x24, 0x80}
		for len(body) > 0 {
			n := min(7, len(body))
			out = append(out, 0x04, byte(n))
			out = append(out, body[:n]...)
			body = body[n:]
		}
		return append(out, 0x00, 0x00), rest
	}
	if tag&0x20 == 0 {
		return b[:hdr+length], rest
	}
	out = []byte{tag, 0x80}
	for len(body) > 0 {
		var child []byte
		child, body = rewriteBER(t, body, chunked)
		out = append(out, child...)
	}
	return append(out, 0x00, 0x00), rest
}
