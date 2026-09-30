package timesync

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
	"errors"
	"testing"
	"time"
)

func TestRequestHeader(t *testing.T) {
	nonce := Timestamp(0x0123456789abcdef)
	b := NewRequest(nonce).Marshal()
	if len(b) != PacketLen {
		t.Fatalf("request is %d bytes, want %d", len(b), PacketLen)
	}
	// LI=0, VN=4, Mode=3 (client).
	if b[0] != 0x23 {
		t.Fatalf("first octet = %#02x, want 0x23", b[0])
	}
	for i := 1; i < 40; i++ {
		if b[i] != 0 {
			t.Fatalf("octet %d = %#02x, want every field but Transmit Timestamp zero", i, b[i])
		}
	}
	h, err := ParseHeader(b)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Transmit != nonce {
		t.Fatalf("Transmit = %#x, want the nonce %#x", uint64(h.Transmit), uint64(nonce))
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	in := Header{
		Leap: 1, Version: 4, Mode: ModeServer, Stratum: 2, Poll: 6, Precision: -20,
		RootDelay: 0x00010000, RootDispersion: 0x00008000, ReferenceID: [4]byte{'G', 'P', 'S', 0},
		Reference: 1, Origin: 2, Receive: 3, Transmit: 4,
	}
	out, err := ParseHeader(in.Marshal())
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if out != in {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
}

func TestParseHeaderRejectsShortPacket(t *testing.T) {
	if _, err := ParseHeader(make([]byte, PacketLen-1)); err == nil {
		t.Fatal("ParseHeader accepted a 47-octet packet")
	}
}

// Extension fields and a MAC may follow the header; an SNTP client ignores
// them (RFC 4330 section 4).
func TestParseHeaderIgnoresTrailingData(t *testing.T) {
	b := append(NewRequest(7).Marshal(), make([]byte, 20)...)
	if _, err := ParseHeader(b); err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
}

func TestTimestampConversion(t *testing.T) {
	unixEpoch := time.Unix(0, 0).UTC()
	if got := TimestampFromTime(unixEpoch); got != Timestamp(uint64(2208988800)<<32) {
		t.Fatalf("Unix epoch = %#x, want 2208988800<<32", uint64(got))
	}
	half := unixEpoch.Add(500 * time.Millisecond)
	if got := TimestampFromTime(half); uint32(got) != 0x80000000 {
		t.Fatalf("fraction of 0.5 s = %#x, want 0x80000000", uint32(got))
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 123456789, time.UTC)
	back := TimestampFromTime(now).Time(now)
	if d := back.Sub(now); d < -time.Nanosecond || d > time.Nanosecond {
		t.Fatalf("round trip drifted by %v", d)
	}
}

// RFC 5905 section 6: the 32-bit seconds field wraps on 2036-02-07T06:28:16Z
// (the start of era 1). A timestamp maps into the era nearest the pivot, never
// assuming era 0.
func TestTimestampEraRollover(t *testing.T) {
	era1 := time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
	cases := []struct {
		name  string
		ts    Timestamp
		pivot time.Time
		want  time.Time
	}{
		{"era 1 start, pivot just after", 0, era1.Add(4 * time.Second), era1},
		{"era 1 start, pivot just before", 0, era1.Add(-4 * time.Second), era1},
		{"end of era 0, pivot after the wrap", Timestamp(uint64(0xfffffff0) << 32), era1.Add(time.Hour), era1.Add(-16 * time.Second)},
		{"well into era 1", Timestamp(uint64(86400) << 32), era1.Add(-time.Hour), era1.Add(24 * time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ts.Time(tc.pivot); !got.Equal(tc.want) {
				t.Fatalf("Time = %v, want %v", got, tc.want)
			}
		})
	}
	after := era1.Add(90 * time.Minute)
	if got := TimestampFromTime(after); uint64(got)>>32 != 5400 {
		t.Fatalf("seconds field after the wrap = %d, want 5400", uint64(got)>>32)
	}
}

func TestShortDuration(t *testing.T) {
	if got := Short(0x00018000).Duration(); got != 1500*time.Millisecond {
		t.Fatalf("Duration = %v, want 1.5s", got)
	}
}

func goodReply(nonce Timestamp) Header {
	return Header{
		Version: 4, Mode: ModeServer, Stratum: 2,
		RootDelay: 0x00000800, RootDispersion: 0x00000800,
		Origin: nonce, Receive: 100, Transmit: 101,
	}
}

func TestValidateReply(t *testing.T) {
	const nonce = Timestamp(0xfeedfacecafebeef)
	cases := []struct {
		name     string
		mutate   func(*Header)
		wantKiss string
		ok       bool
	}{
		{"good", func(*Header) {}, "", true},
		{"version 3 reply is accepted", func(h *Header) { h.Version = 3 }, "", true},
		{"version 2 is refused", func(h *Header) { h.Version = 2 }, "", false},
		{"version 5 is refused", func(h *Header) { h.Version = 5 }, "", false},
		{"client mode is not a reply", func(h *Header) { h.Mode = ModeClient }, "", false},
		{"broadcast is not a reply", func(h *Header) { h.Mode = 5 }, "", false},
		{"origin does not echo the nonce", func(h *Header) { h.Origin = nonce + 1 }, "", false},
		{"zero transmit timestamp", func(h *Header) { h.Transmit = 0 }, "", false},
		{"leap indicator 3 means the server is unsynchronised", func(h *Header) { h.Leap = 3 }, "", false},
		{"leap indicator 1 is a warning, not a failure", func(h *Header) { h.Leap = 1 }, "", true},
		{"stratum 16 is unsynchronised", func(h *Header) { h.Stratum = 16 }, "", false},
		{"stratum 15 is the last valid one", func(h *Header) { h.Stratum = 15 }, "", true},
		{"root distance over 1 s", func(h *Header) { h.RootDelay = 0x00020000 }, "", false},
		{"root dispersion over 1 s", func(h *Header) { h.RootDispersion = 0x00010001 }, "", false},
		{"kiss DENY", func(h *Header) { h.Stratum = 0; h.Leap = 3; h.ReferenceID = [4]byte{'D', 'E', 'N', 'Y'} }, "DENY", false},
		{"kiss RSTR", func(h *Header) { h.Stratum = 0; h.ReferenceID = [4]byte{'R', 'S', 'T', 'R'} }, "RSTR", false},
		{"kiss RATE", func(h *Header) { h.Stratum = 0; h.ReferenceID = [4]byte{'R', 'A', 'T', 'E'} }, "RATE", false},
		{"kiss with another code", func(h *Header) { h.Stratum = 0; h.ReferenceID = [4]byte{'I', 'N', 'I', 'T'} }, "INIT", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := goodReply(nonce)
			tc.mutate(&h)
			err := ValidateReply(h, nonce)
			if tc.ok {
				if err != nil {
					t.Fatalf("ValidateReply: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ValidateReply accepted a reply it must discard")
			}
			var kiss *KissError
			if tc.wantKiss != "" {
				if !errors.As(err, &kiss) || kiss.Code != tc.wantKiss {
					t.Fatalf("error = %v, want a kiss-o'-death %q", err, tc.wantKiss)
				}
			} else if errors.As(err, &kiss) {
				t.Fatalf("error = %v, want a plain rejection, not a kiss-o'-death", err)
			}
		})
	}
}

func TestComputeOffsetAndDelay(t *testing.T) {
	t1 := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(1500 * time.Millisecond)
	t3 := t1.Add(1600 * time.Millisecond)
	t4 := t1.Add(200 * time.Millisecond)
	h := Header{Receive: TimestampFromTime(t2), Transmit: TimestampFromTime(t3)}
	offset, delay, err := Compute(t1, t4, h, t1)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !near(offset, 1450*time.Millisecond) {
		t.Errorf("offset = %v, want 1.45s", offset)
	}
	if !near(delay, 100*time.Millisecond) {
		t.Errorf("delay = %v, want 100ms", delay)
	}
}

func TestComputeRejectsNegativeDelay(t *testing.T) {
	t1 := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	h := Header{Receive: TimestampFromTime(t1), Transmit: TimestampFromTime(t1.Add(time.Second))}
	if _, _, err := Compute(t1, t1.Add(10*time.Millisecond), h, t1); err == nil {
		t.Fatal("Compute accepted a negative round-trip delay")
	}
}

// Across the 2036 wrap the client and server timestamps sit in different eras;
// the offset must still be the true few seconds.
func TestComputeAcrossEraBoundary(t *testing.T) {
	era1 := time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
	t1 := era1.Add(-2 * time.Second)
	t4 := t1.Add(10 * time.Millisecond)
	srv := era1.Add(3 * time.Second)
	h := Header{Receive: TimestampFromTime(srv), Transmit: TimestampFromTime(srv)}
	offset, _, err := Compute(t1, t4, h, t1)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !near(offset, 4995*time.Millisecond) {
		t.Fatalf("offset = %v, want about 5s", offset)
	}
}

func TestCombine(t *testing.T) {
	s := func(name string, off time.Duration) Sample { return Sample{Server: name, Offset: off, Stratum: 2} }
	cases := []struct {
		name       string
		in         []Sample
		wantOffset time.Duration
		wantServer string
		disagree   bool
	}{
		{"one", []Sample{s("a", 3*time.Second)}, 3 * time.Second, "a", false},
		{"three take the median", []Sample{s("a", 2300*time.Millisecond), s("b", 2*time.Second), s("c", 2100*time.Millisecond)}, 2100 * time.Millisecond, "c", false},
		{"two take the mean", []Sample{s("a", 100*time.Millisecond), s("b", 300*time.Millisecond)}, 200 * time.Millisecond, "a", false},
		{"two more than 1 s apart", []Sample{s("a", 0), s("b", 5*time.Second)}, 0, "", true},
		{"one outlier among three", []Sample{s("a", 0), s("b", 10*time.Millisecond), s("c", 1500*time.Millisecond)}, 0, "", true},
		{"exactly 1 s apart agrees", []Sample{s("a", 0), s("b", time.Second)}, 500 * time.Millisecond, "a", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Combine(tc.in)
			if tc.disagree {
				if !errors.Is(err, ErrDisagree) {
					t.Fatalf("Combine error = %v, want ErrDisagree", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if got.Offset != tc.wantOffset || got.Server != tc.wantServer {
				t.Fatalf("Combine = %s %v, want %s %v", got.Server, got.Offset, tc.wantServer, tc.wantOffset)
			}
		})
	}
	if _, err := Combine(nil); err == nil {
		t.Fatal("Combine accepted no samples")
	}
}

func near(got, want time.Duration) bool {
	d := got - want
	return d > -time.Millisecond && d < time.Millisecond
}
