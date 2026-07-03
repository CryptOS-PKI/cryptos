package netlink

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
	"net/netip"
	"testing"
)

func TestRTAAlign(t *testing.T) {
	cases := map[int]int{0: 0, 1: 4, 4: 4, 5: 8, 8: 8}
	for in, want := range cases {
		if got := rtaAlign(in); got != want {
			t.Errorf("rtaAlign(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestAttr(t *testing.T) {
	a := attr(ifaLocal, []byte{10, 0, 0, 10})
	if len(a) != 8 {
		t.Fatalf("attr len = %d, want 8 (4 hdr + 4 data)", len(a))
	}
	if got := native.Uint16(a[0:2]); got != 8 {
		t.Errorf("rta_len = %d, want 8", got)
	}
	if got := native.Uint16(a[2:4]); got != ifaLocal {
		t.Errorf("rta_type = %d, want %d", got, ifaLocal)
	}
	// Data with padding: 3-byte value -> rta_len 7, buffer padded to 8.
	p := attr(rtaOif, []byte{1, 2, 3})
	if len(p) != 8 {
		t.Errorf("padded attr len = %d, want 8", len(p))
	}
	if got := native.Uint16(p[0:2]); got != 7 {
		t.Errorf("padded rta_len = %d, want 7 (unpadded)", got)
	}
}

func TestBuildLinkUpRequest(t *testing.T) {
	msg := buildLinkUpRequest(1, 7)
	if len(msg) != nlmsghdrLen+ifinfomsgLen {
		t.Fatalf("len = %d, want %d", len(msg), nlmsghdrLen+ifinfomsgLen)
	}
	if native.Uint32(msg[0:4]) != uint32(len(msg)) {
		t.Error("nlmsg_len mismatch")
	}
	if native.Uint16(msg[4:6]) != rtmNewLink {
		t.Error("nlmsg_type != RTM_NEWLINK")
	}
	if native.Uint16(msg[6:8]) != (nlmFRequest | nlmFAck) {
		t.Error("flags != REQUEST|ACK")
	}
	body := msg[nlmsghdrLen:]
	if native.Uint32(body[4:8]) != 7 {
		t.Error("ifi_index != 7")
	}
	if native.Uint32(body[8:12]) != iffUp {
		t.Error("ifi_flags != IFF_UP")
	}
	if native.Uint32(body[12:16]) != iffUp {
		t.Error("ifi_change != IFF_UP")
	}
}

func TestBuildAddrRequest(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.10/24")
	msg := buildAddrRequest(2, 7, p)
	// 16 (nlmsghdr) + 8 (ifaddrmsg) + 8 (IFA_LOCAL) + 8 (IFA_ADDRESS).
	if len(msg) != 40 {
		t.Fatalf("len = %d, want 40", len(msg))
	}
	if native.Uint16(msg[4:6]) != rtmNewAddr {
		t.Error("type != RTM_NEWADDR")
	}
	if native.Uint16(msg[6:8]) != (nlmFRequest | nlmFAck | nlmFCreate | nlmFReplace) {
		t.Error("flags mismatch")
	}
	body := msg[nlmsghdrLen:]
	if body[0] != afInet {
		t.Error("ifa_family != AF_INET")
	}
	if body[1] != 24 {
		t.Errorf("ifa_prefixlen = %d, want 24", body[1])
	}
	if native.Uint32(body[4:8]) != 7 {
		t.Error("ifa_index != 7")
	}
	// First attr: IFA_LOCAL = 10.0.0.10
	a1 := body[ifaddrmsgLen:]
	if native.Uint16(a1[2:4]) != ifaLocal {
		t.Error("first attr type != IFA_LOCAL")
	}
	if got := [4]byte{a1[4], a1[5], a1[6], a1[7]}; got != [4]byte{10, 0, 0, 10} {
		t.Errorf("IFA_LOCAL addr = %v, want 10.0.0.10", got)
	}
	// Second attr: IFA_ADDRESS
	a2 := a1[8:]
	if native.Uint16(a2[2:4]) != ifaAddress {
		t.Error("second attr type != IFA_ADDRESS")
	}
}

func TestBuildDefaultRouteRequest(t *testing.T) {
	gw := netip.MustParseAddr("10.0.0.1")
	msg := buildDefaultRouteRequest(3, 7, gw)
	// 16 + 12 (rtmsg) + 8 (RTA_GATEWAY) + 8 (RTA_OIF).
	if len(msg) != 44 {
		t.Fatalf("len = %d, want 44", len(msg))
	}
	if native.Uint16(msg[4:6]) != rtmNewRoute {
		t.Error("type != RTM_NEWROUTE")
	}
	if native.Uint16(msg[6:8]) != (nlmFRequest | nlmFAck | nlmFCreate | nlmFReplace) {
		t.Error("flags mismatch")
	}
	body := msg[nlmsghdrLen:]
	if body[0] != afInet {
		t.Error("rtm_family != AF_INET")
	}
	if body[1] != 0 {
		t.Error("rtm_dst_len != 0 (default route)")
	}
	if body[4] != rtTableMain || body[7] != rtnUnicast {
		t.Error("rtm table/type mismatch")
	}
	a1 := body[rtmsgLen:]
	if native.Uint16(a1[2:4]) != rtaGateway {
		t.Error("first attr != RTA_GATEWAY")
	}
	if got := [4]byte{a1[4], a1[5], a1[6], a1[7]}; got != [4]byte{10, 0, 0, 1} {
		t.Errorf("gateway = %v, want 10.0.0.1", got)
	}
	a2 := a1[8:]
	if native.Uint16(a2[2:4]) != rtaOif {
		t.Error("second attr != RTA_OIF")
	}
	if native.Uint32(a2[4:8]) != 7 {
		t.Error("RTA_OIF index != 7")
	}
}

func TestParseAck(t *testing.T) {
	// Success: NLMSG_ERROR with errno 0.
	ok := make([]byte, nlmsghdrLen+4)
	native.PutUint16(ok[4:6], nlmsgError)
	if errno, found := parseAck(ok); !found || errno != 0 {
		t.Errorf("parseAck(success) = (%d,%v), want (0,true)", errno, found)
	}
	// Failure: errno -17 (-EEXIST).
	fail := make([]byte, nlmsghdrLen+4)
	native.PutUint16(fail[4:6], nlmsgError)
	var negErr int32 = -17
	native.PutUint32(fail[nlmsghdrLen:], uint32(negErr))
	if errno, found := parseAck(fail); !found || errno != -17 {
		t.Errorf("parseAck(fail) = (%d,%v), want (-17,true)", errno, found)
	}
	// Not an ERROR message (type 0 != NLMSG_ERROR).
	if _, found := parseAck(make([]byte, nlmsghdrLen+4)); found {
		t.Error("parseAck(non-error type) should not be ok")
	}
	if _, found := parseAck([]byte{1, 2}); found {
		t.Error("parseAck(short) should not be ok")
	}
}

// fakeNetlink records the requests configure/bringUpLoopback would send.
type fakeNetlink struct {
	indexByName map[string]int
	indexErr    error
	sent        [][]byte
	sendErr     error
}

func (f *fakeNetlink) index(name string) (int, error) {
	if f.indexErr != nil {
		return 0, f.indexErr
	}
	return f.indexByName[name], nil
}

func (f *fakeNetlink) send(msg []byte) error {
	f.sent = append(f.sent, msg)
	return f.sendErr
}

func TestConfigure_SequenceAndOrder(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"eth0": 3}}
	cfg := Config{
		Name:    "eth0",
		Address: netip.MustParsePrefix("10.0.0.10/24"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
	}
	if err := configure(cfg, f.index, f.send); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(f.sent) != 3 {
		t.Fatalf("sent %d requests, want 3 (link up, addr, route)", len(f.sent))
	}
	types := []uint16{rtmNewLink, rtmNewAddr, rtmNewRoute}
	for i, want := range types {
		if got := native.Uint16(f.sent[i][4:6]); got != want {
			t.Errorf("request[%d] type = %d, want %d", i, got, want)
		}
	}
}

func TestConfigure_NoGatewaySkipsRoute(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"eth0": 3}}
	cfg := Config{Name: "eth0", Address: netip.MustParsePrefix("10.0.0.10/24")}
	if err := configure(cfg, f.index, f.send); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if len(f.sent) != 2 {
		t.Errorf("sent %d, want 2 (no gateway => no route)", len(f.sent))
	}
}

func TestConfigure_Errors(t *testing.T) {
	good := Config{Name: "eth0", Address: netip.MustParsePrefix("10.0.0.10/24")}

	if err := configure(Config{}, (&fakeNetlink{}).index, (&fakeNetlink{}).send); err == nil {
		t.Error("empty config should error")
	}
	// index lookup failure.
	f := &fakeNetlink{indexErr: errors.New("no such device")}
	if err := configure(good, f.index, f.send); err == nil {
		t.Error("index error should propagate")
	}
	// send failure on the first (link-up) request aborts.
	f2 := &fakeNetlink{indexByName: map[string]int{"eth0": 3}, sendErr: errors.New("boom")}
	if err := configure(good, f2.index, f2.send); err == nil {
		t.Error("send error should propagate")
	}
	if len(f2.sent) != 1 {
		t.Errorf("after first send failure, sent = %d, want 1 (aborts)", len(f2.sent))
	}
}

func TestBringUpLoopback_Builds(t *testing.T) {
	f := &fakeNetlink{indexByName: map[string]int{"lo": 1}}
	if err := bringUpLoopback(f.index, f.send); err != nil {
		t.Fatalf("bringUpLoopback: %v", err)
	}
	if len(f.sent) != 1 || native.Uint16(f.sent[0][4:6]) != rtmNewLink {
		t.Error("loopback should send one RTM_NEWLINK")
	}
}
