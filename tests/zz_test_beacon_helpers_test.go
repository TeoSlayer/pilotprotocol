// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/beacon"
)

// startTestBeacon + sendUDP were originally defined in
// zz_fuzz_beacon_test.go but that file moved to the beacon sibling
// repo. zz_security_phase2_test.go (default-tag) still uses both
// helpers, so they need a default-tag home here. Keeping them in
// their own helper file rather than testenv.go so the
// `pilot-protocol/beacon` import stays narrowly scoped.

func startTestBeacon(t *testing.T) (*beacon.Server, *net.UDPAddr) {
	t.Helper()
	s := beacon.New()
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("beacon server did not start")
	}
	addr := s.Addr().(*net.UDPAddr)
	return s, addr
}

func sendUDP(t *testing.T, addr *net.UDPAddr, data []byte) []byte {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// A package-wide run executes the real-network tests in parallel with the
	// daemon and external-delivery suites. Give the scheduler enough room to
	// service this UDP round trip; 200 ms made a healthy beacon look broken
	// under full-suite load even though focused repetitions always passed.
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil // timeout = no reply
	}
	return buf[:n]
}
