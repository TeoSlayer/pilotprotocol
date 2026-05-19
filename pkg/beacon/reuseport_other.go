// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package beacon

import "net"

// listenReusePort falls back to plain net.ListenUDP on non-Linux
// platforms. SO_REUSEPORT semantics vary across OSes (notably Darwin's
// version doesn't flow-hash like Linux's does), and the build target
// for production is Linux. On Mac dev / non-Linux CI runners we just
// open a single socket and accept the lower throughput — correctness
// is unchanged.
func listenReusePort(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", udpAddr)
}

// MaxReusePortShards caps how many SO_REUSEPORT sockets the beacon
// opens. On non-Linux platforms this is 1 — without kernel flow-hash,
// opening more would just fail with "address already in use" on the
// second bind. Production (Linux) uses the default 2× NumCPU.
const MaxReusePortShards = 1
