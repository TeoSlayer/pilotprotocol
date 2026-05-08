// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"net"
	"testing"
)

// BenchmarkRetransmitRatioNoLoss measures retransmits/MB at 0% packet loss.
func BenchmarkRetransmitRatioNoLoss(b *testing.B) {
	runRetransmitRatioBench(b, 0.00)
}

// BenchmarkRetransmitRatio1PctLoss measures retransmits/MB at 1% packet loss.
func BenchmarkRetransmitRatio1PctLoss(b *testing.B) {
	runRetransmitRatioBench(b, 0.01)
}

// BenchmarkRetransmitRatio5PctLoss measures retransmits/MB at 5% packet loss.
func BenchmarkRetransmitRatio5PctLoss(b *testing.B) {
	runRetransmitRatioBench(b, 0.05)
}

// runRetransmitRatioBench runs one benchmark iteration at the given loss rate,
// measuring timeout retransmits, fast retransmits, and the combined ratio per
// megabyte sent. A high retx/MB value indicates the CC stack is over-inflating
// CongWin and triggering self-induced drops; the v1.9.1 CC fixes should reduce
// this number.
func runRetransmitRatioBench(b *testing.B, lossRate float64) {
	b.Helper()

	env := newBenchEnv(b)

	// Wire daemons — through a lossy proxy when lossRate > 0, directly otherwise.
	if lossRate > 0 {
		addrA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: env.A.Daemon.TunnelAddr().(*net.UDPAddr).Port}
		addrB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: env.B.Daemon.TunnelAddr().(*net.UDPAddr).Port}

		proxy := newLossProxy(b, addrA, addrB, lossRate)

		env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), proxy.AddrForA())
		env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), proxy.AddrForB())
	} else {
		env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), localUDPAddr(env.B.Daemon))
		env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), localUDPAddr(env.A.Daemon))
	}

	// Start listener on daemon B — drains all incoming data and closes the connection.
	ln, err := env.B.Driver.Listen(benchPort)
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	b.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, benchChunk)
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	chunk := make([]byte, benchChunk)
	for i := range chunk {
		chunk[i] = byte(i & 0xff)
	}

	b.SetBytes(benchPayload)
	b.ResetTimer()

	var totalRetx uint64
	var totalFastRetx uint64
	var totalTimeoutRetx uint64
	var totalBytesSent uint64

	for i := 0; i < b.N; i++ {
		conn, err := env.A.Daemon.DialConnection(env.B.Daemon.Addr(), benchPort)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}

		// Send benchPayload bytes in benchChunk-sized writes.
		sent := 0
		for sent < benchPayload {
			remaining := benchPayload - sent
			c := chunk
			if remaining < benchChunk {
				c = chunk[:remaining]
			}
			if err := env.A.Daemon.SendData(conn, c); err != nil {
				b.Fatalf("send at offset %d: %v", sent, err)
			}
			sent += len(c)
		}

		env.A.Daemon.CloseConnection(conn)

		// Collect stats under the connection mutex.
		conn.Mu.Lock()
		retx := conn.Stats.Retransmits + conn.Stats.FastRetx
		fastRetx := conn.Stats.FastRetx
		timeoutRetx := conn.Stats.Retransmits
		bytesSent := conn.Stats.BytesSent
		conn.Mu.Unlock()

		totalRetx += retx
		totalFastRetx += fastRetx
		totalTimeoutRetx += timeoutRetx
		totalBytesSent += bytesSent
	}

	b.StopTimer()

	b.ReportMetric(float64(totalRetx)/float64(b.N), "retx/iter")
	// retx/MB: use totalBytesSent so the ratio is anchored to actual wire bytes.
	// Guard against zero with +1 to avoid division-by-zero on trivially fast runs.
	b.ReportMetric(float64(totalRetx)*float64(benchChunk)/float64(totalBytesSent+1), "retx/MB")
	b.ReportMetric(float64(totalFastRetx)/float64(b.N), "fast-retx/iter")
	b.ReportMetric(float64(totalTimeoutRetx)/float64(b.N), "timeout-retx/iter")
}
