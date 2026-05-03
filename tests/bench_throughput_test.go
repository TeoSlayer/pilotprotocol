// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"sync"
	"testing"
)

// BenchmarkBinaryThroughputNoLoss measures end-to-end binary throughput
// between two Pilot daemons with no packet loss.
func BenchmarkBinaryThroughputNoLoss(b *testing.B) {
	runBinaryThroughput(b, 0.0)
}

// BenchmarkBinaryThroughput1PctLoss measures end-to-end binary throughput
// between two Pilot daemons with 1% packet loss.
func BenchmarkBinaryThroughput1PctLoss(b *testing.B) {
	runBinaryThroughput(b, 0.01)
}

// BenchmarkBinaryThroughput5PctLoss measures end-to-end binary throughput
// between two Pilot daemons with 5% packet loss.
func BenchmarkBinaryThroughput5PctLoss(b *testing.B) {
	runBinaryThroughput(b, 0.05)
}

// runBinaryThroughput is the shared benchmark implementation. It sets up two
// daemons, optionally wires them through a lossy UDP proxy, then measures how
// fast benchPayload bytes can be transferred per iteration.
func runBinaryThroughput(b *testing.B, lossRate float64) {
	b.Helper()
	b.ReportAllocs()

	env := newBenchEnv(b)

	addrA := localUDPAddr(env.A.Daemon)
	addrB := localUDPAddr(env.B.Daemon)

	if lossRate > 0 {
		proxy := newLossProxy(b, addrA, addrB, lossRate)
		b.Cleanup(proxy.Stop)

		// A sees B through the proxy's A-side; B sees A through the proxy's B-side.
		env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), proxy.AddrForA())
		env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), proxy.AddrForB())
	} else {
		env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), addrB)
		env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), addrA)
	}

	// Bind the server listener on B before starting iterations.
	ln, err := env.B.Driver.Listen(benchPort)
	if err != nil {
		b.Fatalf("listen on port %d: %v", benchPort, err)
	}
	b.Cleanup(func() { ln.Close() })

	b.SetBytes(benchPayload)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// done is closed by the server goroutine after it has drained the
		// connection, signalling the client that the transfer is complete.
		done := make(chan struct{})

		// Server: accept one connection, drain benchPayload bytes, then close.
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go func() {
				buf := make([]byte, benchChunk)
				total := 0
				for total < benchPayload {
					n, err := conn.Read(buf)
					if err != nil {
						break
					}
					total += n
				}
				conn.Close()
				close(done)
			}()
		}()

		// Client: dial B and send benchPayload bytes in benchChunk-sized writes.
		clientConn, err := env.A.Driver.DialAddr(env.B.Daemon.Addr(), benchPort)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}

		chunk := make([]byte, benchChunk)
		sent := 0
		for sent < benchPayload {
			toSend := benchChunk
			if sent+toSend > benchPayload {
				toSend = benchPayload - sent
			}
			n, err := clientConn.Write(chunk[:toSend])
			if err != nil {
				b.Fatalf("write at offset %d: %v", sent, err)
			}
			sent += n
		}

		// Signal EOF to the server, then wait for it to finish draining.
		clientConn.Close()
		<-done
		wg.Wait()
	}

	b.StopTimer()
}
