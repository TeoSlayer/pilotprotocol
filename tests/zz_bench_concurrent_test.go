// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"net"
	"sync"
	"testing"
)

// BenchmarkConcurrentStreams5 measures aggregate throughput across 5 simultaneous streams.
func BenchmarkConcurrentStreams5(b *testing.B) { runConcurrentBench(b, 5) }

// BenchmarkConcurrentStreams10 measures aggregate throughput across 10 simultaneous streams.
func BenchmarkConcurrentStreams10(b *testing.B) { runConcurrentBench(b, 10) }

// BenchmarkConcurrentStreams25 measures aggregate throughput across 25 simultaneous streams.
func BenchmarkConcurrentStreams25(b *testing.B) { runConcurrentBench(b, 25) }

// runConcurrentBench transfers benchPayload bytes across n concurrent streams
// per iteration and measures aggregate throughput. With a correctly-behaved
// congestion controller each stream's window stays proportional to 1/n of the
// bottleneck, keeping the aggregate stable. An over-inflated CongWin causes
// collective overshoot, self-induced drops and lower aggregate throughput.
func runConcurrentBench(b *testing.B, n int) {
	b.Helper()
	b.ReportAllocs()

	env := newBenchEnv(b)

	// Wire daemons directly (no loss proxy).
	env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), localUDPAddr(env.B.Daemon))
	env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), localUDPAddr(env.A.Daemon))

	// Pre-create all n listeners on B, one per stream port.
	// Ports benchPort … benchPort+n-1 (benchPort=9201, max n=25 → 9225).
	type listenerState struct {
		ln interface {
			Accept() (net.Conn, error)
			Close() error
		}
	}

	listeners := make([]*listenerState, n)
	for i := 0; i < n; i++ {
		port := benchPort + uint16(i)
		ln, err := env.B.Driver.Listen(port)
		if err != nil {
			b.Fatalf("listen port %d: %v", port, err)
		}
		ls := &listenerState{ln: ln}
		listeners[i] = ls
		b.Cleanup(func() { ln.Close() })
	}

	// b.SetBytes counts the total bytes transferred across all streams per iteration.
	b.SetBytes(int64(n) * benchPayload)
	b.ResetTimer()

	for iter := 0; iter < b.N; iter++ {
		// Per-iteration done channels: one per stream.
		// Each server goroutine closes its channel after draining one connection.
		doneChs := make([]chan struct{}, n)
		for i := range doneChs {
			doneChs[i] = make(chan struct{})
		}

		// Launch server goroutines: each accepts one connection, drains benchPayload
		// bytes, then closes the done channel for this iteration.
		for i := 0; i < n; i++ {
			i := i
			go func() {
				conn, err := listeners[i].ln.Accept()
				if err != nil {
					close(doneChs[i])
					return
				}
				buf := make([]byte, benchChunk)
				total := 0
				for total < benchPayload {
					nr, err := conn.Read(buf)
					if err != nil {
						break
					}
					total += nr
				}
				conn.Close()
				close(doneChs[i])
			}()
		}

		// Launch n client goroutines; each dials its dedicated port and sends
		// benchPayload bytes in benchChunk-sized writes.
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			i := i
			go func() {
				defer wg.Done()
				port := benchPort + uint16(i)
				conn, err := env.A.Driver.DialAddr(env.B.Daemon.Addr(), port)
				if err != nil {
					b.Errorf("stream %d dial: %v", i, err)
					return
				}
				chunk := make([]byte, benchChunk)
				sent := 0
				for sent < benchPayload {
					toSend := benchChunk
					if sent+toSend > benchPayload {
						toSend = benchPayload - sent
					}
					nw, err := conn.Write(chunk[:toSend])
					if err != nil {
						b.Errorf("stream %d write at offset %d: %v", i, sent, err)
						conn.Close()
						return
					}
					sent += nw
				}
				conn.Close()
			}()
		}

		// Wait for all senders to finish, then wait for all receivers to drain.
		wg.Wait()
		for i := 0; i < n; i++ {
			<-doneChs[i]
		}
	}

	b.StopTimer()
	b.ReportMetric(float64(n), "streams")
}
