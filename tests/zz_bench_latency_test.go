// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"io"
	"sort"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// BenchmarkLatencyUnderLoad measures p50/p95/p99 round-trip latency for small
// echo messages while a background goroutine saturates the connection with bulk
// data. With over-inflated CongWin the queue bloats and tail latency spikes;
// the v1.9.1 fixes should reduce p95/p99 significantly.
func BenchmarkLatencyUnderLoad(b *testing.B) {
	runLatencyBench(b, true)
}

// BenchmarkLatencyIdle is the baseline: same latency measurement without any
// background load. Compare against BenchmarkLatencyUnderLoad to quantify the
// head-of-line blocking overhead.
func BenchmarkLatencyIdle(b *testing.B) {
	runLatencyBench(b, false)
}

// runLatencyBench is the shared implementation for the latency benchmarks.
// When withLoad is true a background goroutine keeps a separate connection
// saturated with bulk data throughout the measurement window.
func runLatencyBench(b *testing.B, withLoad bool) {
	b.Helper()

	env := newBenchEnv(b)

	// Wire daemons directly — no loss proxy.
	env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), localUDPAddr(env.B.Daemon))
	env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), localUDPAddr(env.A.Daemon))

	// Daemon B auto-starts the echo service on port 7 (protocol.PortEcho).
	// No explicit listener setup is required on the server side.

	// --- Background load goroutine ---
	// Bind a server on B at benchPort to absorb the bulk data stream.
	var loadDone chan struct{}
	if withLoad {
		ln, err := env.B.Driver.Listen(benchPort)
		if err != nil {
			b.Fatalf("load listener: %v", err)
		}
		b.Cleanup(func() { ln.Close() })

		loadDone = make(chan struct{})

		// Server side: accept one connection and drain it until EOF / closed.
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, benchChunk)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					return
				}
			}
		}()

		// Client side: dial and write in a loop until loadDone is closed.
		loadConn, err := env.A.Driver.DialAddr(env.B.Daemon.Addr(), benchPort)
		if err != nil {
			b.Fatalf("load dial: %v", err)
		}
		b.Cleanup(func() { loadConn.Close() })

		go func() {
			defer close(loadDone)
			chunk := make([]byte, benchChunk)
			for {
				select {
				case <-loadDone:
					return
				default:
					if _, err := loadConn.Write(chunk); err != nil {
						return
					}
				}
			}
		}()

		// Give the load goroutine time to saturate the connection before we
		// start measuring latency.
		time.Sleep(200 * time.Millisecond)
	}

	// Open a single persistent echo connection to B's built-in echo service
	// before the timer starts so that dial overhead is excluded from latency
	// measurements.
	echoConn, err := env.A.Driver.DialAddr(env.B.Daemon.Addr(), protocol.PortEcho)
	if err != nil {
		b.Fatalf("dial echo: %v", err)
	}
	b.Cleanup(func() { echoConn.Close() })

	ping := make([]byte, benchSmallPing)
	pong := make([]byte, benchSmallPing)

	b.SetBytes(int64(benchSmallPing))
	b.ResetTimer()

	latencies := make([]int64, 0, b.N)

	for i := 0; i < b.N; i++ {
		start := time.Now()

		if _, err := echoConn.Write(ping); err != nil {
			b.Fatalf("echo write: %v", err)
		}

		// Read exactly benchSmallPing bytes back.
		if _, err := io.ReadFull(echoConn, pong); err != nil {
			b.Fatalf("echo read: %v", err)
		}

		latencies = append(latencies, time.Since(start).Nanoseconds())
	}

	b.StopTimer()

	// Signal the load goroutine to stop (no-op when withLoad is false).
	if withLoad && loadDone != nil {
		// loadDone is closed by the load goroutine itself when the write
		// fails after loadConn is closed via b.Cleanup. Nothing more needed.
	}

	// Compute percentiles.
	if len(latencies) == 0 {
		return
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	n := len(latencies)
	p50 := float64(latencies[n*50/100])
	p95 := float64(latencies[n*95/100])
	p99 := float64(latencies[n*99/100])

	b.ReportMetric(p50, "p50-ns")
	b.ReportMetric(p95, "p95-ns")
	b.ReportMetric(p99, "p99-ns")
}
