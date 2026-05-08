// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"math"
	"sync/atomic"
	"testing"
	"time"
)

// mean returns the arithmetic mean of a slice of float64 values.
func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// stddev returns the population standard deviation of a slice of float64 values.
func stddev(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := mean(xs)
	variance := 0.0
	for _, x := range xs {
		d := x - m
		variance += d * d
	}
	return math.Sqrt(variance / float64(len(xs)))
}

// BenchmarkSteadyStateThroughputVariance measures the coefficient of variation
// (stddev/mean) of throughput over a long transfer under sustained 1% packet
// loss. A low CoV indicates stable congestion control; a high CoV indicates an
// oscillating congestion window.
func BenchmarkSteadyStateThroughputVariance(b *testing.B) {
	env := newBenchEnv(b)

	addrA := localUDPAddr(env.A.Daemon)
	addrB := localUDPAddr(env.B.Daemon)

	// Wire daemons through a 1% loss proxy.
	proxy := newLossProxy(b, addrA, addrB, 0.01)
	b.Cleanup(proxy.Stop)

	env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), proxy.AddrForA())
	env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), proxy.AddrForB())

	// Bind the server listener on B once for the whole benchmark.
	ln, err := env.B.Driver.Listen(benchPort)
	if err != nil {
		b.Fatalf("listen on port %d: %v", benchPort, err)
	}
	b.Cleanup(func() { ln.Close() })

	// Dial a single long-lived connection A → B.
	clientConn, err := env.A.Driver.DialAddr(env.B.Daemon.Addr(), benchPort)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	b.Cleanup(func() { clientConn.Close() })

	// Accept that single connection on the server side. The server goroutine
	// runs for the duration of the benchmark, draining bytes as they arrive.
	serverConn, err := ln.Accept()
	if err != nil {
		b.Fatalf("accept: %v", err)
	}
	b.Cleanup(func() { serverConn.Close() })

	// serverDone is closed when the server goroutine exits (connection closed).
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, benchChunk)
		for {
			_, err := serverConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// bytesSent is incremented by the client goroutine; the ticker goroutine
	// snapshots it every 100 ms to derive per-window byte rates.
	var bytesSent atomic.Int64

	// samples collects the per-window throughput in bytes/second.
	var samples []float64

	// Start the 100 ms ticker that records per-window rates.
	ticker := time.NewTicker(100 * time.Millisecond)
	tickerDone := make(chan struct{})
	go func() {
		defer close(tickerDone)
		var prev int64
		for range ticker.C {
			cur := bytesSent.Load()
			delta := cur - prev
			prev = cur
			// delta bytes in 100 ms → bytes/sec
			samples = append(samples, float64(delta)*10)
		}
	}()

	b.SetBytes(benchPayload)
	b.ResetTimer()

	chunk := make([]byte, benchChunk)
	for i := 0; i < b.N; i++ {
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
			bytesSent.Add(int64(n))
		}
	}

	b.StopTimer()

	// Stop the ticker and wait for the ticker goroutine to drain.
	ticker.Stop()
	// Drain any final tick already queued.
	for {
		select {
		case <-tickerDone:
			goto done
		default:
		}
		// Give the goroutine a moment to notice the stopped ticker.
		time.Sleep(time.Millisecond)
	}
done:

	// Discard leading zero samples that occur before data flows (warm-up).
	var nonZero []float64
	for _, s := range samples {
		if s > 0 {
			nonZero = append(nonZero, s)
		}
	}

	if len(nonZero) == 0 {
		b.Log("no non-zero throughput samples collected")
		return
	}

	m := mean(nonZero)
	sd := stddev(nonZero)
	var cov float64
	if m > 0 {
		cov = sd / m
	}

	b.ReportMetric(m/1e6, "mean-MB/s")
	b.ReportMetric(cov*100, "cov-pct")
}
