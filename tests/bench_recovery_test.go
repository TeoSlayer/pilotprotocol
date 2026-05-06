// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// burstProxy is a UDP proxy that can drop a configurable burst of N consecutive
// packets in the A→B direction on demand, then resume forwarding normally.
// B→A traffic is always forwarded without drops.
type burstProxy struct {
	toB     *net.UDPConn
	toA     *net.UDPConn
	realA   *net.UDPAddr
	realB   *net.UDPAddr
	dropN   atomic.Int64
	stopped atomic.Bool
}

// newBurstProxy creates a controllable UDP proxy between addrA and addrB.
// Wire daemons:
//
//	env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), proxy.AddrForA())
//	env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), proxy.AddrForB())
func newBurstProxy(b testing.TB, addrA, addrB *net.UDPAddr) *burstProxy {
	b.Helper()

	toB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Fatalf("burstProxy: listen toB: %v", err)
	}

	toA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		toB.Close()
		b.Fatalf("burstProxy: listen toA: %v", err)
	}

	p := &burstProxy{
		toB:   toB,
		toA:   toA,
		realA: addrA,
		realB: addrB,
	}

	// A → B forwarding goroutine: drops packets when dropN > 0.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := toB.ReadFromUDP(buf)
			if p.stopped.Load() {
				return
			}
			if err != nil {
				return
			}
			// Atomically consume one drop token; a non-negative result before
			// decrement means a drop was requested for this packet.
			after := p.dropN.Add(-1)
			if after >= 0 {
				// Drop this packet — a burst drop was requested.
				continue
			}
			// Counter went negative; clamp it back to zero.
			p.dropN.CompareAndSwap(after, 0)
			_, _ = toB.WriteTo(buf[:n], addrB)
		}
	}()

	// B → A forwarding goroutine: always forwards.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := toA.ReadFromUDP(buf)
			if p.stopped.Load() {
				return
			}
			if err != nil {
				return
			}
			_, _ = toA.WriteTo(buf[:n], addrA)
		}
	}()

	b.Cleanup(p.Stop)

	return p
}

// TriggerDrop schedules the next n A→B packets to be dropped.
func (p *burstProxy) TriggerDrop(n int) {
	p.dropN.Store(int64(n))
}

// AddrForA returns the proxy address that daemon A should use to reach B.
func (p *burstProxy) AddrForA() *net.UDPAddr {
	return p.toB.LocalAddr().(*net.UDPAddr)
}

// AddrForB returns the proxy address that daemon B should use to reach A.
func (p *burstProxy) AddrForB() *net.UDPAddr {
	return p.toA.LocalAddr().(*net.UDPAddr)
}

// Stop halts the proxy goroutines.
func (p *burstProxy) Stop() {
	p.stopped.Store(true)
	p.toB.Close()
	p.toA.Close()
}

// BenchmarkRecoveryTime measures how long it takes for a connection to complete
// a benchPayload/2 transfer after a burst of 10 consecutive dropped packets is
// injected at the midpoint. The recovery-ns metric captures the wall-clock cost
// of the retransmit/recovery phase; compare ns/op against
// BenchmarkBinaryThroughputNoLoss to quantify the overhead introduced by the
// burst loss.
func BenchmarkRecoveryTime(b *testing.B) {
	b.Helper()
	b.ReportAllocs()

	env := newBenchEnv(b)

	addrA := localUDPAddr(env.A.Daemon)
	addrB := localUDPAddr(env.B.Daemon)

	proxy := newBurstProxy(b, addrA, addrB)

	// Wire daemons through the burst proxy.
	env.A.Daemon.AddTunnelPeer(env.B.Daemon.NodeID(), proxy.AddrForA())
	env.B.Daemon.AddTunnelPeer(env.A.Daemon.NodeID(), proxy.AddrForB())

	const half = benchPayload / 2

	// Bind the server listener on B.
	ln, err := env.B.Driver.Listen(benchPort)
	if err != nil {
		b.Fatalf("listen on port %d: %v", benchPort, err)
	}
	b.Cleanup(func() { ln.Close() })

	b.SetBytes(benchPayload)
	b.ResetTimer()

	var totalRecoveryNs int64

	for i := 0; i < b.N; i++ {
		// Server: accept one connection and drain all bytes.
		serverDone := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ln.Accept()
			if err != nil {
				close(serverDone)
				return
			}
			go func() {
				buf := make([]byte, benchChunk)
				for {
					_, err := conn.Read(buf)
					if err != nil {
						break
					}
				}
				conn.Close()
				close(serverDone)
			}()
		}()

		// Client: dial B.
		clientConn, err := env.A.Driver.DialAddr(env.B.Daemon.Addr(), benchPort)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}

		chunk := make([]byte, benchChunk)

		// Phase 1: warm-up — send first half without loss.
		sent := 0
		for sent < half {
			toSend := benchChunk
			if sent+toSend > half {
				toSend = half - sent
			}
			n, err := clientConn.Write(chunk[:toSend])
			if err != nil {
				b.Fatalf("write (warm-up) at offset %d: %v", sent, err)
			}
			sent += n
		}

		// Inject a burst of 10 consecutive dropped A→B packets at the midpoint.
		proxy.TriggerDrop(10)

		// Phase 2: recovery — send the second half through the burst loss.
		recoveryStart := time.Now()
		sent = 0
		for sent < half {
			toSend := benchChunk
			if sent+toSend > half {
				toSend = half - sent
			}
			n, err := clientConn.Write(chunk[:toSend])
			if err != nil {
				if err == io.EOF {
					break
				}
				b.Fatalf("write (recovery) at offset %d: %v", sent, err)
			}
			sent += n
		}
		recoveryNs := time.Since(recoveryStart).Nanoseconds()
		totalRecoveryNs += recoveryNs

		// Signal EOF and wait for the server to finish draining.
		clientConn.Close()
		<-serverDone
		wg.Wait()
	}

	b.StopTimer()

	if b.N > 0 {
		avgRecoveryNs := float64(totalRecoveryNs) / float64(b.N)
		b.ReportMetric(avgRecoveryNs, "recovery-ns")
		b.ReportMetric(float64(b.N), "iterations")
	}
}
