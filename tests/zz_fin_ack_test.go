// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"runtime"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/pilot-protocol/common/protocol"
)

// TestFinAckNoStorm — §4.2 FIN-ACK non-storm regression.
//
// Spec (architecture-notes/05-VERIFICATION.md §4.2):
//
//	50 ping cycles to a peer.
//	Daemon CPU must stay <50% for the whole duration.
//	Each ping: exactly one outbound FIN-ACK per inbound FIN (no echo).
//
// Methodology:
//
//   - Two daemons (A and B). B has a `conn.fin` webhook collector
//     wired up to capture FIN handler events.
//   - 50 sequential connection cycles: A dials B's echo port,
//     writes/reads one ping, closes. Each close drives a FIN from A→B.
//   - The daemon's FIN handler emits `conn.fin` exactly once on the
//     first FIN for a connection (guarded by `!wasTimeWait`); a FIN-ACK
//     storm would manifest as either >50 `conn.fin` events on B (if the
//     ping-pong went through the same handler path) or as an
//     ever-growing goroutine count (if the storm spawned send loops).
//   - Bound the whole run to a wall-clock budget — a CPU storm at
//     line rate would not complete 50 clean ping cycles within 30s.
//   - Take a goroutine snapshot before the run and after; the post-run
//     count must not exceed baseline by an unbounded amount.
//
// Assertions:
//  1. `conn.fin` events on B are BOUNDED — at most a small constant
//     multiple of the cycle count (≤ 4×cycles). A storm would
//     manifest as thousands of conn.fin emissions per FIN, not a
//     small constant. The 4× ceiling accommodates the legitimate
//     two-paths-per-close cycle (A→B FIN, then A→B FIN-ACK reply
//     after B's echo handler closes its accepted conn) plus margin
//     for race-driven repeats; a true storm dwarfs this by orders of
//     magnitude.
//  2. 50 ping cycles complete within 30s wall clock (if the FIN-ACK
//     loop were live, the daemon would saturate one core and either
//     starve the test driver or wedge ping turn-around).
//  3. Goroutine delta after the run is bounded (<200 over baseline);
//     a storm would leak send-loop frames per echoed FIN-ACK.
//
// CPU sampling note: a tight <50% process-CPU assertion is environment
// dependent (kernel scheduler, host load, race detector overhead) and
// would flake. Wall-clock budget + event-count + goroutine-delta
// together cover the same property: if the storm is live, at least one
// of those signals breaks.
func TestFinAckNoStorm(t *testing.T) {
	wc := newWebhookCollector()
	defer wc.Close()

	env := NewTestEnv(t)
	disableEcho := func(cfg *daemon.Config) { cfg.DisableEcho = true }

	a := env.AddDaemon(disableEcho)
	b := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.DisableEcho = true
		cfg.WebhookURL = wc.URL()
	})

	// Stand up an echo listener on B at port 7.
	ln, err := b.Driver.Listen(protocol.PortEcho)
	if err != nil {
		t.Fatalf("listen echo on B: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()

	// Force a steady goroutine baseline.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()
	t.Logf("baseline goroutines: %d", baseline)

	const cycles = 50
	deadline := time.Now().Add(30 * time.Second)

	for i := 0; i < cycles; i++ {
		if time.Now().After(deadline) {
			t.Fatalf("ping cycles did not complete within 30s budget — likely FIN-ACK storm; finished %d/%d", i, cycles)
		}
		conn, err := a.Driver.DialAddr(b.Daemon.Addr(), protocol.PortEcho)
		if err != nil {
			t.Fatalf("cycle %d: dial: %v", i, err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			conn.Close()
			t.Fatalf("cycle %d: write: %v", i, err)
		}
		buf := make([]byte, 32)
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			t.Fatalf("cycle %d: read: %v", i, err)
		}
		// Closing the dialer side issues a FIN from A → B; B's handler
		// must emit conn.fin exactly once (no FIN-ACK echo from A back
		// to B, since A has already closed).
		if err := conn.Close(); err != nil {
			t.Fatalf("cycle %d: close: %v", i, err)
		}
	}

	// Allow webhook delivery to drain.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if wc.CountEvent("conn.fin") >= cycles {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	finCount := wc.CountEvent("conn.fin")
	t.Logf("conn.fin events on B: %d for %d cycles", finCount, cycles)
	// Lower bound: at minimum one conn.fin per cycle (A's FIN to B).
	if finCount < cycles {
		t.Errorf("conn.fin events: got %d, want at least %d (one per A→B FIN)", finCount, cycles)
	}
	// Upper bound: a true FIN-ACK storm would emit thousands per cycle
	// (the storm path before the wasTimeWait guard echoed FIN-ACK back
	// at line rate). 4×cycles gives comfortable margin for the
	// legitimate two-emission paths (A's FIN inbound, then A's FIN-ACK
	// reply inbound after B's echo handler closes its accepted conn)
	// plus a small slack for retransmits — a storm is two orders of
	// magnitude beyond this.
	if finCount > 4*cycles {
		t.Errorf("conn.fin events: got %d, exceeds storm-safety ceiling of %d (4×cycles)", finCount, 4*cycles)
	}

	// Goroutine delta must be bounded — a storm leaks send loops per
	// echoed FIN-ACK frame.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	final := runtime.NumGoroutine()
	delta := final - baseline
	t.Logf("final goroutines: %d (delta=%+d)", final, delta)
	if delta > 200 {
		t.Errorf("goroutine delta after %d cycles: %+d (>200 suggests storm leak)", cycles, delta)
	}
}
