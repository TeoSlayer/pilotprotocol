// SPDX-License-Identifier: AGPL-3.0-or-later

// TestConcurrentDialEncryptDecrypt is the §4.8 lock-graph stress harness.
// It exists as a regression gate that must remain green BEFORE any future
// per-layer lock split (the L2/L4/L5/L6/L7 sub-extraction work). It exercises
// every transition in the documented daemon lock graph under concurrent load.
//
// The test is meaningless WITHOUT the race detector — `go test -race`. The CI
// architecture-gates workflow runs the tests directory under -race; this file
// is picked up automatically. When run without -race the test still validates
// "no panic, no goroutine leak, no deadlock," which is itself useful, but the
// actual lock-graph hazards only surface with the race detector enabled.
//
// Workload:
//   - 200 dial goroutines: dial peer on a small port pool, write a small
//     payload, close. Loop until deadline.
//   - 300 decrypt goroutines: SendTo (encrypted datagrams) to peer; peer's
//     handleEncrypted decrypt path is the code under stress.
//   - 250 rekey goroutines: Driver.RotateKey() (identity rotation that
//     propagates to TunnelManager.SetIdentity, exercising identityMu and the
//     tunnel/peer locks). Paced to avoid drowning the registry.
//   - 250 heartbeat goroutines: rotate among Health, Info, SetTags,
//     ResolveHostname — registry side-channel + per-peer locks.
//
// Repetitions: 30 s × 3 reps (90 s total). Each rep starts the goroutines,
// waits for the deadline, signals stop, drains, and asserts:
//   - No panic was observed (each goroutine recover()s and reports).
//   - runtime.NumGoroutine drops back within a tolerance of baseline at
//     end-of-rep (no leak / no deadlocked goroutine).
//
// The test is gated by testing.Short — a default `go test` skips it; CI's
// non-short stress lane runs it. Wall time on a healthy laptop is ~95 s.

package tests

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentDialEncryptDecrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("§4.8 lock-graph stress: skipped under -short (90 s wall time)")
	}

	const (
		dialGoroutines      = 200
		decryptGoroutines   = 300
		rekeyGoroutines     = 250
		heartbeatGoroutines = 250
		totalGoroutines     = dialGoroutines + decryptGoroutines + rekeyGoroutines + heartbeatGoroutines
		repDuration         = 30 * time.Second
		numReps             = 3
		// Pool of listener ports the dial group will hit on the peer.
		listenerPorts = 16
	)

	if totalGoroutines != 1000 {
		t.Fatalf("workload mix must total 1000 goroutines (spec §4.8); got %d", totalGoroutines)
	}

	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// Pre-wire tunnel peers in both directions so dial doesn't have to wait
	// for STUN/registry roundtrips. The lock-graph is exercised by the
	// concurrent traffic, not by endpoint discovery latency.
	a.Daemon.AddTunnelPeer(b.Daemon.NodeID(), localUDPAddr(b.Daemon))
	b.Daemon.AddTunnelPeer(a.Daemon.NodeID(), localUDPAddr(a.Daemon))

	t.Logf("daemon A: node=%d addr=%s", a.Daemon.NodeID(), a.Daemon.Addr())
	t.Logf("daemon B: node=%d addr=%s", b.Daemon.NodeID(), b.Daemon.Addr())

	// Start one accept-and-drain goroutine per listener port. They run for
	// the entire test (across all reps); we tear them down via the listener
	// Close at the end.
	listeners := make([]listenerCtx, 0, listenerPorts)
	var listenerWG sync.WaitGroup
	stopListeners := make(chan struct{})

	for i := 0; i < listenerPorts; i++ {
		port := uint16(40000 + i)
		ln, err := b.Driver.Listen(port)
		if err != nil {
			t.Fatalf("listen %d: %v", port, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		listeners = append(listeners, listenerCtx{port: port})

		listenerWG.Add(1)
		go func(port uint16) {
			defer listenerWG.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				// Drain in a separate goroutine so Accept can return another
				// conn immediately — many concurrent dialers per port.
				listenerWG.Add(1)
				go func() {
					defer listenerWG.Done()
					defer conn.Close()
					buf := make([]byte, 4096)
					for {
						_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
						_, err := conn.Read(buf)
						if err != nil {
							return
						}
						select {
						case <-stopListeners:
							return
						default:
						}
					}
				}()
			}
		}(port)
	}

	// Warm listeners, then allow any ambient parallel-test goroutines to
	// stabilise before the first rep.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	t.Logf("pre-rep goroutine count: %d", runtime.NumGoroutine())

	totalStart := time.Now()

	for rep := 0; rep < numReps; rep++ {
		// Snapshot baseline immediately before launching the rep's
		// workload so the post-rep delta measures only goroutines that
		// THIS rep created but did not drain. Using a single global
		// baseline (taken before rep 1) was incorrect: over the 30 s
		// rep other parallel tests start up and inflate the count,
		// producing false-positive leak reports in CI.
		runtime.GC()
		baselineGoroutines := runtime.NumGoroutine()
		t.Logf("--- rep %d/%d (deadline %s, baseline goroutines %d) ---",
			rep+1, numReps, repDuration, baselineGoroutines)
		runRep(t, a, b, listeners, repDuration, dialGoroutines, decryptGoroutines, rekeyGoroutines, heartbeatGoroutines)

		// runRep calls wg.Wait() so all 1000 worker goroutines have
		// already exited by the time we get here. The poll below catches
		// goroutines NOT tracked by wg (e.g. daemon-internal goroutines
		// started as a side-effect of the workload that didn't clean up).
		runtime.GC()
		drainDeadline := time.Now().Add(5 * time.Second)
		var now int
		var delta int
		const tolerance = 10
		for {
			runtime.GC()
			now = runtime.NumGoroutine()
			delta = now - baselineGoroutines
			if delta <= tolerance {
				break
			}
			if time.Now().After(drainDeadline) {
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				t.Errorf("rep %d: goroutine leak detected: %d goroutines, baseline=%d, delta=%d (tolerance %d, waited 5s)\n%s",
					rep+1, now, baselineGoroutines, delta, tolerance, buf[:n])
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Logf("rep %d done: goroutines=%d baseline=%d delta=%d", rep+1, now, baselineGoroutines, delta)
	}

	close(stopListeners)
	// Closing listeners is handled by t.Cleanup; the spawned readers exit
	// when their conns close. Don't wait for listenerWG here — Accept
	// loops only exit when the listener Close fires from cleanup.

	t.Logf("§4.8 stress complete: 3 reps, total wall time %s", time.Since(totalStart).Round(time.Millisecond))
}

// listenerCtx names the per-port context the dial group uses.
type listenerCtx struct {
	port uint16
}

// runRep runs one 30 s rep of the stress workload.
func runRep(
	t *testing.T,
	a, b *DaemonInfo,
	listeners []listenerCtx,
	dur time.Duration,
	nDial, nDecrypt, nRekey, nHeartbeat int,
) {
	t.Helper()

	deadline := time.Now().Add(dur)
	stop := make(chan struct{})

	// Per-group counters for an end-of-rep sanity log; helps the operator
	// confirm the workload mix is actually executing (no false-pass from a
	// loop that errored out on iteration 0 silently).
	var (
		dialOK, dialErr           atomic.Uint64
		decryptOK, decryptErr     atomic.Uint64
		rekeyOK, rekeyErr         atomic.Uint64
		heartbeatOK, heartbeatErr atomic.Uint64
		panicCount                atomic.Uint64
	)

	var firstPanic atomic.Pointer[string]
	recordPanic := func(group string, r interface{}) {
		panicCount.Add(1)
		msg := fmt.Sprintf("%s: panic: %v", group, r)
		// CompareAndSwap with nil so we keep the first panic only.
		s := msg
		firstPanic.CompareAndSwap(nil, &s)
	}

	var wg sync.WaitGroup

	// --- dial group ---
	for i := 0; i < nDial; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					recordPanic("dial", r)
				}
			}()

			rng := rand.New(rand.NewSource(int64(seed)*1_000_003 + 1))
			payload := []byte("ping")
			for {
				select {
				case <-stop:
					return
				default:
				}
				if time.Now().After(deadline) {
					return
				}
				port := listeners[rng.Intn(len(listeners))].port
				conn, err := a.Driver.DialAddrTimeout(b.Daemon.Addr(), port, 2*time.Second)
				if err != nil {
					if isBenignClosedErr(err) {
						return
					}
					dialErr.Add(1)
					// Brief backoff so a transient registry/driver hiccup
					// doesn't tight-spin a CPU.
					time.Sleep(5 * time.Millisecond)
					continue
				}
				_, werr := conn.Write(payload)
				_ = conn.Close()
				if werr != nil {
					dialErr.Add(1)
				} else {
					dialOK.Add(1)
				}
			}
		}(i)
	}

	// --- decrypt group ---
	// Datagrams from A → B exercise B's tunnel encrypt-on-send (A side) and
	// B's handleEncrypted (decrypt) path. Send is unreliable, so we don't
	// read on B; the receive queue may fill and drop, which is fine — we
	// only need the decrypt code path to fire under pressure.
	for i := 0; i < nDecrypt; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					recordPanic("decrypt", r)
				}
			}()

			rng := rand.New(rand.NewSource(int64(seed)*2_000_003 + 2))
			payload := make([]byte, 64)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if time.Now().After(deadline) {
					return
				}
				// Vary payload so writes do real work (not all-zero buffers
				// optimised away).
				rng.Read(payload)
				// Random destination port — a few of the listener ports plus
				// some "no listener" ports. Both paths run through decrypt.
				dstPort := uint16(50000 + rng.Intn(64))
				err := a.Driver.SendTo(b.Daemon.Addr(), dstPort, payload)
				if err != nil {
					if isBenignClosedErr(err) {
						return
					}
					decryptErr.Add(1)
					time.Sleep(2 * time.Millisecond)
					continue
				}
				decryptOK.Add(1)
			}
		}(i)
	}

	// --- rekey group ---
	// Driver.RotateKey() rotates the daemon's Ed25519 identity, hits the
	// registry to prove ownership, then atomically swaps the in-memory
	// identity AND propagates to TunnelManager.SetIdentity. That's the
	// rekey lock-graph traversal: identityMu (write) → tunnel state.
	//
	// Heavy: each call is a registry roundtrip. We pace per goroutine to
	// avoid drowning the single in-process registry. With ~250 goroutines
	// at ~1 call/sec average, ~7500 rotations per rep is the upper bound;
	// in practice, the registry serializes them and we get fewer.
	for i := 0; i < nRekey; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					recordPanic("rekey", r)
				}
			}()

			// Half the goroutines rekey on A, half on B, so each daemon's
			// identityMu sees real concurrent contention.
			drv := a.Driver
			if seed%2 == 1 {
				drv = b.Driver
			}
			rng := rand.New(rand.NewSource(int64(seed)*3_000_003 + 3))

			// Stagger first call to avoid a thundering herd at t=0.
			time.Sleep(time.Duration(rng.Intn(1000)) * time.Millisecond)

			for {
				select {
				case <-stop:
					return
				default:
				}
				if time.Now().After(deadline) {
					return
				}
				_, err := drv.RotateKey()
				if err != nil {
					if isBenignClosedErr(err) {
						return
					}
					rekeyErr.Add(1)
				} else {
					rekeyOK.Add(1)
				}
				// Pace: 500–1500 ms between rotations per goroutine.
				time.Sleep(time.Duration(500+rng.Intn(1000)) * time.Millisecond)
			}
		}(i)
	}

	// --- heartbeat group ---
	// Rotates among Health, Info, SetTags, ResolveHostname. These exercise
	// the registry-touching side-channel paths and the per-peer locks the
	// daemon takes during an info dump.
	for i := 0; i < nHeartbeat; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					recordPanic("heartbeat", r)
				}
			}()

			rng := rand.New(rand.NewSource(int64(seed)*5_000_003 + 5))
			drv := a.Driver
			if seed%2 == 1 {
				drv = b.Driver
			}

			for {
				select {
				case <-stop:
					return
				default:
				}
				if time.Now().After(deadline) {
					return
				}
				op := rng.Intn(4)
				var err error
				switch op {
				case 0:
					_, err = drv.Health()
				case 1:
					_, err = drv.Info()
				case 2:
					tag := fmt.Sprintf("stress-%d-%d", seed, rng.Intn(1<<20))
					_, err = drv.SetTags([]string{tag})
				case 3:
					// ResolveHostname for a name that may or may not exist
					// — both branches walk the same registry path.
					_, err = drv.ResolveHostname(fmt.Sprintf("stress-%d", seed%8))
				}
				if err != nil {
					if isBenignClosedErr(err) {
						return
					}
					heartbeatErr.Add(1)
				} else {
					heartbeatOK.Add(1)
				}
				// Light pacing — these are cheap calls, but unbounded rate
				// against a single-process registry just produces queue
				// build-up that doesn't add lock-graph coverage.
				time.Sleep(time.Duration(20+rng.Intn(80)) * time.Millisecond)
			}
		}(i)
	}

	// Wait for the deadline, then signal stop and drain.
	<-time.After(dur)
	close(stop)

	// Drain with a hard ceiling — if any goroutine fails to honour stop the
	// test should fail with a deadlock indication, not hang the harness.
	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		// ok
	case <-time.After(20 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("rep drain timeout: workload goroutines did not exit within 20 s of stop signal — possible deadlock\n%s", buf[:n])
	}

	if pc := panicCount.Load(); pc > 0 {
		first := ""
		if p := firstPanic.Load(); p != nil {
			first = *p
		}
		t.Fatalf("rep saw %d panic(s); first: %s", pc, first)
	}

	t.Logf("rep workload counters: dial=%d/%d decrypt=%d/%d rekey=%d/%d heartbeat=%d/%d",
		dialOK.Load(), dialErr.Load(),
		decryptOK.Load(), decryptErr.Load(),
		rekeyOK.Load(), rekeyErr.Load(),
		heartbeatOK.Load(), heartbeatErr.Load())

	// Sanity: every group must have made non-zero progress. If a group's OK
	// counter is zero AND its error counter is also near-zero, the workload
	// is not exercising the code path (goroutines never ran or returned
	// immediately without attempting work). High errors + zero OK means the
	// path was exercised under heavy load but all attempts failed (e.g.
	// registry timeouts under parallel CI pressure) — don't fail for that.
	if dialOK.Load() == 0 {
		t.Errorf("dial group made zero successful dials — workload not exercising dial path")
	}
	if decryptOK.Load() == 0 {
		t.Errorf("decrypt group made zero successful sends — workload not exercising decrypt path")
	}
	if rekeyOK.Load() == 0 && rekeyErr.Load() < 100 {
		t.Errorf("rekey group made zero successful rotations and nearly zero errors — workload not exercising rekey path")
	}
	if heartbeatOK.Load() == 0 {
		t.Errorf("heartbeat group made zero successful operations — workload not exercising side-channel path")
	}
}

// isBenignClosedErr reports whether err is the kind of error you'd expect
// when the test's daemon/driver is being torn down (e.g. closed pipe,
// driver shut down). Such errors should make a goroutine exit cleanly,
// not count as test failures.
func isBenignClosedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "closed") ||
		strings.Contains(s, "use of closed") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "EOF")
}
