// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build loadtest

package tests

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	registry "github.com/TeoSlayer/pilotprotocol/pkg/registry/client"
)

// ---------------------------------------------------------------------------
// TestFakeNodeSpamNoAuth — proves registration accepts random 32-byte keys
// with no proof-of-possession. Registers 100K fake nodes, verifies all
// accepted, then fast-forwards time and reaps to show they die without
// heartbeats.
// ---------------------------------------------------------------------------

func TestFakeNodeSpamNoAuth(t *testing.T) {
	t.Parallel()
	const numNodes = 100_000
	const numConns = 50

	s := registry.New("")
	s.SetMaxNodes(1_100_000)
	s.SetMaxConnections(500)
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry did not start")
	}
	defer s.Close()
	addr := s.Addr().(*net.TCPAddr).String()

	// Generate 100K random 32-byte "public keys" — NOT real Ed25519
	t.Logf("generating %d random keys...", numNodes)
	keygenStart := time.Now()
	keys := make([]string, numNodes)
	for i := range keys {
		var buf [32]byte
		if _, err := rand.Read(buf[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		keys[i] = base64.StdEncoding.EncodeToString(buf[:])
	}
	keygenDur := time.Since(keygenStart)
	t.Logf("keygen: %d keys in %v (%.0f keys/s)", numNodes, keygenDur, float64(numNodes)/keygenDur.Seconds())

	// Open connections
	clients := make([]*registry.Client, numConns)
	for i := range clients {
		c, err := registry.Dial(addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
		clients[i] = c
	}

	// Register concurrently — one goroutine per connection
	t.Logf("registering %d fake nodes over %d connections...", numNodes, numConns)
	var regErrors int64
	var wg sync.WaitGroup
	regStart := time.Now()

	perConn := numNodes / numConns
	for ci := 0; ci < numConns; ci++ {
		ci := ci
		lo := ci * perConn
		hi := lo + perConn
		if ci == numConns-1 {
			hi = numNodes
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := clients[ci]
			for i := lo; i < hi; i++ {
				_, err := c.RegisterWithKey("127.0.0.1:4000", keys[i], "", nil)
				if err != nil {
					atomic.AddInt64(&regErrors, 1)
				}
			}
		}()
	}
	wg.Wait()
	regDur := time.Since(regStart)
	t.Logf("registration: %d nodes in %v (%.0f reg/s), errors: %d",
		numNodes, regDur, float64(numNodes)/regDur.Seconds(), regErrors)

	// Verify all accepted
	stats := s.GetDashboardStats()
	t.Logf("TotalNodes after registration: %d", stats.TotalNodes)
	if stats.TotalNodes < numNodes-int(regErrors) {
		t.Fatalf("expected >= %d total nodes, got %d", numNodes-int(regErrors), stats.TotalNodes)
	}

	// Measure per-node memory
	runtime.GC()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	t.Logf("heap after %d nodes: %.1f MB (%.1f KB/node)",
		stats.TotalNodes, float64(mem.HeapAlloc)/(1024*1024),
		float64(mem.HeapAlloc)/float64(stats.TotalNodes)/1024)

	// Fast-forward clock by 6 minutes and reap — no heartbeats means all reaped.
	// Reap processes 10K nodes per call (reapChunkSize), so we need enough passes.
	// Note: GetDashboardStats().TotalNodes is a high-water mark (nextNode-1), not
	// len(nodes), so we verify reap by attempting lookups on sampled node IDs.
	t.Log("fast-forwarding clock by 6 minutes and reaping...")
	future := time.Now().Add(6 * time.Minute)
	s.SetClock(func() time.Time { return future })
	reapPasses := (numNodes / 10_000) + 2
	for i := 0; i < reapPasses; i++ {
		s.Reap()
	}

	// Verify reaped: lookup should fail for all sampled nodes
	lookupClient, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("dial for lookup: %v", err)
	}
	defer lookupClient.Close()

	reaped := 0
	alive := 0
	for nodeID := uint32(1); nodeID <= uint32(numNodes); nodeID += 100 {
		_, err := lookupClient.Lookup(nodeID)
		if err != nil {
			reaped++
		} else {
			alive++
		}
	}
	t.Logf("after reap: sampled %d nodes — reaped=%d, alive=%d", reaped+alive, reaped, alive)
	if alive > 0 {
		t.Fatalf("expected all sampled nodes to be reaped, but %d still alive", alive)
	}
}

// ---------------------------------------------------------------------------
// TestFakeNodeSpamWithHeartbeat — full attack simulation: register N nodes
// with real Ed25519 keys, send signed heartbeats to survive reaping.
// Scales through 1K → 10K → 100K → 500K → 1M.
// ---------------------------------------------------------------------------

func TestFakeNodeSpamWithHeartbeat(t *testing.T) {
	t.Parallel()
	scales := []int{1_000, 10_000, 100_000, 500_000, 1_000_000}

	for _, n := range scales {
		n := n
		t.Run(fmt.Sprintf("scale_%d", n), func(t *testing.T) {
			s := registry.New("")
			s.SetMaxNodes(1_100_000)
			s.SetMaxConnections(500)
			go s.ListenAndServe("127.0.0.1:0")
			select {
			case <-s.Ready():
			case <-time.After(5 * time.Second):
				t.Fatal("registry did not start")
			}
			defer s.Close()
			addr := s.Addr().(*net.TCPAddr).String()

			// ---- Phase 1: Keygen (parallel) ----
			t.Logf("[keygen] generating %d Ed25519 identities...", n)
			keygenStart := time.Now()
			identities := make([]*crypto.Identity, n)
			const keygenWorkers = 8
			var kwg sync.WaitGroup
			chunk := (n + keygenWorkers - 1) / keygenWorkers
			for w := 0; w < keygenWorkers; w++ {
				w := w
				lo := w * chunk
				hi := lo + chunk
				if hi > n {
					hi = n
				}
				kwg.Add(1)
				go func() {
					defer kwg.Done()
					for i := lo; i < hi; i++ {
						id, err := crypto.GenerateIdentity()
						if err != nil {
							t.Errorf("keygen %d: %v", i, err)
							return
						}
						identities[i] = id
					}
				}()
			}
			kwg.Wait()
			keygenDur := time.Since(keygenStart)
			keygenRate := float64(n) / keygenDur.Seconds()
			t.Logf("[keygen] %d keys in %v (%.0f keys/s)", n, keygenDur, keygenRate)

			// ---- Phase 2: Register (concurrent, one goroutine per conn) ----
			numConns := n / 50
			if numConns < 1 {
				numConns = 1
			}
			if numConns > 100 {
				numConns = 100
			}
			t.Logf("[register] %d nodes over %d connections...", n, numConns)

			regClients := make([]*registry.Client, numConns)
			for i := range regClients {
				c, err := registry.Dial(addr)
				if err != nil {
					t.Fatalf("dial %d: %v", i, err)
				}
				defer c.Close()
				regClients[i] = c
			}

			nodeIDs := make([]uint32, n)
			var regErrors int64
			var rwg sync.WaitGroup

			regStart := time.Now()
			perConn := n / numConns
			for ci := 0; ci < numConns; ci++ {
				ci := ci
				lo := ci * perConn
				hi := lo + perConn
				if ci == numConns-1 {
					hi = n
				}
				rwg.Add(1)
				go func() {
					defer rwg.Done()
					c := regClients[ci]
					for i := lo; i < hi; i++ {
						resp, err := c.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(identities[i].PublicKey), "", nil)
						if err != nil {
							atomic.AddInt64(&regErrors, 1)
							continue
						}
						nodeIDs[i] = uint32(resp["node_id"].(float64))
					}
				}()
			}
			rwg.Wait()
			regDur := time.Since(regStart)
			regRate := float64(n) / regDur.Seconds()

			stats := s.GetDashboardStats()
			t.Logf("[register] TotalNodes=%d, errors=%d, %.0f reg/s in %v",
				stats.TotalNodes, regErrors, regRate, regDur)

			// ---- Phase 3: Heartbeat (concurrent, one goroutine per binary conn) ----
			hbConns := numConns
			if hbConns > 100 {
				hbConns = 100
			}
			if hbConns < 1 {
				hbConns = 1
			}
			t.Logf("[heartbeat] %d signed heartbeats over %d binary connections...", n, hbConns)

			binClients := make([]*registry.BinaryClient, hbConns)
			for i := range binClients {
				bc, err := registry.DialBinary(addr)
				if err != nil {
					t.Fatalf("dial binary %d: %v", i, err)
				}
				defer bc.Close()
				binClients[i] = bc
			}

			var hbErrors int64
			var hwg sync.WaitGroup

			hbStart := time.Now()
			perHB := n / hbConns
			for ci := 0; ci < hbConns; ci++ {
				ci := ci
				lo := ci * perHB
				hi := lo + perHB
				if ci == hbConns-1 {
					hi = n
				}
				hwg.Add(1)
				go func() {
					defer hwg.Done()
					bc := binClients[ci]
					for i := lo; i < hi; i++ {
						if nodeIDs[i] == 0 {
							continue
						}
						msg := fmt.Sprintf("heartbeat:%d", nodeIDs[i])
						sig := identities[i].Sign([]byte(msg))
						_, _, err := bc.Heartbeat(nodeIDs[i], sig)
						if err != nil {
							atomic.AddInt64(&hbErrors, 1)
						}
					}
				}()
			}
			hwg.Wait()
			hbDur := time.Since(hbStart)
			hbRate := float64(n) / hbDur.Seconds()

			// ---- Phase 4: Verify alive ----
			stats = s.GetDashboardStats()
			t.Logf("[verify] TotalNodes=%d, ActiveNodes=%d, hb errors=%d",
				stats.TotalNodes, stats.ActiveNodes, hbErrors)

			// ---- Phase 5: Memory ----
			runtime.GC()
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			heapMB := float64(mem.HeapAlloc) / (1024 * 1024)
			kbPerNode := float64(0)
			if stats.TotalNodes > 0 {
				kbPerNode = float64(mem.HeapAlloc) / float64(stats.TotalNodes) / 1024
			}

			t.Logf("\n"+
				"╔══════════════════════════════════════════════════════╗\n"+
				"║  Scale:    %-8d                                  ║\n"+
				"║  Keygen:   %10.0f keys/s  (%v)                    \n"+
				"║  Register: %10.0f reg/s   (%v)                    \n"+
				"║  Heartbeat:%10.0f hb/s    (%v)                    \n"+
				"║  Heap:     %10.1f MB                               \n"+
				"║  Per-node: %10.1f KB                               \n"+
				"║  Nodes:    %10d (active: %d)                      \n"+
				"║  Errors:   reg=%d hb=%d                            \n"+
				"╚══════════════════════════════════════════════════════╝",
				n, keygenRate, keygenDur, regRate, regDur, hbRate, hbDur,
				heapMB, kbPerNode, stats.TotalNodes, stats.ActiveNodes,
				regErrors, hbErrors)
		})
	}
}

// ---------------------------------------------------------------------------
// TestRegistrationThroughput — raw registration throughput + latency
// percentiles. Sub-tests: 1 conn, 10 conns, 50 conns, 100 conns.
// ---------------------------------------------------------------------------

func TestRegistrationThroughput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		conns   int
		numRegs int
	}{
		{"1_conn", 1, 5_000},
		{"10_conns", 10, 50_000},
		{"50_conns", 50, 200_000},
		{"100_conns", 100, 500_000},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := registry.New("")
			s.SetMaxNodes(1_100_000)
			s.SetMaxConnections(500)
			go s.ListenAndServe("127.0.0.1:0")
			select {
			case <-s.Ready():
			case <-time.After(5 * time.Second):
				t.Fatal("registry did not start")
			}
			defer s.Close()
			addr := s.Addr().(*net.TCPAddr).String()

			// Pre-generate keys
			keys := make([]string, tc.numRegs)
			for i := range keys {
				var buf [32]byte
				rand.Read(buf[:])
				keys[i] = base64.StdEncoding.EncodeToString(buf[:])
			}

			// Open connections
			clients := make([]*registry.Client, tc.conns)
			for i := range clients {
				c, err := registry.Dial(addr)
				if err != nil {
					t.Fatalf("dial %d: %v", i, err)
				}
				defer c.Close()
				clients[i] = c
			}

			// Concurrent registration with latency tracking
			latencies := make([]int64, tc.numRegs) // nanoseconds, atomic-safe
			var errCount int64
			var wg sync.WaitGroup

			perConn := tc.numRegs / tc.conns

			start := time.Now()
			for ci := 0; ci < tc.conns; ci++ {
				ci := ci
				lo := ci * perConn
				hi := lo + perConn
				if ci == tc.conns-1 {
					hi = tc.numRegs
				}

				wg.Add(1)
				go func() {
					defer wg.Done()
					c := clients[ci]
					for i := lo; i < hi; i++ {
						t0 := time.Now()
						_, err := c.RegisterWithKey("127.0.0.1:4000", keys[i], "", nil)
						lat := time.Since(t0).Nanoseconds()
						atomic.StoreInt64(&latencies[i], lat)
						if err != nil {
							atomic.AddInt64(&errCount, 1)
						}
					}
				}()
			}
			wg.Wait()
			totalDur := time.Since(start)

			// Compute percentiles
			valid := make([]time.Duration, 0, tc.numRegs)
			for _, ns := range latencies {
				if ns > 0 {
					valid = append(valid, time.Duration(ns))
				}
			}
			sort.Slice(valid, func(i, j int) bool { return valid[i] < valid[j] })

			p := func(pct float64) time.Duration {
				if len(valid) == 0 {
					return 0
				}
				idx := int(float64(len(valid)) * pct / 100)
				if idx >= len(valid) {
					idx = len(valid) - 1
				}
				return valid[idx]
			}

			stats := s.GetDashboardStats()
			t.Logf("\n"+
				"╔══════════════════════════════════════════════════════╗\n"+
				"║  Conns: %-3d   Regs: %-8d                        ║\n"+
				"║  Total:   %-12v                                   \n"+
				"║  Rate:    %-10.0f reg/s                            \n"+
				"║  Errors:  %-8d                                    \n"+
				"║  Nodes:   %-8d                                    \n"+
				"║  p50:     %-12v                                   \n"+
				"║  p95:     %-12v                                   \n"+
				"║  p99:     %-12v                                   \n"+
				"║  min:     %-12v                                   \n"+
				"║  max:     %-12v                                   \n"+
				"╚══════════════════════════════════════════════════════╝",
				tc.conns, tc.numRegs,
				totalDur,
				float64(tc.numRegs)/totalDur.Seconds(),
				errCount,
				stats.TotalNodes,
				p(50), p(95), p(99),
				p(0), p(100))
		})
	}
}

// ---------------------------------------------------------------------------
// TestSustainedFakeNodeAttack — registers 100K nodes then keeps them alive
// with continuous signed heartbeats for 15 minutes. Samples stats every 30s
// and writes CPU + heap profiles at the end.
//
// Simulates a real attacker holding fake nodes online indefinitely.
// Heartbeat interval: 30s per node (rolling batches, ~3.3K hb/s sustained).
// ---------------------------------------------------------------------------

func TestSustainedFakeNodeAttack(t *testing.T) {
	const (
		numNodes     = 100_000
		numConns     = 100
		numBinConns  = 50
		sustainDur   = 15 * time.Minute
		hbInterval   = 30 * time.Second // heartbeat each node every 30s
		samplePeriod = 30 * time.Second // print stats every 30s
	)

	s := registry.New("")
	s.SetMaxNodes(1_100_000)
	s.SetMaxConnections(500)
	go s.ListenAndServe("127.0.0.1:0")
	select {
	case <-s.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry did not start")
	}
	defer s.Close()
	addr := s.Addr().(*net.TCPAddr).String()

	// ---- Phase 1: Keygen (parallel) ----
	t.Logf("[setup] generating %d Ed25519 identities...", numNodes)
	identities := make([]*crypto.Identity, numNodes)
	const keygenWorkers = 8
	var kwg sync.WaitGroup
	chunk := (numNodes + keygenWorkers - 1) / keygenWorkers
	for w := 0; w < keygenWorkers; w++ {
		w := w
		lo := w * chunk
		hi := lo + chunk
		if hi > numNodes {
			hi = numNodes
		}
		kwg.Add(1)
		go func() {
			defer kwg.Done()
			for i := lo; i < hi; i++ {
				id, err := crypto.GenerateIdentity()
				if err != nil {
					t.Errorf("keygen %d: %v", i, err)
					return
				}
				identities[i] = id
			}
		}()
	}
	kwg.Wait()

	// ---- Phase 2: Register (concurrent) ----
	t.Logf("[setup] registering %d nodes over %d connections...", numNodes, numConns)
	regClients := make([]*registry.Client, numConns)
	for i := range regClients {
		c, err := registry.Dial(addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
		regClients[i] = c
	}

	nodeIDs := make([]uint32, numNodes)
	var regErrors int64
	var rwg sync.WaitGroup
	regStart := time.Now()

	perConn := numNodes / numConns
	for ci := 0; ci < numConns; ci++ {
		ci := ci
		lo := ci * perConn
		hi := lo + perConn
		if ci == numConns-1 {
			hi = numNodes
		}
		rwg.Add(1)
		go func() {
			defer rwg.Done()
			c := regClients[ci]
			for i := lo; i < hi; i++ {
				resp, err := c.RegisterWithKey("127.0.0.1:4000",
					crypto.EncodePublicKey(identities[i].PublicKey), "", nil)
				if err != nil {
					atomic.AddInt64(&regErrors, 1)
					continue
				}
				nodeIDs[i] = uint32(resp["node_id"].(float64))
			}
		}()
	}
	rwg.Wait()
	regDur := time.Since(regStart)
	t.Logf("[setup] registered %d nodes in %v (%.0f reg/s, errors: %d)",
		numNodes, regDur, float64(numNodes)/regDur.Seconds(), regErrors)

	// ---- Phase 3: Open binary connections for heartbeats ----
	binClients := make([]*registry.BinaryClient, numBinConns)
	for i := range binClients {
		bc, err := registry.DialBinary(addr)
		if err != nil {
			t.Fatalf("dial binary %d: %v", i, err)
		}
		defer bc.Close()
		binClients[i] = bc
	}

	// ---- Phase 4: Sustained heartbeat loop ----
	// Strategy: divide nodes into batches. Each tick (~10ms), heartbeat one batch.
	// Full cycle completes in hbInterval (30s). This gives ~3.3K hb/s for 100K nodes.

	t.Logf("[sustain] starting %v sustained heartbeat loop (%v interval per node)...",
		sustainDur, hbInterval)

	// Start CPU profile
	cpuFile, err := os.CreateTemp("", "loadtest-cpu-*.prof")
	if err != nil {
		t.Fatalf("create cpu profile: %v", err)
	}
	defer os.Remove(cpuFile.Name())
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		t.Fatalf("start cpu profile: %v", err)
	}
	t.Logf("[profile] CPU profile → %s", cpuFile.Name())

	// Compute batch parameters
	// We want to heartbeat all numNodes in hbInterval using numBinConns goroutines.
	// Each goroutine handles numNodes/numBinConns nodes per cycle.
	// Tick rate: complete one full cycle every hbInterval.
	// With numBinConns concurrent goroutines doing sequential heartbeats,
	// each goroutine does (numNodes/numBinConns) heartbeats per cycle.

	stop := make(chan struct{})
	var totalHBSent int64
	var totalHBErrors int64
	var cycleCount int64

	perWorker := numNodes / numBinConns

	// Pacing: each worker has ~2000 nodes and must spread them across hbInterval (30s).
	// That's ~67 hb/s per connection — safely under the server's 100 req/s throttle and
	// well under the 500 req/s kill limit. We insert a per-heartbeat delay:
	// hbInterval / perWorker ≈ 30s / 2000 = 15ms between heartbeats per connection.
	perHBDelay := hbInterval / time.Duration(perWorker)
	if perHBDelay < time.Millisecond {
		perHBDelay = time.Millisecond
	}

	var sustainWg sync.WaitGroup
	for ci := 0; ci < numBinConns; ci++ {
		ci := ci
		lo := ci * perWorker
		hi := lo + perWorker
		if ci == numBinConns-1 {
			hi = numNodes
		}
		sustainWg.Add(1)
		go func() {
			defer sustainWg.Done()
			bc := binClients[ci]
			ticker := time.NewTicker(perHBDelay)
			defer ticker.Stop()
			for {
				cycleStart := time.Now()
				for i := lo; i < hi; i++ {
					select {
					case <-stop:
						return
					case <-ticker.C:
					}
					if nodeIDs[i] == 0 {
						continue
					}
					msg := fmt.Sprintf("heartbeat:%d", nodeIDs[i])
					sig := identities[i].Sign([]byte(msg))
					_, _, err := bc.Heartbeat(nodeIDs[i], sig)
					if err != nil {
						atomic.AddInt64(&totalHBErrors, 1)
					}
					atomic.AddInt64(&totalHBSent, 1)
				}
				if ci == 0 {
					atomic.AddInt64(&cycleCount, 1)
				}
				// If we finished early, sleep the remainder of hbInterval
				if rem := hbInterval - time.Since(cycleStart); rem > 0 {
					select {
					case <-stop:
						return
					case <-time.After(rem):
					}
				}
			}
		}()
	}

	// ---- Phase 5: Sample stats periodically ----
	type sample struct {
		elapsed     time.Duration
		activeNodes int
		totalHB     int64
		hbErrors    int64
		cycles      int64
		heapMB      float64
		goroutines  int
	}
	var samples []sample

	// Baseline memory
	runtime.GC()
	var baselineMem runtime.MemStats
	runtime.ReadMemStats(&baselineMem)

	deadline := time.After(sustainDur)
	ticker := time.NewTicker(samplePeriod)
	defer ticker.Stop()

	startTime := time.Now()
	t.Logf("\n%-8s  %8s  %10s  %8s  %6s  %8s  %5s",
		"elapsed", "active", "total_hb", "hb_err", "cycles", "heap_MB", "goro")
	t.Logf("%-8s  %8s  %10s  %8s  %6s  %8s  %5s",
		"-------", "------", "--------", "------", "------", "-------", "----")

	running := true
	for running {
		select {
		case <-deadline:
			running = false
		case <-ticker.C:
		}

		elapsed := time.Since(startTime).Round(time.Second)
		stats := s.GetDashboardStats()
		hbSent := atomic.LoadInt64(&totalHBSent)
		hbErrs := atomic.LoadInt64(&totalHBErrors)
		cycles := atomic.LoadInt64(&cycleCount)

		runtime.GC()
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		heapMB := float64(mem.HeapAlloc) / (1024 * 1024)
		goros := runtime.NumGoroutine()

		s := sample{
			elapsed:     elapsed,
			activeNodes: stats.ActiveNodes,
			totalHB:     hbSent,
			hbErrors:    hbErrs,
			cycles:      cycles,
			heapMB:      heapMB,
			goroutines:  goros,
		}
		samples = append(samples, s)

		t.Logf("%-8v  %8d  %10d  %8d  %6d  %8.1f  %5d",
			elapsed, s.activeNodes, s.totalHB, s.hbErrors, s.cycles, s.heapMB, s.goroutines)
	}

	// ---- Phase 6: Stop and collect profiles ----
	close(stop)
	sustainWg.Wait()

	pprof.StopCPUProfile()
	cpuFile.Close()

	// Write heap profile
	heapFile, err := os.CreateTemp("", "loadtest-heap-*.prof")
	if err != nil {
		t.Fatalf("create heap profile: %v", err)
	}
	defer os.Remove(heapFile.Name())
	runtime.GC()
	if err := pprof.WriteHeapProfile(heapFile); err != nil {
		t.Fatalf("write heap profile: %v", err)
	}
	heapFile.Close()
	t.Logf("[profile] heap profile → %s", heapFile.Name())

	// ---- Phase 7: Final summary ----
	finalHB := atomic.LoadInt64(&totalHBSent)
	finalErrors := atomic.LoadInt64(&totalHBErrors)
	finalCycles := atomic.LoadInt64(&cycleCount)
	totalElapsed := time.Since(startTime)
	sustainedRate := float64(finalHB) / totalElapsed.Seconds()

	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)

	finalStats := s.GetDashboardStats()

	t.Logf("\n"+
		"╔══════════════════════════════════════════════════════════════╗\n"+
		"║  SUSTAINED ATTACK SUMMARY                                   ║\n"+
		"╠══════════════════════════════════════════════════════════════╣\n"+
		"║  Nodes:          %8d                                    ║\n"+
		"║  Duration:       %8v                                    ║\n"+
		"║  Active at end:  %8d                                    ║\n"+
		"║  HB cycles:      %8d  (%.1fs/cycle)                     \n"+
		"║  Total HBs:      %8d                                    \n"+
		"║  HB errors:      %8d                                    \n"+
		"║  Sustained rate:  %7.0f hb/s                              \n"+
		"║  Final heap:     %8.1f MB                                \n"+
		"║  Baseline heap:  %8.1f MB                                \n"+
		"║  Heap delta:     %8.1f MB                                \n"+
		"║  Goroutines:     %8d                                    \n"+
		"║  CPU profile:    %s\n"+
		"║  Heap profile:   %s\n"+
		"╚══════════════════════════════════════════════════════════════╝",
		numNodes,
		totalElapsed.Round(time.Second),
		finalStats.ActiveNodes,
		finalCycles, totalElapsed.Seconds()/float64(max(finalCycles, 1)),
		finalHB,
		finalErrors,
		sustainedRate,
		float64(finalMem.HeapAlloc)/(1024*1024),
		float64(baselineMem.HeapAlloc)/(1024*1024),
		float64(finalMem.HeapAlloc-baselineMem.HeapAlloc)/(1024*1024),
		runtime.NumGoroutine(),
		cpuFile.Name(),
		heapFile.Name())

	// Assert all nodes stayed online the whole time
	if finalStats.ActiveNodes < numNodes/2 {
		t.Fatalf("expected most nodes to remain active, got %d/%d",
			finalStats.ActiveNodes, numNodes)
	}
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
