// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"

	bwss "github.com/TeoSlayer/pilotprotocol/pkg/beacon/wss"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// beaconNode tracks a node's observed endpoint and when it was last seen.
type beaconNode struct {
	addr     *net.UDPAddr
	lastSeen time.Time
}

// relayJob is a pre-parsed relay packet dispatched to a worker.
type relayJob struct {
	senderID uint32
	destID   uint32
	payload  []byte // owned by the job, returned to pool after send
}

type Server struct {
	mu             sync.RWMutex       // protects registryAddr / advertiseAddr / registryAdminToken
	conn           *net.UDPConn       // primary read+write socket; equal to conns[0]
	conns          []*net.UDPConn     // SO_REUSEPORT sockets — one per reader goroutine
	sendBatchConns []*ipv4.PacketConn // ipv4 wrappers of conns[i] for WriteBatch (sendmmsg) — one per worker fd
	nodes          *nodeMap           // sharded node_id → observed endpoint + last-seen
	readyCh        chan struct{}
	relayCh        chan relayJob // buffered channel for relay workers
	pool           sync.Pool     // reusable payload buffers (inner relay payload)
	outBufPool     sync.Pool     // reusable outbound packet buffers (header + payload)

	// Relay counters (atomic for lock-free worker access)
	relayForwarded  atomic.Uint64 // successful relay deliveries
	relayDropped    atomic.Uint64 // queue-full drops
	relayNotFound   atomic.Uint64 // unknown destination drops
	lastDropLog     atomic.Int64  // UnixNano of last drop warning (rate limit)
	lastNotFoundLog atomic.Int64  // UnixNano of last not-found warning (rate limit)

	// Peer mesh (gossip)
	beaconID    uint32
	peers       []*net.UDPAddr                          // peer beacon addresses (slow path, peerMu)
	peerNodes   atomic.Pointer[map[uint32]*net.UDPAddr] // nodeID → peer beacon (hot read, copy-on-write)
	peerWriteMu sync.Mutex                              // serialises copy-on-write writers to peerNodes
	peerMu      sync.RWMutex                            // protects s.peers only (peerNodes is atomic)
	healthOk    atomic.Bool

	registryAddr       string // registry address for dynamic peer discovery
	advertiseAddr      string // address to register (overrides auto-detect from TCP local addr)
	registryAdminToken string // admin token sent with beacon_register (required by SEC-002)

	// Compat-mode WSS bridge. Set via EnableCompatWSS. When non-nil,
	// the relay worker checks for a WSS-connected destination BEFORE
	// the UDP tier-1/2 lookups. Inbound WSS frames feed into
	// handlePacket the same way UDP datagrams do.
	wssServer *bwss.Server

	done chan struct{} // closed on shutdown
}

// relayQueueSize is the buffered channel depth between the read loop
// and the relay workers. Bumped from 128K → 512K on 2026-05-14 after
// the LB started dropping ~56 packets/sec under 171k+ active nodes —
// inbound relay rate was slightly exceeding the workers' drain rate,
// queue pinned at cap, every further enqueue dropped. 4× buffer +
// 2× workers (see ListenAndServe) gives the workers more slack to
// absorb bursts; per-job memory is small (relayJob = senderID(4) +
// destID(4) + a pooled []byte payload), so worst-case bump is ~50MB.
const relayQueueSize = 524288

// maxRelayPayload caps the relay payload size. UDP itself limits datagrams to ~65KB,
// but this provides defense-in-depth against future transport changes.
const maxRelayPayload = 65535

// maxBeaconNodes caps the number of tracked nodes to prevent memory exhaustion.
// At ~32 bytes per node, 500k entries consume ~16 MB — well within fleet budget.
// Raised from 100k after the network grew past that threshold (v1.9.4).
const maxBeaconNodes = 500_000

// beaconNodeTTL is how long a node entry lives without a discover refresh.
// Set to 10 minutes (well above the 60s heartbeat-driven re-discover interval)
// so nodes survive brief registry outages without losing beacon registration.
const beaconNodeTTL = 10 * time.Minute

func New() *Server {
	return NewWithPeers(0, nil)
}

// NewWithPeers creates a beacon server with gossip peer support.
// beaconID uniquely identifies this beacon instance (0 = standalone).
// peers is a list of peer beacon addresses for gossip exchange.
func NewWithPeers(beaconID uint32, peers []string) *Server {
	s := &Server{
		nodes:    newNodeMap(),
		readyCh:  make(chan struct{}),
		relayCh:  make(chan relayJob, relayQueueSize),
		beaconID: beaconID,
		done:     make(chan struct{}),
	}
	emptyPeers := make(map[uint32]*net.UDPAddr)
	s.peerNodes.Store(&emptyPeers)
	s.pool.New = func() interface{} {
		b := make([]byte, 1500)
		return &b
	}
	// outBufs hold "header + relay payload". maxRelayPayload caps the
	// payload at 65535; longest header is BeaconMsgRelay (1+4+4 = 9
	// bytes). Pre-size to 65544 so every slice fits with no growSlice.
	s.outBufPool.New = func() interface{} {
		b := make([]byte, maxRelayPayload+9)
		return &b
	}
	s.healthOk.Store(true)

	for _, p := range peers {
		addr, err := net.ResolveUDPAddr("udp", p)
		if err != nil {
			slog.Warn("beacon: invalid peer address", "addr", p, "err", err)
			continue
		}
		s.peers = append(s.peers, addr)
	}

	return s
}

// EnableCompatWSS attaches a WSS-bridge listener for compat-mode
// daemons. After Start, the beacon's relay worker checks the WSS
// peer map BEFORE the UDP tier-1/2 lookups: relay packets destined
// for a WSS-connected daemon are written over WSS instead of UDP.
// Inbound WSS frames feed into handlePacket the same way UDP
// datagrams do, so the existing dispatch logic (BeaconMsgRelay,
// BeaconMsgDiscover, etc.) handles them without changes.
//
// pubKeyLookup must return the Ed25519 pubkey registered for nodeID.
// In the rendezvous binary this is plumbed to the in-process
// registry's pubkey index.
//
// Call this BEFORE ListenAndServe so the wssServer is in place
// when the first UDP datagram arrives.
func (s *Server) EnableCompatWSS(bindAddr string, pubKeyLookup bwss.PubKeyLookupFn) error {
	if s.wssServer != nil {
		return fmt.Errorf("beacon: compat WSS already enabled")
	}
	ws, err := bwss.New(bwss.Config{
		BindAddr:     bindAddr,
		PubKeyLookup: pubKeyLookup,
		OnFrame: func(senderID uint32, frame []byte) {
			// A WSS frame from a compat peer carries a raw Pilot
			// beacon-protocol packet (the same bytes the daemon
			// would have written to UDP). Dispatch it through
			// handlePacket so the existing BeaconMsgRelay /
			// BeaconMsgDiscover / BeaconMsgPunchRequest branches
			// handle it identically. The synthetic remote address
			// is informational only — handlers that need a real
			// remote addr (e.g. handleDiscover replies) skip the
			// reply when the source is a WSS peer; see fast-path
			// notes in those handlers.
			synth := &net.UDPAddr{
				IP:   net.ParseIP("192.0.2.1"),
				Port: int(senderID & 0xFFFF),
			}
			s.handlePacket(frame, synth)
		},
	})
	if err != nil {
		return fmt.Errorf("beacon: create WSS server: %w", err)
	}
	if err := ws.Start(); err != nil {
		return fmt.Errorf("beacon: start WSS server: %w", err)
	}
	s.wssServer = ws
	slog.Info("beacon compat WSS bridge enabled", "bind", ws.Addr())
	return nil
}

// WSSMetrics returns the live WSS-bridge metrics, or zero values if
// EnableCompatWSS was never called. Used by the dashboard / Prom
// scrape to expose compat-mode visibility.
func (s *Server) WSSMetrics() bwss.Metrics {
	if s.wssServer == nil {
		return bwss.Metrics{}
	}
	return s.wssServer.Metrics()
}

// CloseCompatWSS shuts down the WSS bridge. Idempotent. Used by
// graceful shutdown paths and tests.
func (s *Server) CloseCompatWSS() error {
	if s.wssServer == nil {
		return nil
	}
	err := s.wssServer.Close()
	s.wssServer = nil
	return err
}

func (s *Server) ListenAndServe(addr string) error {
	// Open one UDP socket per CPU core via SO_REUSEPORT (Linux) so the
	// kernel flow-hashes incoming packets across N user-space readers.
	// The pre-shard implementation used a single net.ListenUDP and one
	// read goroutine, which became the throughput cliff under full
	// fleet Discover load — see nodeMap doc for the lock side; this is
	// the kernel side of the same fix.
	// 2× NumCPU readers (16 → 32 on the LB box). More SO_REUSEPORT
	// buckets means the kernel's 5-tuple hash spreads chatty source
	// IPs across more sockets; we previously saw one socket pinned
	// at 8MB Recv-Q while others sat idle when a handful of busy
	// peers hashed to the same fd.
	readers := runtime.NumCPU() * 2
	if readers < 2 {
		readers = 2
	}
	// Non-Linux platforms (Mac dev / Windows / etc.) lack flow-hashing
	// SO_REUSEPORT semantics; a second bind to the same UDP port fails
	// with EADDRINUSE. MaxReusePortShards is 1 there, 0 (= unlimited)
	// on Linux.
	if MaxReusePortShards > 0 && readers > MaxReusePortShards {
		readers = MaxReusePortShards
	}
	s.conns = make([]*net.UDPConn, 0, readers)
	for i := 0; i < readers; i++ {
		c, err := listenReusePort(addr)
		if err != nil {
			// Best-effort cleanup of any already-open sockets so we don't leak fds.
			for _, opened := range s.conns {
				_ = opened.Close()
			}
			return fmt.Errorf("listen %d: %w", i, err)
		}
		// 16 MB per socket — matches the kernel net.core.rmem_max ceiling.
		// Was 8 MB; bumped after observing kernel RcvbufErrors under bursty
		// load (the 8 MB per-fd buffer couldn't absorb 30-second bursts
		// before the readLoop drained it). Read and write set symmetrically
		// so outbound bursts have equal headroom.
		_ = c.SetReadBuffer(16 * 1024 * 1024)  // 16MB per socket — UDP recv (was 8MB)
		_ = c.SetWriteBuffer(16 * 1024 * 1024) // 16MB per socket — UDP send (was 8MB)
		s.conns = append(s.conns, c)
	}
	s.conn = s.conns[0] // non-relay sends (Discover replies, gossip, etc.) go through fd 0
	// One ipv4 wrapper per UDP fd. Pre-2026-05-14 all workers shared a
	// single wrapper of s.conn[0], which serialised every WriteBatch on
	// that one fd's kernel-side socket lock — workers hit ~190k/sec
	// aggregate forward rate even with sendmmsg, and the LB started
	// dropping ~160k/sec relay packets when inbound exceeded that ceiling.
	// Fanning workers across the SO_REUSEPORT fds removes the per-fd
	// contention; each fd takes ~12k/sec instead of one fd taking 190k/sec.
	//
	// Fan-out only works when all sockets share the same local port
	// (true on Linux via SO_REUSEPORT). On non-Linux platforms
	// (Darwin/test rigs) listenReusePort falls back to plain ListenUDP,
	// so each conn gets a different ephemeral port — sending from a
	// non-canonical port breaks any peer that dialed conns[0]'s port.
	// In that case we route all sends through the canonical fd.
	basePort := s.conns[0].LocalAddr().(*net.UDPAddr).Port
	sharedPort := true
	for _, c := range s.conns[1:] {
		if c.LocalAddr().(*net.UDPAddr).Port != basePort {
			sharedPort = false
			break
		}
	}
	if sharedPort {
		s.sendBatchConns = make([]*ipv4.PacketConn, len(s.conns))
		for i, c := range s.conns {
			s.sendBatchConns[i] = ipv4.NewPacketConn(c)
		}
	} else {
		s.sendBatchConns = []*ipv4.PacketConn{ipv4.NewPacketConn(s.conn)}
	}

	slog.Info("beacon listening", "addr", s.conn.LocalAddr(), "beacon_id", s.beaconID, "peers", len(s.peers), "readers", readers)
	close(s.readyCh)

	// Start relay workers. The 2026-05-14 hotfix wave:
	//   1. Bumped count 2× → 4× CPU cores (more parallel WriteBatch calls)
	//   2. Switched from per-packet WriteToUDP to sendmmsg via ipv4.WriteBatch
	//      (each worker batches up to 32 messages then flushes; saves
	//      ~32× syscall overhead under steady load).
	//   3. Brought count back down to 1× CPU. With 4× workers the inbound
	//      rate (~200k/sec post-recvmmsg) spread to ~3k/sec per worker,
	//      which hit the 500µs flush timer with only 1-2 packets in the
	//      batch — most sendmmsg calls were tiny, wasting the batch path.
	//      At 1× workers each gets ~12k/sec, so the 2ms flush window
	//      fills batches to ~24 packets (near the 32 cap). Same total
	//      drain capacity, ~4× fewer sendmmsg syscalls.
	// Each worker is one goroutine + a 32-slot ipv4.Message buffer + a
	// 32-slot payload-return slice (~6 KB).
	workers := runtime.NumCPU()
	if workers < 8 {
		workers = 8
	}
	for i := 0; i < workers; i++ {
		go s.relayWorker(s.sendBatchConns[i%len(s.sendBatchConns)])
	}

	// Start relay stats logger (every 60s)
	go s.relayStatsLoop()

	// Start reap loop to evict stale node entries
	go s.reapLoop()

	// Start gossip loop (always — peers may be added dynamically via registry)
	go s.gossipLoop()

	// Start registry-based peer discovery. The loop checks registryAddr at
	// runtime so it is started unconditionally; SetRegistry may be called
	// after ListenAndServe and the loop will pick up the address on its
	// next tick without requiring a restart.
	go s.registryDiscoveryLoop()

	// Spawn N-1 reader goroutines; the last one runs inline so the caller
	// blocks here as the existing API requires. All N sockets are bound
	// to the same UDP port via SO_REUSEPORT — the kernel splits packets.
	errCh := make(chan error, len(s.conns))
	for i := 1; i < len(s.conns); i++ {
		go func(c *net.UDPConn) { errCh <- s.readLoop(c) }(s.conns[i])
	}
	return s.readLoop(s.conns[0])
}

// readBatchCap is the upper bound on packets one readLoop pulls per
// recvmmsg syscall. Mirrors the send side's relayBatchCap. 32 was
// chosen so each socket can drain its Recv-Q in 32-packet chunks
// instead of one-by-one — under the 2026-05-14 LB load the kernel
// Recv-Q was running 50-95% full on most SO_REUSEPORT sockets and
// RcvbufErrors was accumulating at ~250/s, because the prior
// per-packet ReadFromUDP path paid one syscall per packet.
const readBatchCap = 32

// readLoop is the per-socket receive path. One per SO_REUSEPORT socket.
// Uses ipv4.PacketConn.ReadBatch (recvmmsg on Linux) to pull up to
// readBatchCap packets in a single syscall, then dispatches each
// synchronously through handlePacket. Each message has its own
// pre-allocated 65535-byte buffer so there is no cross-goroutine
// allocation contention. On non-Linux platforms the x/net/ipv4
// fallback degrades to per-message ReadFrom, preserving correctness.
func (s *Server) readLoop(conn *net.UDPConn) error {
	pc := ipv4.NewPacketConn(conn)
	msgs := make([]ipv4.Message, readBatchCap)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, 65535)}
	}
	for {
		n, err := pc.ReadBatch(msgs, 0)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return nil
			}
			slog.Debug("beacon read batch error", "err", err)
			continue
		}
		for i := 0; i < n; i++ {
			m := &msgs[i]
			if m.N < 1 {
				continue
			}
			addr, ok := m.Addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			s.handlePacket(m.Buffers[0][:m.N], addr)
		}
	}
}

// Ready returns a channel that is closed when the server has bound its port.
func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// Addr returns the server's bound address. Only valid after Ready() fires.
func (s *Server) Addr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *Server) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	var firstErr error
	for _, c := range s.conns {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RelayForwarded returns the count of relay packets the beacon
// has forwarded since startup. Used by /api/stats to surface
// observable evidence that the relay path is live.
func (s *Server) RelayForwarded() uint64 { return s.relayForwarded.Load() }

// RelayDropped returns the count of relay packets dropped (capacity / errors).
func (s *Server) RelayDropped() uint64 { return s.relayDropped.Load() }

// RelayNotFound returns the count of relay packets dropped because the destination
// node was not registered with the beacon.
func (s *Server) RelayNotFound() uint64 { return s.relayNotFound.Load() }

func (s *Server) handlePacket(data []byte, remote *net.UDPAddr) {
	msgType := data[0]

	switch msgType {
	case protocol.BeaconMsgDiscover:
		s.handleDiscover(data[1:], remote)
	case protocol.BeaconMsgPunchRequest:
		s.handlePunchRequest(data[1:], remote)
	case protocol.BeaconMsgRelay:
		s.dispatchRelay(data[1:])
	case protocol.BeaconMsgSync:
		s.handleSync(data[1:], remote)
	default:
		slog.Debug("unknown beacon message type", "type", fmt.Sprintf("0x%02X", msgType), "from", remote)
	}
}

func (s *Server) handleDiscover(data []byte, remote *net.UDPAddr) {
	if len(data) < 4 {
		return
	}

	nodeID := binary.BigEndian.Uint32(data[0:4])

	// Record this node's observed public endpoint. Sharded — no global lock.
	if _, atCap := s.nodes.Upsert(nodeID, remote, time.Now(), maxBeaconNodes); atCap {
		return // shard at capacity — drop silently
	}

	slog.Debug("beacon discover", "node_id", nodeID, "addr", remote)

	// Reply with observed IP:port using variable-length IP encoding
	ip := remote.IP.To4()
	if ip == nil {
		ip = remote.IP.To16()
	}
	if ip == nil {
		slog.Warn("beacon: cannot encode IP", "node_id", nodeID, "addr", remote)
		return
	}

	// Format: [type(1)][iplen(1)][IP(4 or 16)][port(2)]
	reply := make([]byte, 1+1+len(ip)+2)
	reply[0] = protocol.BeaconMsgDiscoverReply
	reply[1] = byte(len(ip))
	copy(reply[2:2+len(ip)], ip)
	binary.BigEndian.PutUint16(reply[2+len(ip):], uint16(remote.Port))

	if _, err := s.conn.WriteToUDP(reply, remote); err != nil {
		slog.Debug("beacon discover reply failed", "node_id", nodeID, "err", err)
	}
}

func (s *Server) handlePunchRequest(data []byte, remote *net.UDPAddr) {
	if len(data) < 8 {
		return
	}

	requesterID := binary.BigEndian.Uint32(data[0:4])
	targetID := binary.BigEndian.Uint32(data[4:8])

	// Update requester's endpoint (handles symmetric NAT port changes).
	s.nodes.Upsert(requesterID, remote, time.Now(), maxBeaconNodes)

	targetNode := s.nodes.Get(targetID)
	requesterNode := s.nodes.Get(requesterID)
	if targetNode == nil {
		slog.Warn("punch target not found", "target_id", targetID)
		return
	}
	if requesterNode == nil {
		slog.Warn("punch requester not found", "requester_id", requesterID)
		return
	}

	targetAddr := targetNode.addr
	requesterAddr := requesterNode.addr

	// Send punch commands to both sides
	if err := s.SendPunchCommand(requesterID, targetAddr.IP, uint16(targetAddr.Port)); err != nil {
		slog.Debug("punch command to requester failed", "node_id", requesterID, "err", err)
	}
	if err := s.SendPunchCommand(targetID, requesterAddr.IP, uint16(requesterAddr.Port)); err != nil {
		slog.Debug("punch command to target failed", "node_id", targetID, "err", err)
	}
	slog.Debug("punch coordinated", "requester", requesterID, "target", targetID,
		"requester_addr", requesterAddr, "target_addr", targetAddr)
}

// dispatchRelay parses the relay header and dispatches to a worker goroutine.
// The read loop stays fast — no locks (other than a sharded RLock for the
// pre-check), no syscalls, no allocations on the hot path.
func (s *Server) dispatchRelay(data []byte) {
	if len(data) < 8 {
		return
	}

	senderID := binary.BigEndian.Uint32(data[0:4])
	destID := binary.BigEndian.Uint32(data[4:8])

	// Pre-check destination presence before paying the per-packet
	// payload-copy + queue-enqueue + worker-dequeue costs. Without
	// this, every relay for an unknown destination still went all the
	// way through to a worker, which did the same lookup, dropped,
	// and counted not_found. Profile snapshot during the 171k-active
	// nodes overload (2026-05-14) showed ~65% of relay dispatches
	// fell into the worker not-found path — pure wasted work that
	// also kept the relay queue at cap (queue-full drops cascade).
	//
	// Doing the lookup here at the read loop:
	//   - cuts worker queue pressure (the productive 35% gets through
	//     freely; nothing else even enters the queue)
	//   - frees the ~15% of total CPU workers were burning on not-found
	//   - pays a sharded RLock + map-get per inbound relay packet,
	//     measured ~50ns and contention-free (64 shards distribute
	//     by destID)
	//
	// Race: a destination could send Discover concurrently with a
	// sender's relay arriving. With this pre-check, the relay drops
	// in that microsecond window. UDP is best-effort; sender retries
	// (existing 3-attempt path in pkg/daemon/daemon.go relay branch)
	// will catch the next iteration once Discover has propagated.
	if s.nodes.Get(destID) == nil {
		// Tier-2 fallback: check the peer mesh. peerNodes is an
		// atomic.Pointer to a map; reads are lock-free (a single
		// pointer load + map lookup). Writes copy-on-write under
		// peerWriteMu — see handleSync. At 300k+ relays/sec the
		// previous peerMu RLock showed up as 11% CPU in lock2/futex.
		peerMap := *s.peerNodes.Load()
		_, peerOk := peerMap[destID]
		// Tier-WSS fallback (compat mode): if the dest isn't in
		// the local UDP table or the peer mesh, it might be a
		// compat-mode daemon connected via WSS. Skip the
		// not-found drop in that case — the worker's Tier-0 check
		// will do the actual WSS write.
		wssOk := s.wssServer != nil && s.wssServer.IsConnected(destID)
		if !peerOk && !wssOk {
			// Same accounting as the worker's Tier-3 path would do,
			// minus the per-packet log line — relayStatsLoop surfaces
			// the count every 60s, which is the only visibility we
			// actually use today.
			s.relayNotFound.Add(1)
			return
		}
	}

	// Copy payload into a pooled buffer so we don't hold the read buffer
	payload := data[8:]
	if len(payload) > maxRelayPayload {
		return // oversized relay payload — drop silently
	}
	bp := s.pool.Get().(*[]byte)
	buf := *bp
	if cap(buf) < len(payload) {
		buf = make([]byte, len(payload))
	} else {
		buf = buf[:len(payload)]
	}
	copy(buf, payload)

	select {
	case s.relayCh <- relayJob{senderID: senderID, destID: destID, payload: buf}:
	default:
		// Queue full — drop packet (UDP is best-effort). Rare now that
		// the pre-check filters not-found at the read loop, but still
		// possible if found-traffic alone exceeds worker drain rate.
		s.relayDropped.Add(1)
		now := time.Now().UnixNano()
		if last := s.lastDropLog.Load(); now-last > int64(time.Second) {
			if s.lastDropLog.CompareAndSwap(last, now) {
				slog.Warn("relay queue full, dropping packet", "sender", senderID, "dest", destID)
			}
		}
		*bp = buf[:cap(buf)]
		s.pool.Put(bp)
	}
}

// relayBatchCap is the upper bound on packets a worker batches before
// flushing via sendmmsg. 32 is the sweet spot: large enough that the
// per-syscall overhead is amortised across many packets, small enough
// that batch-fill latency stays sub-millisecond under steady load.
const relayBatchCap = 32

// relayFlushAfter caps the latency a packet spends sitting in a worker's
// batch waiting for siblings. Bumped 500µs → 2ms on 2026-05-14 when
// post-recvmmsg measurements showed batches typically flushing on the
// timer (not the cap), with only 1-2 packets in the batch. 2 ms paired
// with 1× CPU workers gets each batch near the 32 cap before flushing.
// 2 ms is still negligible vs network jitter (the LB sits 50-150 ms
// from end-user daemons; another 2 ms of buffering is invisible).
const relayFlushAfter = 2 * time.Millisecond

// relayWorker processes relay jobs: dest lookup and batched UDP send.
// Workers maintain a local batch of up to relayBatchCap messages and
// flush via ipv4.PacketConn.WriteBatch (sendmmsg on Linux) when the
// batch fills OR when relayFlushAfter elapses since the first message.
//
// 3-tier destination lookup is unchanged from the pre-batching code:
//  1. Local nodes map → MsgRelayDeliver directly to agent
//  2. Peer nodes map → forward MsgRelay to peer beacon
//  3. Neither → drop (unknown dest, counter only — no per-packet log)
//
// Each worker is pinned to one of the SO_REUSEPORT fds (round-robin in
// ListenAndServe). Because the kernel takes a per-fd socket lock on
// every send, sharing one fd across all workers serialised every
// WriteBatch globally — the send-side bottleneck before fan-out.
// With per-fd workers, sends parallelise across fds and the only
// serialisation left is per-worker (its own batch state).
func (s *Server) relayWorker(sendConn *ipv4.PacketConn) {
	msgs := make([]ipv4.Message, 0, relayBatchCap)
	payloadsToReturn := make([][]byte, 0, relayBatchCap)
	outBufsToReturn := make([]*[]byte, 0, relayBatchCap)

	flush := func() {
		if len(msgs) == 0 {
			return
		}
		n, err := sendConn.WriteBatch(msgs, 0)
		if err != nil {
			slog.Debug("relay write batch failed", "n", n, "of", len(msgs), "err", err)
		}
		if n > 0 {
			s.relayForwarded.Add(uint64(n))
		}
		for _, p := range payloadsToReturn {
			s.returnPayload(p)
		}
		for _, b := range outBufsToReturn {
			*b = (*b)[:cap(*b)]
			s.outBufPool.Put(b)
		}
		msgs = msgs[:0]
		payloadsToReturn = payloadsToReturn[:0]
		outBufsToReturn = outBufsToReturn[:0]
	}

	timer := time.NewTimer(relayFlushAfter)
	if !timer.Stop() {
		<-timer.C
	}
	timerActive := false

	for {
		select {
		case <-s.done:
			flush()
			return
		case <-timer.C:
			timerActive = false
			flush()
			continue
		case job := <-s.relayCh:
			// Tier 0: compat-mode WSS destination. Bypass the
			// sendmmsg batching path entirely — WSS writes go to a
			// per-conn TCP stream, no batching benefit. The WSS
			// frame is shaped exactly like a local-UDP delivery
			// (BeaconMsgRelayDeliver + senderID + payload) so the
			// receiving compat daemon's L4 dispatcher routes it
			// identically to a UDP-arrived relay-deliver packet.
			if s.wssServer != nil && s.wssServer.IsConnected(job.destID) {
				obp := s.outBufPool.Get().(*[]byte)
				outBuf := *obp
				outBuf = outBuf[:1+4+len(job.payload)]
				outBuf[0] = protocol.BeaconMsgRelayDeliver
				binary.BigEndian.PutUint32(outBuf[1:5], job.senderID)
				copy(outBuf[5:], job.payload)
				if s.wssServer.WriteFrame(job.destID, outBuf) {
					s.relayForwarded.Add(1)
				} else {
					// Conn dropped between IsConnected and Write —
					// the WSS server has already disconnected the
					// peer. Count as not-found rather than dropped:
					// the dest is genuinely gone.
					s.relayNotFound.Add(1)
				}
				s.returnPayload(job.payload)
				*obp = outBuf[:cap(outBuf)]
				s.outBufPool.Put(obp)
				continue
			}

			// Tier 1: local node lookup — sharded, RLock + snapshot.
			// We use Snapshot (not Get) so the addr read happens under
			// the shard's RLock — Upsert writes `addr` under that same
			// lock, and the race detector flagged the previous Get+read
			// pattern on 2026-05-19.
			localAddr, localOk := s.nodes.Snapshot(job.destID)
			obp := s.outBufPool.Get().(*[]byte)
			outBuf := *obp
			var addr *net.UDPAddr
			if localOk {
				addr = localAddr
				outBuf = outBuf[:1+4+len(job.payload)]
				outBuf[0] = protocol.BeaconMsgRelayDeliver
				binary.BigEndian.PutUint32(outBuf[1:5], job.senderID)
				copy(outBuf[5:], job.payload)
			} else {
				// Tier 2: peer beacon lookup. peerNodes is an
				// atomic.Pointer; reads are lock-free.
				peerMap := *s.peerNodes.Load()
				peerAddr, peerOk := peerMap[job.destID]
				if !peerOk {
					// Tier 3: unknown dest. Counter only — the
					// per-packet slog.Warn that used to live here cost
					// real CPU on every miss (rate-limited or not).
					// relayStatsLoop's periodic INFO already surfaces
					// the count to operators.
					s.relayNotFound.Add(1)
					s.returnPayload(job.payload)
					*obp = (*obp)[:cap(*obp)]
					s.outBufPool.Put(obp)
					continue
				}
				addr = peerAddr
				outBuf = outBuf[:1+4+4+len(job.payload)]
				outBuf[0] = protocol.BeaconMsgRelay
				binary.BigEndian.PutUint32(outBuf[1:5], job.senderID)
				binary.BigEndian.PutUint32(outBuf[5:9], job.destID)
				copy(outBuf[9:], job.payload)
			}
			*obp = outBuf

			msgs = append(msgs, ipv4.Message{
				Buffers: [][]byte{outBuf},
				Addr:    addr,
			})
			payloadsToReturn = append(payloadsToReturn, job.payload)
			outBufsToReturn = append(outBufsToReturn, obp)

			if len(msgs) >= relayBatchCap {
				if timerActive {
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timerActive = false
				}
				flush()
			} else if !timerActive {
				timer.Reset(relayFlushAfter)
				timerActive = true
			}
		}
	}
}

func (s *Server) returnPayload(buf []byte) {
	buf = buf[:cap(buf)]
	s.pool.Put(&buf)
}

// relayStatsLoop logs relay counters every 60 seconds.
func (s *Server) relayStatsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			fwd := s.relayForwarded.Load()
			drop := s.relayDropped.Load()
			nf := s.relayNotFound.Load()
			if fwd > 0 || drop > 0 || nf > 0 {
				slog.Info("relay stats", "forwarded", fwd, "dropped", drop, "not_found", nf)
			}
		}
	}
}

// SendPunchCommand tells a node to send UDP to a target endpoint.
func (s *Server) SendPunchCommand(nodeID uint32, targetIP net.IP, targetPort uint16) error {
	node := s.nodes.Get(nodeID)
	if node == nil {
		return fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	nodeAddr := node.addr

	ip := targetIP.To4()
	if ip == nil {
		ip = targetIP.To16()
	}
	if ip == nil {
		return fmt.Errorf("cannot encode target IP")
	}

	// Format: [type(1)][iplen(1)][IP(4 or 16)][port(2)]
	msg := make([]byte, 1+1+len(ip)+2)
	msg[0] = protocol.BeaconMsgPunchCommand
	msg[1] = byte(len(ip))
	copy(msg[2:2+len(ip)], ip)
	binary.BigEndian.PutUint16(msg[2+len(ip):], targetPort)

	_, err := s.conn.WriteToUDP(msg, nodeAddr)
	return err
}

// --- Reap ---

// reapLoop periodically removes stale node entries that haven't sent a
// discover message within beaconNodeTTL. Prevents dead nodes from
// accumulating indefinitely.
func (s *Server) reapLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.reapStaleNodes()
		case <-s.done:
			return
		}
	}
}

func (s *Server) reapStaleNodes() {
	threshold := time.Now().Add(-beaconNodeTTL)
	s.nodes.ReapStale(threshold)
}

// --- Gossip ---

// gossipLoop periodically sends the local node list to all peer beacons.
// Format: [0x07][beaconID(4)][nodeCount(2)][nodeID(4)]...[nodeID(4)]
func (s *Server) gossipLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.sendGossip()
		case <-s.done:
			return
		}
	}
}

func (s *Server) sendGossip() {
	nodeIDs := s.nodes.IDs()

	if len(nodeIDs) > 65535 {
		nodeIDs = nodeIDs[:65535] // cap at uint16 max
	}

	// Build sync message: [type(1)][beaconID(4)][nodeCount(2)][nodeID(4)...]
	msgLen := 1 + 4 + 2 + 4*len(nodeIDs)
	msg := make([]byte, msgLen)
	msg[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(msg[1:5], s.beaconID)
	binary.BigEndian.PutUint16(msg[5:7], uint16(len(nodeIDs)))
	for i, id := range nodeIDs {
		binary.BigEndian.PutUint32(msg[7+4*i:7+4*i+4], id)
	}

	s.peerMu.RLock()
	peers := make([]*net.UDPAddr, len(s.peers))
	copy(peers, s.peers)
	s.peerMu.RUnlock()

	for _, peer := range peers {
		if _, err := s.conn.WriteToUDP(msg, peer); err != nil {
			slog.Debug("gossip send failed", "peer", peer, "err", err)
		}
	}

	slog.Debug("gossip sent", "beacon_id", s.beaconID, "nodes", len(nodeIDs), "peers", len(peers))
}

// handleSync processes an incoming gossip sync message from a peer beacon.
func (s *Server) handleSync(data []byte, remote *net.UDPAddr) {
	// Need at least beaconID(4) + nodeCount(2)
	if len(data) < 6 {
		return
	}

	peerBeaconID := binary.BigEndian.Uint32(data[0:4])
	nodeCount := binary.BigEndian.Uint16(data[4:6])

	// Validate message length
	expected := 6 + 4*int(nodeCount)
	if len(data) < expected {
		slog.Debug("gossip sync message too short", "peer_beacon_id", peerBeaconID, "expected", expected, "got", len(data))
		return
	}

	// Parse node IDs
	nodeIDs := make([]uint32, nodeCount)
	for i := 0; i < int(nodeCount); i++ {
		nodeIDs[i] = binary.BigEndian.Uint32(data[6+4*i : 6+4*i+4])
	}

	// Update peer node map via copy-on-write. peerWriteMu serialises
	// concurrent gossip writers; readers (on the relay hot path) load
	// the pointer lock-free.
	s.peerWriteMu.Lock()
	cur := *s.peerNodes.Load()
	next := make(map[uint32]*net.UDPAddr, len(cur)+len(nodeIDs))
	for id, addr := range cur {
		if !(addr.IP.Equal(remote.IP) && addr.Port == remote.Port) {
			next[id] = addr
		}
	}
	for _, id := range nodeIDs {
		if !s.nodes.Has(id) {
			next[id] = remote
		}
	}
	s.peerNodes.Store(&next)
	s.peerWriteMu.Unlock()

	slog.Debug("gossip sync received", "peer_beacon_id", peerBeaconID, "nodes", nodeCount, "from", remote)
}

// --- Registry-based peer discovery ---

// SetRegistry sets the registry address for dynamic peer discovery.
// Safe to call at any time — protected by mu so the discovery loop
// does not race against a post-startup SetRegistry call.
func (s *Server) SetRegistry(addr string) {
	s.mu.Lock()
	s.registryAddr = addr
	s.mu.Unlock()
}

// SetAdvertiseAddr sets the address this beacon registers with the registry.
// When empty (default), the beacon auto-detects from its TCP local addr to
// the registry — which on a GCP MIG deployment yields the INTERNAL VPC
// address (10.128.0.x), unreachable from external daemons. MIG-deployed
// beacons must set this to the public DNAT entrypoint (e.g. the rendezvous
// reserved IP on UDP 9001) so external clients receive a routable address
// from beacon_list.
func (s *Server) SetAdvertiseAddr(addr string) {
	s.mu.Lock()
	s.advertiseAddr = addr
	s.mu.Unlock()
}

// SetRegistryAdminToken sets the admin token sent with beacon_register.
// Required when the registry enforces SEC-002 beacon registration auth.
func (s *Server) SetRegistryAdminToken(token string) {
	s.mu.Lock()
	s.registryAdminToken = token
	s.mu.Unlock()
}

// registryDiscoveryLoop registers this beacon with the registry and discovers
// peers every 30 seconds. Requires the beacon to be listening (conn bound).
func (s *Server) registryDiscoveryLoop() {
	// Wait until we have a bound address
	<-s.readyCh

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Run immediately, then on tick
	s.registryDiscover()
	for {
		select {
		case <-ticker.C:
			s.registryDiscover()
		case <-s.done:
			return
		}
	}
}

func (s *Server) registryDiscover() {
	s.mu.RLock()
	regAddr := s.registryAddr
	advAddr := s.advertiseAddr
	adminToken := s.registryAdminToken
	s.mu.RUnlock()
	if regAddr == "" || s.beaconID == 0 {
		return
	}
	conn, err := net.DialTimeout("tcp", regAddr, 5*time.Second)
	if err != nil {
		slog.Debug("beacon registry connect failed", "addr", regAddr, "err", err)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Registry uses 4-byte big-endian length-prefix framing
	sendMsg := func(msg map[string]interface{}) error {
		body, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err = conn.Write(body)
		return err
	}
	recvMsg := func() (map[string]interface{}, error) {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length > 1<<20 {
			return nil, fmt.Errorf("message too large: %d", length)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		return resp, json.Unmarshal(body, &resp)
	}

	// Pick the address to register. Operator-supplied advertiseAddr wins
	// (MIG deployments need this — see SetAdvertiseAddr). Otherwise
	// auto-detect from the TCP local addr, which on a single-node deploy
	// is the right answer but on a VPC-internal beacon yields a private
	// 10.x address that external daemons cannot reach.
	var myAddr string
	if advAddr != "" {
		myAddr = advAddr
	} else {
		listenAddr := s.conn.LocalAddr().String()
		host, port, _ := net.SplitHostPort(listenAddr)
		if host == "::" || host == "0.0.0.0" || host == "" {
			if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
				host = tcpAddr.IP.String()
			}
		}
		myAddr = net.JoinHostPort(host, port)
	}

	regMsg := map[string]interface{}{
		"type":      "beacon_register",
		"beacon_id": s.beaconID,
		"addr":      myAddr,
	}
	if adminToken != "" {
		regMsg["admin_token"] = adminToken
	}
	if err := sendMsg(regMsg); err != nil {
		slog.Debug("beacon register send failed", "err", err)
		return
	}

	if _, err := recvMsg(); err != nil {
		slog.Debug("beacon register response failed", "err", err)
		return
	}

	// List all beacons
	if err := sendMsg(map[string]interface{}{
		"type": "beacon_list",
	}); err != nil {
		slog.Debug("beacon list send failed", "err", err)
		return
	}

	listResp, err := recvMsg()
	if err != nil {
		slog.Debug("beacon list response failed", "err", err)
		return
	}

	beacons, _ := listResp["beacons"].([]interface{})
	var newPeers []*net.UDPAddr
	for _, b := range beacons {
		bm, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		bid := uint32(0)
		if v, ok := bm["id"].(float64); ok {
			bid = uint32(v)
		}
		baddr, _ := bm["addr"].(string)
		if bid == s.beaconID || baddr == "" {
			continue // skip self
		}
		udpAddr, err := net.ResolveUDPAddr("udp", baddr)
		if err != nil {
			slog.Debug("beacon peer resolve failed", "addr", baddr, "err", err)
			continue
		}
		newPeers = append(newPeers, udpAddr)
	}

	// Update peers atomically
	s.peerMu.Lock()
	s.peers = newPeers
	s.peerMu.Unlock()

	slog.Info("beacon registry discovery", "beacon_id", s.beaconID, "my_addr", myAddr, "peers", len(newPeers))
}

// --- Health ---

// ServeHealth starts a simple HTTP server with a /healthz endpoint for load balancer health checks.
func (s *Server) ServeHealth(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.healthOk.Load() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "unhealthy")
		}
	})
	slog.Info("health endpoint listening", "addr", addr)
	return http.ListenAndServe(addr, mux)
}

// SetHealthy sets the health status (for graceful drain on scale-down).
func (s *Server) SetHealthy(ok bool) {
	s.healthOk.Store(ok)
}

// PeerNodeCount returns the number of nodes known via gossip from peer beacons.
func (s *Server) PeerNodeCount() int {
	return len(*s.peerNodes.Load())
}

// LocalNodeCount returns the number of locally registered nodes.
func (s *Server) LocalNodeCount() int {
	return s.nodes.Len()
}
