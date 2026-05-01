// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ErrEphemeralExhausted is returned by callers of AllocEphemeralPort when
// all 16384 ephemeral ports (49152..65535) are simultaneously in use.
var ErrEphemeralExhausted = errors.New("ephemeral ports exhausted")

// SACKBlock represents a contiguous range of received bytes.
// Left is the seq of the first byte; Right is the seq of the first byte AFTER the range.
type SACKBlock struct {
	Left  uint32
	Right uint32
}

// sackMagic identifies SACK data in ACK payloads.
var sackMagic = []byte("SACK")

// EncodeSACK encodes SACK blocks into a byte slice.
// Format: "SACK" (4 bytes) + count (1 byte) + N * 8 bytes (Left:4, Right:4).
func EncodeSACK(blocks []SACKBlock) []byte {
	if len(blocks) == 0 {
		return nil
	}
	n := len(blocks)
	if n > 4 {
		n = 4 // max 4 SACK blocks (same as TCP)
	}
	buf := make([]byte, 5+n*8)
	copy(buf[0:4], sackMagic)
	buf[4] = byte(n)
	for i := 0; i < n; i++ {
		off := 5 + i*8
		binary.BigEndian.PutUint32(buf[off:off+4], blocks[i].Left)
		binary.BigEndian.PutUint32(buf[off+4:off+8], blocks[i].Right)
	}
	return buf
}

// DecodeSACK parses SACK blocks from an ACK payload.
// Returns nil, false if the payload is not SACK data.
func DecodeSACK(data []byte) ([]SACKBlock, bool) {
	if len(data) < 5 || !bytes.Equal(data[0:4], sackMagic) {
		return nil, false
	}
	n := int(data[4])
	if n == 0 || n > 4 || len(data) < 5+n*8 {
		return nil, false
	}
	blocks := make([]SACKBlock, n)
	for i := 0; i < n; i++ {
		off := 5 + i*8
		blocks[i] = SACKBlock{
			Left:  binary.BigEndian.Uint32(data[off : off+4]),
			Right: binary.BigEndian.Uint32(data[off+4 : off+8]),
		}
	}
	return blocks, true
}

// MaxConnectionsPerPort and MaxTotalConnections defaults are defined in daemon.go Config.
// The daemon passes resolved values when checking limits.

// PortManager handles virtual port binding and connection tracking.
type PortManager struct {
	mu          sync.RWMutex
	listeners   map[uint16]*Listener
	connections map[uint32]*Connection // conn_id → connection
	nextConnID  uint32
	nextEphPort uint16
}

type Listener struct {
	Port     uint16
	AcceptCh chan *Connection
	mu       sync.Mutex
	closed   bool
}

// TrySend attempts a non-blocking push of conn to AcceptCh.
// Returns true if the connection was queued, false if the queue was full or
// the listener has been closed (via Unbind). Safe to call after Unbind —
// never panics even if AcceptCh is already closed.
//
// v1.9.1 fix: the closed flag is checked under mu before the channel send,
// eliminating the window where Unbind()'s close(AcceptCh) races with
// handleStreamPacket's send. Without this guard, a concurrent Unbind could
// close AcceptCh between GetListener's return and the send, causing a
// "send on closed channel" panic that killed routeLoop.
func (ln *Listener) TrySend(conn *Connection) bool {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.closed {
		return false
	}
	select {
	case ln.AcceptCh <- conn:
		return true
	default:
		return false
	}
}

// close marks the listener as closed and drains + closes AcceptCh.
// Called by Unbind under pm.mu to ensure Listener.TrySend sees the closed
// flag atomically — no send can slip between closed=true and close(AcceptCh).
func (ln *Listener) close() {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.closed {
		ln.closed = true
		close(ln.AcceptCh)
	}
}

// retxEntry is a sent-but-unacknowledged data segment.
type retxEntry struct {
	data     []byte
	seq      uint32
	sentAt   time.Time
	attempts int
	sacked   bool // true if covered by a SACK block (don't retransmit)
}

// recvSegment is an out-of-order received segment waiting for reassembly.
type recvSegment struct {
	seq  uint32
	data []byte
}

// Default window parameters
const (
	InitialCongWin = 10 * MaxSegmentSize          // 40 KB initial congestion window (IW10, RFC 6928)
	MaxCongWin     = 1024 * 1024                  // 1 MB max congestion window
	MaxSegmentSize = 4096                         // MTU for virtual segments
	RecvBufSize    = 512                          // receive buffer channel capacity (segments)
	MaxRecvWin     = RecvBufSize * MaxSegmentSize // 2 MB max receive window
	MaxOOOBuf      = 128                          // max out-of-order segments buffered per connection
	AcceptQueueLen = 64                           // listener accept channel capacity
	SendBufLen     = 256                          // send buffer channel capacity (segments)

	// MaxNagleBuf caps the per-connection NagleBuf at 8 segments
	// (32 KB). v1.9.1 fix: SendData previously appended without bound,
	// so an application writing faster than the network could drain
	// (slow peer, full cwnd, packet loss) leaked memory linearly with
	// offered-but-undeliverable load. With many connections in that
	// state, daemon RSS climbed until OOM. SendData now returns
	// ErrSendBufFull when len(NagleBuf) + len(write) would exceed
	// this cap; callers must retry with backpressure.
	MaxNagleBuf = 8 * MaxSegmentSize
)

// RTO parameters (RFC 6298)
const (
	ClockGranularity = 10 * time.Millisecond  // minimum RTTVAR for RTO calculation
	RTOMin           = 200 * time.Millisecond // minimum retransmission timeout
	RTOMax           = 10 * time.Second       // maximum retransmission timeout
	InitialRTO       = 1 * time.Second        // initial retransmission timeout
)

type Connection struct {
	Mu           sync.Mutex // protects State, SendSeq, RecvAck, LastActivity, Stats
	ID           uint32
	LocalAddr    protocol.Addr // our virtual address
	LocalPort    uint16
	RemoteAddr   protocol.Addr
	RemotePort   uint16
	State        ConnState
	LastActivity time.Time // updated on send/recv
	// Reliable delivery
	SendSeq uint32
	RecvAck uint32
	// SynAckSeq: sequence number used on the original outbound SYN-ACK.
	// P1-001 fix: retransmitted SYNs must receive the same seq, not a
	// stale `SendSeq-1` that has drifted forward once data flowed.
	SynAckSeq    uint32
	SynAckSeqSet bool
	SendBuf chan []byte
	RecvBuf chan []byte
	// Sliding window + retransmission (send side)
	RetxMu        sync.Mutex
	Unacked       []*retxEntry           // ordered by seq
	LastAck       uint32                 // highest cumulative ACK received
	DupAckCount   int                    // consecutive duplicate ACKs
	RTO           time.Duration          // retransmission timeout
	SRTT          time.Duration          // smoothed RTT
	RTTVAR        time.Duration          // RTT variance (RFC 6298)
	CongWin       int                    // congestion window in bytes
	SSThresh      int                    // slow-start threshold
	InRecovery    bool                   // true during timeout loss recovery
	RecoveryPoint uint32                 // highest seq sent when entering recovery
	RetxStop      chan struct{}          // closed to stop retx goroutine
	RetxSend      func(*protocol.Packet) // callback to send retransmitted packets
	WindowCh      chan struct{}          // signaled when window opens up
	PeerRecvWin   int                    // peer's advertised receive window (-1 = not yet received, 0 = explicit zero-window)
	// Nagle algorithm (write coalescing)
	NagleBuf []byte        // pending small write data
	NagleMu  sync.Mutex    // protects NagleBuf
	NagleCh  chan struct{} // signaled when Nagle should flush
	NoDelay  bool          // if true, disable Nagle (send immediately)
	// Receive window (reassembly)
	RecvMu      sync.Mutex
	ExpectedSeq uint32         // next in-order seq expected
	OOOBuf      []*recvSegment // out-of-order buffer
	// Delayed ACK
	AckMu       sync.Mutex  // protects PendingACKs and ACKTimer
	PendingACKs int         // count of unacked received segments
	ACKTimer    *time.Timer // delayed ACK timer
	// Keepalive dead-peer detection
	KeepaliveUnacked int // consecutive unanswered keepalive probes
	// Close
	CloseOnce  sync.Once // ensures RecvBuf is closed exactly once
	RecvClosed bool      // true after RecvBuf is closed (guarded by RecvMu)
	// recvSenders tracks in-flight Phase 2 senders into RecvBuf so CloseRecvBuf
	// can wait for them to drain before close()ing the channel. Without this,
	// `chansend1` and the close() race per the runtime data-race detector even
	// though Go's runtime makes it well-defined (close-then-send panics, the
	// Phase 2 defer recover()s — but the race detector still flags the
	// concurrent close-vs-send on the channel's internal state).
	recvSenders sync.WaitGroup
	// Retransmit state
	LastRetxTime time.Time // when last RTO retransmission fired (prevents cascading)
	// Per-connection statistics
	Stats ConnStats
}

// ConnStats tracks per-connection traffic and reliability metrics.
type ConnStats struct {
	BytesSent   uint64 // total user bytes sent
	BytesRecv   uint64 // total user bytes received
	SegsSent    uint64 // data segments sent
	SegsRecv    uint64 // data segments received
	Retransmits uint64 // timeout-based retransmissions
	FastRetx    uint64 // fast retransmissions (3 dup ACKs)
	SACKRecv    uint64 // SACK blocks received from peer
	SACKSent    uint64 // SACK blocks sent to peer
	DupACKs     uint64 // duplicate ACKs received
}

type ConnState uint8

const (
	StateClosed ConnState = iota
	StateListen
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait
	StateCloseWait
	StateTimeWait
)

func (s ConnState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateListen:
		return "LISTEN"
	case StateSynSent:
		return "SYN_SENT"
	case StateSynReceived:
		return "SYN_RECV"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait:
		return "FIN_WAIT"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateTimeWait:
		return "TIME_WAIT"
	default:
		return "unknown"
	}
}

func NewPortManager() *PortManager {
	return &PortManager{
		listeners:   make(map[uint16]*Listener),
		connections: make(map[uint32]*Connection),
		nextConnID:  1,
		nextEphPort: protocol.PortEphemeralMin,
	}
}

func (pm *PortManager) Bind(port uint16) (*Listener, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.listeners[port]; exists {
		return nil, fmt.Errorf("port %d already bound", port)
	}

	ln := &Listener{
		Port:     port,
		AcceptCh: make(chan *Connection, AcceptQueueLen),
	}
	pm.listeners[port] = ln
	return ln, nil
}

func (pm *PortManager) Unbind(port uint16) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if ln, ok := pm.listeners[port]; ok {
		ln.close() // sets closed=true + close(AcceptCh) under ln.mu
		delete(pm.listeners, port)
	}
}

func (pm *PortManager) GetListener(port uint16) *Listener {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.listeners[port]
}

// ConnectionCountForPort returns the number of active connections on a port.
func (pm *PortManager) ConnectionCountForPort(port uint16) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	count := 0
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if c.LocalPort == port && st != StateClosed && st != StateTimeWait {
			count++
		}
	}
	return count
}

// TotalActiveConnections returns the total number of non-closed connections.
func (pm *PortManager) TotalActiveConnections() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	count := 0
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if st != StateClosed && st != StateTimeWait {
			count++
		}
	}
	return count
}

// AllocEphemeralPort returns an unused ephemeral port in [PortEphemeralMin,
// PortEphemeralMax], or 0 when all 16384 ports are simultaneously in use.
// Callers must treat 0 as ErrEphemeralExhausted.
//
// v1.9.1 fix: the previous implementation incremented nextEphPort as uint16
// and checked `> PortEphemeralMax` afterward. When nextEphPort was 65535,
// uint16++ silently wrapped to 0 before the check fired, so the loop would
// escape the ephemeral range and return port 0 via `portInUse(0) == false`.
// The fix uses a bounded int counter and checks >= PortEphemeralMax BEFORE
// the increment so the uint16 field never reaches 0 via overflow.
func (pm *PortManager) AllocEphemeralPort() uint16 {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	total := int(protocol.PortEphemeralMax-protocol.PortEphemeralMin) + 1
	for i := 0; i < total; i++ {
		port := pm.nextEphPort
		if pm.nextEphPort >= protocol.PortEphemeralMax {
			pm.nextEphPort = protocol.PortEphemeralMin
		} else {
			pm.nextEphPort++
		}
		if !pm.portInUse(port) {
			return port
		}
	}
	return 0 // exhausted; callers must check and return ErrEphemeralExhausted
}

// portInUse returns true if any active connection is using the given local port.
// Must be called with pm.mu held.
func (pm *PortManager) portInUse(port uint16) bool {
	for _, c := range pm.connections {
		if c.LocalPort == port {
			c.Mu.Lock()
			st := c.State
			c.Mu.Unlock()
			if st != StateClosed && st != StateTimeWait {
				return true
			}
		}
	}
	return false
}

func (pm *PortManager) NewConnection(localPort uint16, remoteAddr protocol.Addr, remotePort uint16) *Connection {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	conn := &Connection{
		ID:           pm.nextConnID,
		LocalPort:    localPort,
		RemoteAddr:   remoteAddr,
		RemotePort:   remotePort,
		State:        StateClosed,
		LastActivity: time.Now(),
		SendBuf:      make(chan []byte, SendBufLen),
		RecvBuf:      make(chan []byte, RecvBufSize),
		CongWin:      InitialCongWin,
		SSThresh:     MaxCongWin / 2,
		WindowCh:     make(chan struct{}, 1),
		NagleCh:      make(chan struct{}, 1),
		PeerRecvWin:  -1, // sentinel: no window advertisement received yet
	}
	pm.nextConnID++
	if pm.nextConnID == 0 {
		pm.nextConnID = 1 // wrap around, skip 0 (reserved)
	}
	pm.connections[conn.ID] = conn
	return conn
}

func (pm *PortManager) GetConnection(id uint32) *Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.connections[id]
}

func (pm *PortManager) FindConnection(localPort uint16, remoteAddr protocol.Addr, remotePort uint16) *Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	// v1.9.1: prefer active (non-TIME_WAIT, non-CLOSED) connections when
	// multiple share the same 4-tuple (possible after port reuse on a
	// TIME_WAIT entry). Without this preference, Go's randomised map
	// iteration returned stale TIME_WAIT entries ~50% of the time, causing
	// data packets to be silently discarded by the "established" state guard.
	var fallback *Connection
	for _, c := range pm.connections {
		if c.LocalPort == localPort && c.RemoteAddr == remoteAddr && c.RemotePort == remotePort {
			c.Mu.Lock()
			st := c.State
			c.Mu.Unlock()
			if st != StateTimeWait && st != StateClosed {
				return c // active connection — always prefer over stale entries
			}
			fallback = c // stale; return only when no active match exists
		}
	}
	return fallback
}

// ConnectionInfo describes an active connection for diagnostics.
type ConnectionInfo struct {
	ID          uint32
	LocalPort   uint16
	RemoteAddr  string
	RemotePort  uint16
	State       string
	SendSeq     uint32
	RecvAck     uint32
	CongWin     int
	SSThresh    int
	InFlight    int
	SRTT        time.Duration
	RTTVAR      time.Duration
	Unacked     int
	OOOBuf      int
	PeerRecvWin int
	RecvWin     int
	InRecovery  bool
	Stats       ConnStats
}

// ConnectionList returns info about all active connections.
func (pm *PortManager) ConnectionList() []ConnectionInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var list []ConnectionInfo
	for _, c := range pm.connections {
		c.RetxMu.Lock()
		inFlight := c.BytesInFlight()
		unacked := len(c.Unacked)
		congWin := c.CongWin
		ssthresh := c.SSThresh
		srtt := c.SRTT
		rttvar := c.RTTVAR
		peerWin := c.PeerRecvWin
		inRecovery := c.InRecovery
		c.RetxMu.Unlock()
		recvWin := int(c.RecvWindow()) * MaxSegmentSize

		c.RecvMu.Lock()
		ooo := len(c.OOOBuf)
		c.RecvMu.Unlock()

		c.Mu.Lock()
		st := c.State
		sendSeq := c.SendSeq
		recvAck := c.RecvAck
		stats := c.Stats
		c.Mu.Unlock()

		list = append(list, ConnectionInfo{
			ID:          c.ID,
			LocalPort:   c.LocalPort,
			RemoteAddr:  c.RemoteAddr.String(),
			RemotePort:  c.RemotePort,
			State:       st.String(),
			SendSeq:     sendSeq,
			RecvAck:     recvAck,
			CongWin:     congWin,
			SSThresh:    ssthresh,
			InFlight:    inFlight,
			SRTT:        srtt,
			RTTVAR:      rttvar,
			Unacked:     unacked,
			OOOBuf:      ooo,
			PeerRecvWin: peerWin,
			RecvWin:     recvWin,
			InRecovery:  inRecovery,
			Stats:       stats,
		})
	}
	return list
}

// StaleConnections returns connections in a terminal state that should be cleaned up.
// CLOSED, FIN_WAIT, CLOSE_WAIT are cleaned up immediately.
// TIME_WAIT connections are cleaned up after timeWaitDur.
func (pm *PortManager) StaleConnections(timeWaitDur time.Duration) []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	now := time.Now()
	var stale []*Connection
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		la := c.LastActivity
		c.Mu.Unlock()
		switch st {
		case StateClosed, StateCloseWait:
			stale = append(stale, c)
		case StateFinWait, StateTimeWait:
			if now.Sub(la) > timeWaitDur {
				stale = append(stale, c)
			}
		}
	}
	return stale
}

// IdleConnections returns connections that have been idle longer than the given duration.
func (pm *PortManager) IdleConnections(maxIdle time.Duration) []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	now := time.Now()
	var idle []*Connection
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		la := c.LastActivity
		c.Mu.Unlock()
		if st == StateEstablished && now.Sub(la) > maxIdle {
			idle = append(idle, c)
		}
	}
	return idle
}

// AllConnections returns all active connections.
func (pm *PortManager) AllConnections() []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	conns := make([]*Connection, 0, len(pm.connections))
	for _, c := range pm.connections {
		conns = append(conns, c)
	}
	return conns
}

func (pm *PortManager) RemoveConnection(id uint32) {
	pm.mu.Lock()
	c := pm.connections[id]
	delete(pm.connections, id)
	pm.mu.Unlock()
	// Stop retransmission goroutine
	if c != nil && c.RetxStop != nil {
		select {
		case <-c.RetxStop:
		default:
			close(c.RetxStop)
		}
	}
}

// BytesInFlight returns total unacknowledged bytes, excluding SACKed segments.
// SACKed segments remain in c.Unacked until a cumulative ACK removes them, but
// they are already at the peer so they must not consume congestion-window space.
func (c *Connection) BytesInFlight() int {
	total := 0
	for _, e := range c.Unacked {
		if !e.sacked {
			total += len(e.data)
		}
	}
	return total
}

// EffectiveWindow returns the effective send window (minimum of congestion
// window and peer's advertised receive window).
// Must be called with RetxMu held.
func (c *Connection) EffectiveWindow() int {
	win := c.CongWin
	if win <= 0 {
		win = InitialCongWin
	}
	if c.PeerRecvWin >= 0 && c.PeerRecvWin < win {
		win = c.PeerRecvWin
	}
	return win
}

// WindowAvailable returns true if the effective window allows more data.
// Must be called with RetxMu held.
func (c *Connection) WindowAvailable() bool {
	return c.BytesInFlight() < c.EffectiveWindow()
}

// TrackSend adds a sent data segment to the retransmission buffer.
func (c *Connection) TrackSend(seq uint32, data []byte) {
	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()
	saved := make([]byte, len(data))
	copy(saved, data)
	c.Unacked = append(c.Unacked, &retxEntry{
		data:     saved,
		seq:      seq,
		sentAt:   time.Now(),
		attempts: 1,
	})
}

// ProcessAck removes segments acknowledged by the given ack number,
// updates RTT estimate, detects duplicate ACKs for fast retransmit,
// and grows the congestion window.
// If pureACK is true, duplicate ACK detection is enabled. Data packets
// with piggybacked ACKs should pass pureACK=false to avoid false
// fast retransmits (RFC 5681 Section 3.2).
//
// Lock-order note: Stats fields are guarded by Mu, but the rest of this
// function's state (Unacked, RTT, CongWin, etc.) is guarded by RetxMu.
// To avoid an Mu↔RetxMu inversion (a concurrent Stats() reader holds Mu
// then needs RetxMu, while we hold RetxMu and need Mu), we accumulate
// stats deltas locally and apply them under Mu AFTER RetxMu is released.
func (c *Connection) ProcessAck(ack uint32, pureACK bool) {
	// Capture RecvAck under Mu BEFORE taking RetxMu so fastRetransmit can
	// run lock-order-safe. RecvAck only advances forward (or stays equal),
	// so a slightly stale read is safe — a fresher one would cause us to
	// retransmit data the peer would discard, harmless.
	c.Mu.Lock()
	recvAck := c.RecvAck
	c.Mu.Unlock()

	var dupAcks, fastRetx uint64
	defer func() {
		if dupAcks == 0 && fastRetx == 0 {
			return
		}
		c.Mu.Lock()
		c.Stats.DupACKs += dupAcks
		c.Stats.FastRetx += fastRetx
		c.Mu.Unlock()
	}()

	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()

	if seqAfter(c.LastAck, ack) {
		return // ack is behind LastAck (wrapping-safe)
	}

	if ack == c.LastAck {
		if !pureACK {
			return // data packets don't count as dup ACKs
		}
		// Dup-ACK counting is only meaningful when data is genuinely in flight
		// (RFC 5681 §3.2).  Use BytesInFlight() rather than len(Unacked) so
		// that all-SACKed Unacked entries (peer has them, no real loss) do not
		// count as "in flight" and trigger spurious fast retransmit with the
		// associated SSThresh halving.
		if c.BytesInFlight() == 0 {
			return
		}
		c.DupAckCount++
		dupAcks++
		if c.DupAckCount == 3 && len(c.Unacked) > 0 {
			// Fast retransmit (RFC 5681). Only when there is data in flight:
			// keepalive probes and other spurious dup-ACKs with an empty Unacked
			// must not trigger congestion reduction (FlightSize == 0).
			c.fastRetransmit(recvAck)
			fastRetx++
			// Multiplicative decrease
			c.SSThresh = c.CongWin / 2
			if c.SSThresh < MaxSegmentSize {
				c.SSThresh = MaxSegmentSize
			}
			c.CongWin = c.SSThresh + 3*MaxSegmentSize
			// For small CongWin (< 6*SMSS), SSThresh+3*MSS > old CongWin, so
			// the window may have opened.  Signal the sender so it doesn't stall.
			if c.WindowCh != nil && c.WindowAvailable() {
				select {
				case c.WindowCh <- struct{}{}:
				default:
				}
			}
		} else if c.DupAckCount > 3 && len(c.Unacked) > 0 {
			// Inflate window for each additional dup ACK (only in recovery)
			c.CongWin += MaxSegmentSize
			if c.CongWin > MaxCongWin {
				c.CongWin = MaxCongWin
			}
			// RFC 5681 §3.2 step 5: the inflation may open the window for the
			// sender. Signal WindowCh so a sendSegment blocked on a full cwnd
			// can wake up immediately rather than waiting for the probe timer
			// (ZeroWinProbeInitial = 500 ms).
			if c.WindowCh != nil && c.WindowAvailable() {
				select {
				case c.WindowCh <- struct{}{}:
				default:
				}
			}
		}
		return
	}

	// New ACK — advance
	bytesAcked := int(ack - c.LastAck)
	c.LastAck = ack
	oldDupAckCount := c.DupAckCount
	c.DupAckCount = 0
	c.LastRetxTime = time.Time{} // reset retransmit guard so ACK-driven recovery can proceed

	// Exit timeout recovery when all loss-window data is acked
	if c.InRecovery && seqAfterOrEqual(ack, c.RecoveryPoint) {
		c.InRecovery = false
	}

	// Remove acked entries and update RTT from the first once-sent segment.
	// RFC 6298 §2 requires at most one RTT sample per ACK event; taking a
	// sample per segment biases SRTT toward short-RTT late-in-batch entries
	// and inflates RTTVAR with within-batch variance that is not path-level.
	var remaining []*retxEntry
	rttUpdated := false
	for _, e := range c.Unacked {
		endSeq := e.seq + uint32(len(e.data))
		if seqAfterOrEqual(ack, endSeq) {
			// This segment is fully acked — update RTT from the first one only.
			// Karn's algorithm: skip retransmitted segments (attempts > 1).
			// SACK state is not excluded: a once-sent segment is a valid RTT
			// sample per RFC 6298 regardless of whether it was previously
			// reported via SACK (the cumulative ACK time is a conservative
			// upper bound that the EWMA smooths out).
			if e.attempts == 1 && !rttUpdated {
				rtt := time.Since(e.sentAt)
				c.updateRTT(rtt)
				rttUpdated = true
			}
		} else {
			// Retain sacked state for remaining entries (RFC 2018 §5):
			// the peer has confirmed receiving SACKed segments and a
			// partial cumulative ACK above them does not invalidate that.
			remaining = append(remaining, e)
		}
	}
	c.Unacked = remaining

	// RFC 5681 §3.2 step 6: on fast-recovery exit (first new ACK after 3+ dup
	// ACKs), deflate CongWin back to SSThresh before AIMD growth. Without this,
	// CongWin stays at the inflated fast-recovery value (SSThresh + k*MSS) and
	// grows from there — re-entering the burst that caused the loss event.
	if oldDupAckCount >= 3 {
		c.CongWin = c.SSThresh
	}

	// Congestion window growth (Appropriate Byte Counting, RFC 3465)
	// Grow based on bytes ACKed, not number of ACKs — avoids delayed ACK penalty.
	if c.CongWin < c.SSThresh {
		// Slow start: grow by acked bytes (exponential)
		c.CongWin += bytesAcked
	} else {
		// Congestion avoidance: grow by ~MSS per RTT (AIMD)
		increment := MaxSegmentSize * bytesAcked / c.CongWin
		if increment < 1 {
			increment = 1
		}
		c.CongWin += increment
	}
	if c.CongWin > MaxCongWin {
		c.CongWin = MaxCongWin
	}

	// Signal that window opened up
	if c.WindowCh != nil {
		select {
		case c.WindowCh <- struct{}{}:
		default:
		}
	}

	// Signal Nagle flush when no data is genuinely in flight.
	// Use BytesInFlight()==0 rather than len(c.Unacked)==0: after iter-49,
	// sacked entries remain in Unacked across partial ACKs, so len>0 even
	// when the peer already has every outstanding byte.
	if c.BytesInFlight() == 0 && c.NagleCh != nil {
		select {
		case c.NagleCh <- struct{}{}:
		default:
		}
	}
}

// fastRetransmit resends the first unacked-and-not-SACKed segment immediately.
// Must be called with RetxMu held. recvAck is captured by the caller BEFORE
// acquiring RetxMu, so we don't have to take Mu here (which would re-introduce
// the Mu↔RetxMu inversion that the rest of ProcessAck went out of its way
// to avoid).
func (c *Connection) fastRetransmit(recvAck uint32) {
	if len(c.Unacked) == 0 || c.RetxSend == nil {
		return
	}

	// Find the first unacked segment that hasn't been SACKed
	for _, e := range c.Unacked {
		if e.sacked {
			continue
		}
		e.attempts++
		e.sentAt = time.Now()
		pkt := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      c.LocalAddr,
			Dst:      c.RemoteAddr,
			SrcPort:  c.LocalPort,
			DstPort:  c.RemotePort,
			Seq:      e.seq,
			Ack:      recvAck,
			Window:   c.RecvWindow(),
			Payload:  e.data,
		}
		c.RetxSend(pkt)
		return
	}
}

func (c *Connection) updateRTT(rtt time.Duration) {
	if c.SRTT == 0 {
		// First measurement (RFC 6298 Section 2.2)
		c.SRTT = rtt
		c.RTTVAR = rtt / 2
	} else {
		// Subsequent measurements (RFC 6298 Section 2.3)
		// RTTVAR = (1-β)·RTTVAR + β·|SRTT - R|  where β = 1/4
		diff := c.SRTT - rtt
		if diff < 0 {
			diff = -diff
		}
		c.RTTVAR = c.RTTVAR*3/4 + diff/4
		// SRTT = (1-α)·SRTT + α·R  where α = 1/8
		c.SRTT = c.SRTT*7/8 + rtt/8
	}
	// RTO = SRTT + max(G, K·RTTVAR) where K=4, G=clock granularity
	kvar := c.RTTVAR * 4
	if kvar < ClockGranularity {
		kvar = ClockGranularity
	}
	c.RTO = c.SRTT + kvar
	// Clamp RTO
	if c.RTO < RTOMin {
		c.RTO = RTOMin
	}
	if c.RTO > RTOMax {
		c.RTO = RTOMax
	}
}

// seqAfter returns true if a is after b in the circular uint32 sequence space.
// Uses RFC 1982 serial number arithmetic: a > b iff (a - b) interpreted as
// signed int32 is positive.
func seqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// seqAfterOrEqual returns true if a >= b in circular uint32 sequence space.
func seqAfterOrEqual(a, b uint32) bool {
	return a == b || int32(a-b) > 0
}

// DeliverInOrder handles an incoming data segment, buffering out-of-order
// segments and delivering in-order data to RecvBuf. Returns the cumulative
// ACK number (next expected seq).
//
// Three-phase design to avoid both deadlock and sequence leaks:
//   Phase 1: Collect segments to deliver under RecvMu (don't advance ExpectedSeq).
//   Phase 2: Deliver outside lock (prevents routeLoop deadlock, C1 fix).
//   Phase 3: Re-acquire lock, advance ExpectedSeq only for delivered segments,
//            re-buffer undelivered OOO segments.
//
// Safe because routeLoop is single-goroutine — no concurrent DeliverInOrder
// calls for the same connection between Phase 2 and Phase 3.
func (c *Connection) DeliverInOrder(seq uint32, data []byte) uint32 {
	c.RecvMu.Lock()

	if c.RecvClosed {
		expectedSeq := c.ExpectedSeq
		c.RecvMu.Unlock()
		return expectedSeq
	}

	type pendingSeg struct {
		seq  uint32
		data []byte
		size uint32
	}
	var toDeliver []pendingSeg

	if seq == c.ExpectedSeq {
		// In order — collect for delivery (don't advance ExpectedSeq yet)
		toDeliver = append(toDeliver, pendingSeg{seq: seq, data: data, size: uint32(len(data))})
		nextSeq := seq + uint32(len(data))

		// Drain any buffered segments that would become contiguous
		for {
			found := false
			for i, seg := range c.OOOBuf {
				if seg.seq == nextSeq {
					toDeliver = append(toDeliver, pendingSeg{seq: seg.seq, data: seg.data, size: uint32(len(seg.data))})
					nextSeq = seg.seq + uint32(len(seg.data))
					c.OOOBuf = append(c.OOOBuf[:i], c.OOOBuf[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
	} else if seqAfter(seq, c.ExpectedSeq) {
		// Out of order — buffer it (avoid duplicates, enforce bound)
		if !c.hasOOOSeg(seq) && len(c.OOOBuf) < MaxOOOBuf {
			saved := make([]byte, len(data))
			copy(saved, data)
			c.OOOBuf = append(c.OOOBuf, &recvSegment{seq: seq, data: saved})
		}
	}
	// seq before ExpectedSeq means it's a duplicate — ignore

	// Hold a recvSenders slot for the entire Phase 2 so CloseRecvBuf has a
	// well-defined "no in-flight senders" point to wait on before close().
	// Take it under RecvMu so CloseRecvBuf's check-then-wait is atomic.
	c.recvSenders.Add(1)
	c.RecvMu.Unlock()

	// Phase 2: Deliver outside the lock to prevent deadlocking routeLoop
	// when RecvBuf is full (C1 fix). Stop at first failure — remaining
	// segments stay contiguous and will be re-buffered.
	delivered := 0
	for _, seg := range toDeliver {
		ok := func() bool {
			defer func() { recover() }() // handle closed RecvBuf
			select {
			case c.RecvBuf <- seg.data:
				return true
			case <-time.After(1 * time.Second):
				return false
			}
		}()
		if !ok {
			break
		}
		delivered++
	}
	c.recvSenders.Done()

	// Phase 3: Commit — advance ExpectedSeq only for successfully delivered
	// segments. Re-buffer any OOO segments that couldn't be delivered.
	c.RecvMu.Lock()
	for i, seg := range toDeliver {
		if i < delivered {
			c.ExpectedSeq = seg.seq + seg.size
		} else if i > 0 {
			// Re-buffer OOO segments we removed in Phase 1.
			// Skip index 0 (the incoming segment) — sender retransmits
			// since we won't ACK it.
			c.OOOBuf = append(c.OOOBuf, &recvSegment{seq: seg.seq, data: seg.data})
		}
	}
	expectedSeq := c.ExpectedSeq
	c.RecvMu.Unlock()

	return expectedSeq
}

// CloseRecvBuf safely closes RecvBuf exactly once. Sets RecvClosed first so
// new Phase 2 senders bail in DeliverInOrder, then waits for in-flight
// senders to drain (recvSenders WG), then closes the channel. This ordering
// keeps `go test -race` clean — concurrent close-vs-send was previously
// flagged even though the runtime made it safe via defer recover().
func (c *Connection) CloseRecvBuf() {
	c.CloseOnce.Do(func() {
		c.RecvMu.Lock()
		c.RecvClosed = true
		c.RecvMu.Unlock()
		c.recvSenders.Wait()
		c.RecvMu.Lock()
		close(c.RecvBuf)
		c.RecvMu.Unlock()
	})
}

// RecvWindow returns the number of free segments in the receive buffer,
// used as the advertised receive window.
func (c *Connection) RecvWindow() uint16 {
	free := cap(c.RecvBuf) - len(c.RecvBuf)
	if free < 0 {
		free = 0
	}
	if free > 0xFFFF {
		free = 0xFFFF
	}
	return uint16(free)
}

func (c *Connection) hasOOOSeg(seq uint32) bool {
	for _, seg := range c.OOOBuf {
		if seg.seq == seq {
			return true
		}
	}
	return false
}

// SACKBlocks returns SACK blocks describing out-of-order received segments.
// Must be called with RecvMu held.
func (c *Connection) SACKBlocks() []SACKBlock {
	if len(c.OOOBuf) == 0 {
		return nil
	}

	// Sort OOO segments by seq
	sorted := make([]*recvSegment, len(c.OOOBuf))
	copy(sorted, c.OOOBuf)
	sort.Slice(sorted, func(i, j int) bool { return seqAfter(sorted[j].seq, sorted[i].seq) })

	// Merge into contiguous blocks
	var blocks []SACKBlock
	cur := SACKBlock{Left: sorted[0].seq, Right: sorted[0].seq + uint32(len(sorted[0].data))}

	for i := 1; i < len(sorted); i++ {
		seg := sorted[i]
		segEnd := seg.seq + uint32(len(seg.data))
		if seqAfterOrEqual(cur.Right, seg.seq) {
			// Contiguous or overlapping — extend
			if seqAfter(segEnd, cur.Right) {
				cur.Right = segEnd
			}
		} else {
			// Gap — emit current block, start new one
			blocks = append(blocks, cur)
			cur = SACKBlock{Left: seg.seq, Right: segEnd}
		}
	}
	blocks = append(blocks, cur)

	// Limit to 4 blocks, keeping the 4 highest-seq blocks (RFC 2018 §4 prefers
	// most-recently-received first; highest seq approximates most recently added
	// in a seq-sorted OOO buffer).  blocks[:4] would keep the lowest 4 and silently
	// drop the highest block, causing the sender to retransmit it every RTT.
	if len(blocks) > 4 {
		blocks = blocks[len(blocks)-4:]
	}
	return blocks
}

// ProcessSACK marks unacked segments that are covered by SACK blocks.
// This prevents unnecessary retransmission of segments the peer already has.
//
// Lock-order note: see ProcessAck. Stats writes are deferred out of the
// RetxMu hold to avoid an Mu↔RetxMu inversion.
func (c *Connection) ProcessSACK(blocks []SACKBlock) {
	sackRecv := uint64(len(blocks))
	defer func() {
		if sackRecv == 0 {
			return
		}
		c.Mu.Lock()
		c.Stats.SACKRecv += sackRecv
		c.Mu.Unlock()
	}()

	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()

	for _, e := range c.Unacked {
		segEnd := e.seq + uint32(len(e.data))
		for _, b := range blocks {
			if seqAfterOrEqual(e.seq, b.Left) && seqAfterOrEqual(b.Right, segEnd) {
				e.sacked = true
				break
			}
		}
	}

	// Excluding SACKed bytes from BytesInFlight may have opened the send window.
	// Signal WindowCh so a sender blocked in sendSegment wakes immediately.
	if c.WindowCh != nil && c.WindowAvailable() {
		select {
		case c.WindowCh <- struct{}{}:
		default:
		}
	}

	// When all outstanding bytes are now sacked, BytesInFlight()==0 means the
	// peer has received everything in flight.  Signal NagleCh so a nagleFlush
	// goroutine waiting for "all data ACKed" wakes immediately instead of
	// stalling for NagleTimeout (40 ms) until the cumulative ACK arrives.
	if c.NagleCh != nil && c.BytesInFlight() == 0 {
		select {
		case c.NagleCh <- struct{}{}:
		default:
		}
	}
}
