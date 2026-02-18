package daemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

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
	PeerRecvWin   int                    // peer's advertised receive window (0 = unknown/unlimited)
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
	// Close
	CloseOnce  sync.Once // ensures RecvBuf is closed exactly once
	RecvClosed bool      // true after RecvBuf is closed (guarded by RecvMu)
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
		close(ln.AcceptCh)
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

func (pm *PortManager) AllocEphemeralPort() uint16 {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	start := pm.nextEphPort
	for {
		port := pm.nextEphPort
		pm.nextEphPort++
		if pm.nextEphPort > protocol.PortEphemeralMax {
			pm.nextEphPort = protocol.PortEphemeralMin
		}
		if !pm.portInUse(port) {
			return port
		}
		if pm.nextEphPort == start {
			return port // full wrap, return anyway (16384 ports)
		}
	}
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
	}
	pm.nextConnID++
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
	for _, c := range pm.connections {
		if c.LocalPort == localPort && c.RemoteAddr == remoteAddr && c.RemotePort == remotePort {
			return c
		}
	}
	return nil
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
		case StateClosed, StateFinWait, StateCloseWait:
			stale = append(stale, c)
		case StateTimeWait:
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

// BytesInFlight returns total unacknowledged bytes.
func (c *Connection) BytesInFlight() int {
	total := 0
	for _, e := range c.Unacked {
		total += len(e.data)
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
	if c.PeerRecvWin > 0 && c.PeerRecvWin < win {
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
func (c *Connection) ProcessAck(ack uint32, pureACK bool) {
	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()

	if seqAfter(c.LastAck, ack) {
		return // ack is behind LastAck (wrapping-safe)
	}

	if ack == c.LastAck {
		if !pureACK {
			return // data packets don't count as dup ACKs
		}
		// Duplicate ACK (pure ACK only)
		c.DupAckCount++
		c.Mu.Lock()
		c.Stats.DupACKs++
		c.Mu.Unlock()
		if c.DupAckCount == 3 {
			// Fast retransmit (RFC 5681)
			c.fastRetransmit()
			c.Mu.Lock()
			c.Stats.FastRetx++
			c.Mu.Unlock()
			// Multiplicative decrease
			c.SSThresh = c.CongWin / 2
			if c.SSThresh < MaxSegmentSize {
				c.SSThresh = MaxSegmentSize
			}
			c.CongWin = c.SSThresh + 3*MaxSegmentSize
		} else if c.DupAckCount > 3 {
			// Inflate window for each additional dup ACK
			c.CongWin += MaxSegmentSize
			if c.CongWin > MaxCongWin {
				c.CongWin = MaxCongWin
			}
		}
		return
	}

	// New ACK — advance
	bytesAcked := int(ack - c.LastAck)
	c.LastAck = ack
	c.DupAckCount = 0
	c.LastRetxTime = time.Time{} // reset retransmit guard so ACK-driven recovery can proceed

	// Exit timeout recovery when all loss-window data is acked
	if c.InRecovery && seqAfterOrEqual(ack, c.RecoveryPoint) {
		c.InRecovery = false
	}

	// Remove acked entries and update RTT from the first one
	var remaining []*retxEntry
	for _, e := range c.Unacked {
		endSeq := e.seq + uint32(len(e.data))
		if seqAfterOrEqual(ack, endSeq) {
			// This segment is fully acked — update RTT if first attempt and not SACKed
			if e.attempts == 1 && !e.sacked {
				rtt := time.Since(e.sentAt)
				c.updateRTT(rtt)
			}
		} else {
			// Reset sacked flag for segments that are still unacked
			// (SACK state is refreshed with each incoming ACK)
			e.sacked = false
			remaining = append(remaining, e)
		}
	}
	c.Unacked = remaining

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

	// Signal Nagle flush if all data acknowledged
	if len(c.Unacked) == 0 && c.NagleCh != nil {
		select {
		case c.NagleCh <- struct{}{}:
		default:
		}
	}
}

// fastRetransmit resends the first unacked-and-not-SACKed segment immediately.
// Must be called with RetxMu held.
func (c *Connection) fastRetransmit() {
	if len(c.Unacked) == 0 || c.RetxSend == nil {
		return
	}
	// Read RecvAck under Mu (L1 fix — RecvAck is protected by Mu, not RetxMu)
	c.Mu.Lock()
	recvAck := c.RecvAck
	c.Mu.Unlock()

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
// To avoid deadlocking routeLoop (C1 fix), segments are collected under
// RecvMu and delivered to RecvBuf after releasing the lock.
func (c *Connection) DeliverInOrder(seq uint32, data []byte) uint32 {
	c.RecvMu.Lock()

	if c.RecvClosed {
		expectedSeq := c.ExpectedSeq
		c.RecvMu.Unlock()
		return expectedSeq
	}

	var toDeliver [][]byte

	if seq == c.ExpectedSeq {
		// In order — collect for delivery
		toDeliver = append(toDeliver, data)
		c.ExpectedSeq = seq + uint32(len(data))

		// Drain any buffered segments that are now in order
		for {
			found := false
			for i, seg := range c.OOOBuf {
				if seg.seq == c.ExpectedSeq {
					toDeliver = append(toDeliver, seg.data)
					c.ExpectedSeq = seg.seq + uint32(len(seg.data))
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

	expectedSeq := c.ExpectedSeq
	c.RecvMu.Unlock()

	// Deliver outside the lock to prevent deadlocking routeLoop when
	// RecvBuf is full (C1 fix). The send can still block for backpressure
	// but won't hold RecvMu, so CloseRecvBuf can proceed.
	for _, d := range toDeliver {
		func() {
			defer func() { recover() }() // handle closed RecvBuf
			c.RecvBuf <- d
		}()
	}

	return expectedSeq
}

// CloseRecvBuf safely closes RecvBuf exactly once. Both the flag set and
// channel close happen under RecvMu so DeliverInOrder can never send to a
// closed channel.
func (c *Connection) CloseRecvBuf() {
	c.CloseOnce.Do(func() {
		c.RecvMu.Lock()
		c.RecvClosed = true
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
		if seg.seq <= cur.Right {
			// Contiguous or overlapping — extend
			if segEnd > cur.Right {
				cur.Right = segEnd
			}
		} else {
			// Gap — emit current block, start new one
			blocks = append(blocks, cur)
			cur = SACKBlock{Left: seg.seq, Right: segEnd}
		}
	}
	blocks = append(blocks, cur)

	// Limit to 4 blocks (most recent/important first is fine since they're sorted by seq)
	if len(blocks) > 4 {
		blocks = blocks[:4]
	}
	return blocks
}

// ProcessSACK marks unacked segments that are covered by SACK blocks.
// This prevents unnecessary retransmission of segments the peer already has.
func (c *Connection) ProcessSACK(blocks []SACKBlock) {
	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()

	c.Mu.Lock()
	c.Stats.SACKRecv += uint64(len(blocks))
	c.Mu.Unlock()

	for _, e := range c.Unacked {
		segEnd := e.seq + uint32(len(e.data))
		for _, b := range blocks {
			if e.seq >= b.Left && segEnd <= b.Right {
				e.sacked = true
				break
			}
		}
	}
}
