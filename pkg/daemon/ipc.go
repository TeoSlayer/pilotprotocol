// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// IPC commands (daemon ↔ driver)
const (
	CmdBind              byte = 0x01
	CmdBindOK            byte = 0x02
	CmdDial              byte = 0x03
	CmdDialOK            byte = 0x04
	CmdAccept            byte = 0x05
	CmdSend              byte = 0x06
	CmdRecv              byte = 0x07
	CmdClose             byte = 0x08
	CmdCloseOK           byte = 0x09
	CmdError             byte = 0x0A
	CmdSendTo            byte = 0x0B
	CmdRecvFrom          byte = 0x0C
	CmdInfo              byte = 0x0D
	CmdInfoOK            byte = 0x0E
	CmdHandshake         byte = 0x0F // driver → daemon: handshake request/approve/reject
	CmdHandshakeOK       byte = 0x10
	CmdResolveHostname   byte = 0x11
	CmdResolveHostnameOK byte = 0x12
	CmdSetHostname       byte = 0x13
	CmdSetHostnameOK     byte = 0x14
	CmdSetVisibility     byte = 0x15
	CmdSetVisibilityOK   byte = 0x16
	CmdDeregister        byte = 0x17
	CmdDeregisterOK      byte = 0x18
	CmdSetTags           byte = 0x19
	CmdSetTagsOK         byte = 0x1A
	CmdSetWebhook        byte = 0x1B
	CmdSetWebhookOK      byte = 0x1C
	CmdNetwork           byte = 0x1F
	CmdNetworkOK         byte = 0x20
	CmdHealth            byte = 0x21
	CmdHealthOK          byte = 0x22
	CmdManaged           byte = 0x23
	CmdManagedOK         byte = 0x24
	CmdRotateKey         byte = 0x25
	CmdRotateKeyOK       byte = 0x26
	CmdBroadcast         byte = 0x29
	CmdBroadcastOK       byte = 0x2A
	// CmdCancel: driver → daemon, "abandon the in-flight request that
	// I sent under reqID X". The reqID embedded in the envelope header
	// IS NOT the reqID being cancelled — that's encoded in the body
	// payload as a uint64. The envelope's own reqID is the new request
	// (CmdCancel); we don't reply, so it's effectively unused on the
	// wire (typically 0 from the driver's send() path).
	//
	// Issue #99: without this, a driver that timed out on a slow
	// daemon dial left the daemon's dispatch goroutine grinding for
	// the full 14-31 s retry budget, filling the per-conn dispatch
	// semaphore under burst load (§4.8 stress).
	CmdCancel byte = 0x2B
)

// Network sub-commands (second byte of CmdNetwork payload)
const (
	SubNetworkList          byte = 0x01
	SubNetworkJoin          byte = 0x02
	SubNetworkLeave         byte = 0x03
	SubNetworkMembers       byte = 0x04
	SubNetworkInvite        byte = 0x05
	SubNetworkPollInvites   byte = 0x06
	SubNetworkRespondInvite byte = 0x07
)

// Managed sub-commands (second byte of CmdManaged payload)
const (
	SubManagedStatus     byte = 0x02
	SubManagedCycle      byte = 0x04
	SubManagedPolicy     byte = 0x05 // get/set expr policy
	SubManagedMemberTags byte = 0x06 // get/set member tags
	SubManagedReconcile  byte = 0x07 // poll registry & refresh peer set
)

// ipcConn wraps a net.Conn with an asynchronous writer goroutine that
// serializes outbound messages from a buffered channel. This decouples
// caller goroutines from the underlying socket write — under the previous
// synchronous-write design, a slow IPC client (Dashboard, webhook
// subscriber) could pin daemon goroutines for the duration of each write,
// and observed CPU profiles attributed 96.7% of mutex-wait time during
// stress to (*ipcConn).ipcWrite. See [[X-Tasks/backlog/26-ipc-write-mutex-contention]]
// and [[X-Tasks/backlog/30-mutex-risk-map]] § fix #4.
//
// Wire format (issue #99):
//
//	[uint32-len][uint8-cmd][uint64-reqID][payload...]
//
// reqID is a per-IPC-connection monotonic identifier the driver allocates
// for each request expecting a reply. The daemon echoes the same reqID
// back in the response, so the driver can demultiplex replies that may
// arrive out of submission order (concurrent dispatch — see issue #99).
// reqID==0 means "server-pushed, unsolicited" — used for cmdRecv,
// cmdAccept, cmdRecvFrom, cmdCloseOK from the recvPusher path, and the
// fan-out broadcast in DeliverDatagram. Drivers route those by cmd.
//
// Ordering: per-reqID, requests and their replies are paired (the driver
// sees its own reply). Across requests, replies may interleave with each
// other (concurrent dispatch). Server-pushed messages arrive in send
// order on the writer goroutine. Per-conn ordering for traffic on a
// single overlay connection (CmdRecv frames) is unchanged because the
// recvPusher writes them sequentially.
//
// Concurrency model:
//   - sendCh has capacity ipcSendBuffer (256). Producers (handleBind,
//     handleHealth, etc.) push to it via ipcWrite.
//   - A single writer goroutine drains sendCh in order. Per-client byte
//     ordering on the wire is preserved.
//   - ipcWrite blocks until enqueue, conn-close, or ctx-cancel. The old
//     100 ms backpressure-timeout was removed because the driver waits
//     on a per-reqID channel and a silent reply drop wedged callers
//     forever (issue #99 root cause). With concurrent daemon dispatch,
//     a stalled writeLoop now applies backpressure to the dispatch
//     goroutine pushing the reply, which is the right shape — a slow
//     IPC client throttles the rate at which its requests are answered,
//     not the rate at which other clients are answered.
//   - Close() is idempotent and races-safe; once invoked, ipcWrite returns
//     ErrIPCClosed. The writer drains queued messages best-effort before
//     the underlying net.Conn is closed.
type ipcConn struct {
	net.Conn
	rmu       sync.Mutex
	ports     []uint16 // ports bound by this client
	conns     []uint32 // connection IDs owned by this client
	sendCh    chan []byte
	done      chan struct{} // closed by Close() to signal shutdown to ipcWrite + writeLoop
	closeOnce sync.Once
	writeDone chan struct{}

	// dialCancels holds cancel funcs for in-flight DialConnection calls
	// this client started. On Close() we fire them all so the daemon's
	// dial loops bail out immediately instead of grinding to their full
	// retry budget (~14-31 s) leaving orphan SYN_SENT entries.
	//
	// v1.9.1 fix: changed from []CancelFunc to map[uint64]CancelFunc.
	// addDialCancel returns an ID; removeDialCancel(id) deletes the entry
	// in O(1) so completed dials don't accumulate dead cancel funcs.
	// A []CancelFunc that was never pruned would grow by one entry per
	// completed dial — at 1000 dials/s over 8 h that was ~2.3 GB leaked
	// per IPC connection.
	dialCancels  map[uint64]context.CancelFunc
	nextCancelID uint64
}

// ipcSendBuffer is the per-conn outbound channel capacity. 256 is large
// enough to absorb a transient burst (binds + first packet replays) while
// small enough to keep memory bounded across MaxIPCClients (1024 × 256 ×
// avg 256B/msg ≈ 64 MB worst case).
const ipcSendBuffer = 256

// ipcMaxInflightPerClient caps how many in-flight dispatch goroutines a
// single IPC client may have. Each request becomes a goroutine that
// handles the command and writes the reply (concurrent dispatch — see
// issue #99). Without a cap, a flooding client could spawn unbounded
// goroutines on the daemon. The cap is a buffered semaphore: once
// reached, the read loop blocks before reading the next request, which
// in turn applies TCP-style backpressure to the client.
//
// 1024 is large enough to absorb the §4.8 stress workload (≈700
// concurrent goroutines per IPC pipe — dial+decrypt+rekey+heartbeat)
// while still bounded. Worst-case memory at MaxIPCClients = 1024
// clients is 1024 × 1024 = ~1 M dispatch goroutines, ~8 GB of stacks
// — plenty of headroom for the typical 1-3 IPC clients a daemon sees.
const ipcMaxInflightPerClient = 1024

// ErrIPCClosed is returned when ipcWrite is called after Close.
var ErrIPCClosed = errors.New("ipc: connection closed")

// ErrIPCBackpressure is retained for historical compatibility with tests
// that import it. Post-issue-#99, ipcWrite no longer returns this — it
// blocks until enqueue or close. The constant is unused in production
// code paths.
var ErrIPCBackpressure = errors.New("ipc: backpressure (client too slow)")

// IPCEnvelopeHeaderSize is the size of the per-message header that sits
// inside the ipcutil length-framed envelope: 1 byte cmd.
const IPCEnvelopeHeaderSize = 1

// MaxIPCClients caps the total number of concurrent IPC socket
// connections to the daemon (P2-002). Without this cap a misbehaving or
// malicious local client could exhaust the daemon's FD table by opening
// thousands of IPC sockets, breaking the dashboard, webhooks, and
// tunnel manager.
const MaxIPCClients = 1024

// MaxConnsPerIPCClient caps how many overlay connections a single IPC
// client may own at once. P2-002: without this, a rogue or buggy client
// could exhaust the 65536-slot connection table and DoS the daemon.
const MaxConnsPerIPCClient = 4096

// newIPCConn wraps a net.Conn and starts the per-conn writer goroutine.
// All callers must use this constructor (not &ipcConn{...}) so the writer
// is properly initialized.
func newIPCConn(c net.Conn) *ipcConn {
	ic := &ipcConn{
		Conn:        c,
		sendCh:      make(chan []byte, ipcSendBuffer),
		done:        make(chan struct{}),
		writeDone:   make(chan struct{}),
		dialCancels: make(map[uint64]context.CancelFunc),
	}
	go ic.writeLoop()
	return ic
}

// writeLoop is the sole writer to c.Conn. It exits when c.done is closed
// (clean shutdown) or when ipcutil.Write fails (broken socket).
//
// We never close sendCh — concurrent ipcWrite calls would race with the
// close per Go's channel semantics (and the race detector flags it). The
// done-channel pattern lets multiple producers coordinate with a single
// closer without sharing a "send vs. close" race surface.
func (c *ipcConn) writeLoop() {
	defer close(c.writeDone)
	for {
		select {
		case msg := <-c.sendCh:
			if err := ipcutil.Write(c.Conn, msg); err != nil {
				c.Conn.Close()
				return
			}
		case <-c.done:
			// Best-effort drain of pending messages so callers that already
			// pushed before Close() don't lose their data.
			for {
				select {
				case msg := <-c.sendCh:
					if err := ipcutil.Write(c.Conn, msg); err != nil {
						c.Conn.Close()
						return
					}
				default:
					c.Conn.Close()
					return
				}
			}
		}
	}
}

// ipcWrite queues a message for asynchronous writing. Returns:
//   - nil on successful enqueue (write may still happen later)
//   - ErrIPCClosed if the conn has been Close()d (or is being closed)
//
// Per issue #99, ipcWrite blocks until enqueue or close — there is no
// 100 ms backpressure timeout anymore. Silent reply drops were the root
// cause of the §4.8 stress drain failure: the driver waits on a per-reqID
// channel and a dropped reply hung the waiter forever. Concurrent
// dispatch on the daemon side (handleClient spawns a goroutine per
// request) means a stalled writeLoop applies backpressure only to the
// dispatcher pushing its reply, not to other in-flight requests.
func (c *ipcConn) ipcWrite(data []byte) error {
	// Fast-fail if already closed — avoids the channel-send dance below.
	select {
	case <-c.done:
		return ErrIPCClosed
	default:
	}
	// Fast path: try non-blocking enqueue.
	select {
	case c.sendCh <- data:
		return nil
	case <-c.done:
		return ErrIPCClosed
	default:
	}
	// Slow path: block until the buffer drains, the conn closes, or
	// the writeLoop exits (broken socket).
	select {
	case c.sendCh <- data:
		return nil
	case <-c.done:
		return ErrIPCClosed
	case <-c.writeDone:
		return ErrIPCClosed
	}
}

// writeReply builds an envelope `[cmd][payload...]` and queues it for
// write. The reqID parameter is kept in handler signatures for potential
// future use but is not transmitted on the wire.
func (c *ipcConn) writeReply(cmd byte, _ uint64, payload []byte) error {
	buf := make([]byte, 1+len(payload))
	buf[0] = cmd
	copy(buf[1:], payload)
	return c.ipcWrite(buf)
}

// writePush builds an envelope `[cmd][payload...]` for an unsolicited
// server → client message (CmdRecv, CmdAccept, CmdRecvFrom, broadcast).
func (c *ipcConn) writePush(cmd byte, payload []byte) error {
	buf := make([]byte, 1+len(payload))
	buf[0] = cmd
	copy(buf[1:], payload)
	return c.ipcWrite(buf)
}

// Close is idempotent. It signals the writer goroutine to drain and exit,
// at which point the underlying net.Conn is closed. Subsequent ipcWrite
// calls return ErrIPCClosed.
func (c *ipcConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		// Cancel any in-flight dials this client started so the daemon
		// doesn't keep grinding through retry budgets after the caller
		// has already disconnected. Each cancel removes its connection
		// from the daemon's conn table within milliseconds.
		c.rmu.Lock()
		cancels := c.dialCancels
		c.dialCancels = make(map[uint64]context.CancelFunc)
		c.rmu.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
	})
	return nil
}

// addDialCancel registers a context.CancelFunc for an in-flight dial.
// Returns an opaque ID that the caller passes to removeDialCancel when
// the dial completes, keeping dialCancels bounded to in-flight dials only.
func (c *ipcConn) addDialCancel(cancel context.CancelFunc) uint64 {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.nextCancelID++
	id := c.nextCancelID
	c.dialCancels[id] = cancel
	return id
}

// removeDialCancel removes the cancel registered under id. Called after
// a dial completes (success or error) to prevent dead cancel funcs from
// accumulating in the map for the lifetime of the IPC connection.
func (c *ipcConn) removeDialCancel(id uint64) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	delete(c.dialCancels, id)
}

// dialCancelCount returns the number of in-flight dial cancel funcs (for testing).
func (c *ipcConn) dialCancelCount() int {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return len(c.dialCancels)
}

func (c *ipcConn) trackPort(port uint16) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.ports = append(c.ports, port)
}

func (c *ipcConn) trackConn(connID uint32) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.conns = append(c.conns, connID)
}

// removeConn removes a connection ID from the tracked set when the connection
// is closed (either via explicit CmdClose or remote-FIN path). Without this,
// connCount() would grow without bound, exhausting the per-client quota after
// MaxConnsPerIPCClient dial+close cycles even with zero active connections.
func (c *ipcConn) removeConn(connID uint32) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for i, id := range c.conns {
		if id == connID {
			c.conns = append(c.conns[:i], c.conns[i+1:]...)
			return
		}
	}
}

// connCount returns the number of currently active connections owned by
// this client. Connections are removed from the tracked set when closed
// (removeConn), so this reflects live connections only.
func (c *ipcConn) connCount() int {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return len(c.conns)
}

// IPCServer handles connections from local drivers over Unix socket.
type IPCServer struct {
	socketPath string
	listener   net.Listener
	daemon     *Daemon
	mu         sync.Mutex
	clients    map[*ipcConn]bool
}

func NewIPCServer(socketPath string, d *Daemon) *IPCServer {
	return &IPCServer{
		socketPath: socketPath,
		daemon:     d,
		clients:    make(map[*ipcConn]bool),
	}
}

func (s *IPCServer) Start() error {
	// Remove stale socket
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", s.socketPath, err)
	}
	// Restrict socket access to owner only
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket %s: %w", s.socketPath, err)
	}
	s.listener = ln
	slog.Info("IPC listening", "socket", s.socketPath)

	go s.acceptLoop()
	return nil
}

func (s *IPCServer) Close() error {
	if s.listener != nil {
		s.listener.Close()
	}
	// Close all active client connections (L4 fix)
	s.mu.Lock()
	for conn := range s.clients {
		conn.Close()
	}
	s.mu.Unlock()
	os.Remove(s.socketPath)
	return nil
}

func (s *IPCServer) acceptLoop() {
	for {
		// P2-002: always accept then immediately reject-and-close when
		// the active client set is at the cap. Leaving accepts in the
		// listen backlog lets the kernel silently expand SOMAXCONN and
		// defeats the cap — docker typically has somaxconn=4096, so
		// relying on the backlog lets ~4k connections through. Closing
		// post-accept gives each excess client a clean EOF on read.
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		full := len(s.clients) >= MaxIPCClients
		if !full {
			ic := newIPCConn(conn)
			s.clients[ic] = true
			s.mu.Unlock()
			go s.handleClient(ic)
			continue
		}
		s.mu.Unlock()
		conn.Close()
	}
}

func (s *IPCServer) handleClient(conn *ipcConn) {
	// Outermost defer: L9 panic boundary
	// (architecture-notes/03-INVARIANTS.md §8). Tear down THIS IPC
	// conn only — other clients keep working. The other deferred
	// cleanup (ports/conns/registry) still runs first because defers
	// are LIFO. recoverLayer publishes the bus event so observability
	// sees the per-conn teardown.
	defer recoverLayer("L9", "handleClient", s.daemon.bus, nil)

	// Concurrent-dispatch wait group: every dispatched request bumps it,
	// every reply path decrements it. We wait on this before tearing down
	// ports/conns so an in-flight handler can't write to a closed sendCh.
	var dispatchWG sync.WaitGroup

	defer func() {
		// Drain in-flight dispatch goroutines first so they finish their
		// reply (or fail fast on closed conn) before the cleanup below
		// invalidates ports/conns they may be touching.
		dispatchWG.Wait()

		// Clean up ports and connections owned by this client.
		// Copy the slices into fresh backing arrays — `conn.conns` and
		// `conn.ports` may be mutated by removeConn / unbind paths
		// running after we release rmu, and the [:0] aliasing form
		// would race with our iteration below (bug surfaced by §4.8).
		conn.rmu.Lock()
		ports := make([]uint16, len(conn.ports))
		copy(ports, conn.ports)
		conns := make([]uint32, len(conn.conns))
		copy(conns, conn.conns)
		conn.rmu.Unlock()

		for _, connID := range conns {
			if c := s.daemon.ports.GetConnection(connID); c != nil {
				s.daemon.CloseConnection(c)
			}
		}
		for _, port := range ports {
			s.daemon.ports.Unbind(port)
		}

		conn.Close()
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
	}()

	// Buffered semaphore caps in-flight goroutines per client. Push to it
	// before spawning a dispatcher; pop when the dispatcher exits. If
	// full, the read loop blocks here, applying TCP-style backpressure
	// to the client.
	sem := make(chan struct{}, ipcMaxInflightPerClient)

	for {
		msg, err := ipcutil.Read(conn)
		if err != nil {
			if err != io.EOF {
				slog.Error("IPC read error", "error", err)
			}
			return
		}
		// Wire format: [cmd(1)][payload...]
		if len(msg) < IPCEnvelopeHeaderSize {
			continue
		}
		cmd := msg[0]
		reqID := uint64(0) // not transmitted on wire; kept for handler signatures
		payload := msg[IPCEnvelopeHeaderSize:]

		// CmdCancel: no-op (reqID is not on the wire; kept for wire
		// compat with older clients that still send it).
		if cmd == CmdCancel {
			continue
		}

		// CmdSend MUST dispatch inline to preserve per-client-conn FIFO
		// data ordering — dataexchange.WriteFrame issues two sequential
		// Conn.Write() calls (header + payload); if those raced in
		// worker goroutines, SendData would append in the wrong order
		// and the receiver would see a corrupted frame. CmdSendTo
		// follows the same pattern. CmdClose stays in the concurrent
		// dispatch lane: by the time it arrives, all prior CmdSends on
		// the same conn have already returned from their inline call,
		// so the data is in NagleBuf and Close's FIN goes out after.
		switch cmd {
		case CmdSend:
			s.handleSend(conn, reqID, payload)
			continue
		case CmdSendTo:
			s.handleSendTo(conn, reqID, payload)
			continue
		}

		// Acquire a dispatch slot. Block if the client is already at the
		// per-conn cap; this is what stops a flooding client from
		// spawning unbounded goroutines.
		select {
		case sem <- struct{}{}:
		case <-conn.done:
			return
		}

		dispatchWG.Add(1)
		go func(cmd byte, reqID uint64, payload []byte) {
			defer func() {
				<-sem
				dispatchWG.Done()
			}()
			// Per-handler panic boundary: a panic in one dispatch must not
			// take down handleClient or other in-flight dispatches on the
			// same conn (issue #99, concurrent dispatch).
			defer recoverLayer("L9", "ipcDispatch", s.daemon.bus, nil)
			s.dispatch(conn, cmd, reqID, payload)
		}(cmd, reqID, payload)
	}
}

// dispatch routes a request to the correct handler. Each handler is
// responsible for writing exactly one reply (writeReply with the same
// reqID) or calling sendError (which now also takes reqID). Several
// handlers spawn long-lived background goroutines (e.g. handleBind starts
// the accept-pusher); those run independently and use writePush for
// unsolicited server → client frames.
func (s *IPCServer) dispatch(conn *ipcConn, cmd byte, reqID uint64, payload []byte) {
	switch cmd {
	case CmdBind:
		s.handleBind(conn, reqID, payload)
	case CmdDial:
		s.handleDial(conn, reqID, payload)
	case CmdSend:
		s.handleSend(conn, reqID, payload)
	case CmdClose:
		s.handleClose(conn, reqID, payload)
	case CmdSendTo:
		s.handleSendTo(conn, reqID, payload)
	case CmdBroadcast:
		s.handleBroadcast(conn, reqID, payload)
	case CmdInfo:
		s.handleInfo(conn, reqID)
	case CmdHandshake:
		s.handleHandshake(conn, reqID, payload)
	case CmdResolveHostname:
		s.handleResolveHostname(conn, reqID, payload)
	case CmdSetHostname:
		s.handleSetHostname(conn, reqID, payload)
	case CmdSetVisibility:
		s.handleSetVisibility(conn, reqID, payload)
	case CmdDeregister:
		s.handleDeregister(conn, reqID)
	case CmdSetTags:
		s.handleSetTags(conn, reqID, payload)
	case CmdSetWebhook:
		s.handleSetWebhook(conn, reqID, payload)
	case CmdNetwork:
		s.handleNetwork(conn, reqID, payload)
	case CmdHealth:
		s.handleHealth(conn, reqID)
	case CmdManaged:
		s.handleManaged(conn, reqID, payload)
	case CmdRotateKey:
		s.handleRotateKey(conn, reqID)
	default:
		s.sendError(conn, reqID, fmt.Sprintf("unknown command: 0x%02X", cmd))
	}
}

func (s *IPCServer) handleBind(conn *ipcConn, reqID uint64, payload []byte) {
	if len(payload) < 2 {
		s.sendError(conn, reqID, "bind: missing port")
		return
	}
	port := binary.BigEndian.Uint16(payload[0:2])

	ln, err := s.daemon.ports.Bind(port)
	if err != nil {
		s.sendError(conn, reqID, err.Error())
		return
	}

	conn.trackPort(port)

	// Send bind OK (reply: [port(2)])
	respBody := make([]byte, 2)
	binary.BigEndian.PutUint16(respBody[0:2], port)
	if err := conn.writeReply(CmdBindOK, reqID, respBody); err != nil {
		slog.Debug("IPC bind reply failed", "port", port, "err", err)
		return
	}

	// Start pushing accepted connections to this client. CmdAccept frames
	// are server-pushed (reqID=0) and demuxed by the driver on local port.
	go func() {
		for c := range ln.AcceptCh {
			conn.trackConn(c.ID)
			// H12 fix: include local port for per-port demux
			body := make([]byte, 2+4+protocol.AddrSize+2)
			binary.BigEndian.PutUint16(body[0:2], port)
			binary.BigEndian.PutUint32(body[2:6], c.ID)
			c.RemoteAddr.MarshalTo(body, 6)
			binary.BigEndian.PutUint16(body[6+protocol.AddrSize:], c.RemotePort)
			if err := conn.writePush(CmdAccept, body); err != nil {
				slog.Debug("IPC accept notify failed", "conn_id", c.ID, "err", err)
				return
			}

			s.startRecvPusher(conn, c)
		}
	}()
}

func (s *IPCServer) handleDial(conn *ipcConn, reqID uint64, payload []byte) {
	if len(payload) < protocol.AddrSize+2 {
		s.sendError(conn, reqID, "dial: missing address/port")
		return
	}

	// P2-002: reject dial if this client already owns MaxConnsPerIPCClient
	// connections. Avoids the single-client DoS where one buggy driver
	// exhausts the global connection table.
	if n := conn.connCount(); n >= MaxConnsPerIPCClient {
		s.sendError(conn, reqID, fmt.Sprintf("dial: per-client connection quota (%d) reached", MaxConnsPerIPCClient))
		return
	}

	dstAddr := protocol.UnmarshalAddr(payload[0:protocol.AddrSize])
	dstPort := binary.BigEndian.Uint16(payload[protocol.AddrSize:])

	// Per-dial cancellable context tied to this IPC connection's lifetime
	// Cancellation: ipcConn.Close fires every dialCancels entry so a
	// disconnected driver doesn't leave the daemon grinding through
	// 14-31 s of retries.
	dialCtx, dialCancel := context.WithCancel(context.Background())
	cancelID := conn.addDialCancel(dialCancel)
	defer func() {
		dialCancel()
		conn.removeDialCancel(cancelID)
	}()

	c, err := s.daemon.DialConnectionContext(dialCtx, dstAddr, dstPort)
	if err != nil {
		s.sendError(conn, reqID, err.Error())
		return
	}

	// If the driver cancelled (cmdCancel) AFTER the dial succeeded but
	// BEFORE we got here, the resulting Connection is orphaned: the
	// driver isn't tracking the connID and won't ever send CmdClose. We
	// close it here to avoid leaking the conn table slot + a retxLoop
	// goroutine. Issue #99: §4.8 stress with cmdCancel uncovered ~20
	// retxLoops accumulating per rep from this race.
	select {
	case <-dialCtx.Done():
		s.daemon.CloseConnection(c)
		return
	default:
	}

	conn.trackConn(c.ID)

	// Send dial OK (reply: [connID(4)])
	respBody := make([]byte, 4)
	binary.BigEndian.PutUint32(respBody[0:4], c.ID)
	if err := conn.writeReply(CmdDialOK, reqID, respBody); err != nil {
		slog.Debug("IPC dial reply failed", "conn_id", c.ID, "err", err)
		// Driver isn't reachable — also close the orphan conn.
		s.daemon.CloseConnection(c)
		conn.removeConn(c.ID)
		return
	}

	// Re-check cancellation after the reply has gone out: cmdCancel may
	// have arrived during the window between the first cancel-check and
	// the writeReply. The driver's waiter has already returned a
	// "dial timeout" error, so its reply demux silently drops cmdDialOK
	// and the connection is orphaned with no Close() ever coming. Issue
	// #99 §4.8 residual: this race left ~30 retxLoops alive per rep
	// even after the orphan-close pre-check.
	select {
	case <-dialCtx.Done():
		s.daemon.CloseConnection(c)
		conn.removeConn(c.ID)
		return
	default:
	}

	s.startRecvPusher(conn, c)
}

func (s *IPCServer) handleSend(conn *ipcConn, reqID uint64, payload []byte) {
	// CmdSend is fire-and-forget: no reply on success OR error.
	// Sending a CmdError reply would land in the driver's single
	// pending channel and corrupt a concurrent sendAndWait reply.
	if len(payload) < 4 {
		return
	}
	connID := binary.BigEndian.Uint32(payload[0:4])
	data := payload[4:]

	c := s.daemon.ports.GetConnection(connID)
	if c == nil {
		return
	}
	_ = s.daemon.SendData(c, data)
}

func (s *IPCServer) handleClose(conn *ipcConn, reqID uint64, payload []byte) {
	if len(payload) < 4 {
		s.sendError(conn, reqID, "close: missing conn_id")
		return
	}
	connID := binary.BigEndian.Uint32(payload[0:4])

	c := s.daemon.ports.GetConnection(connID)
	if c != nil {
		s.daemon.CloseConnection(c)
	}
	conn.removeConn(connID)

	respBody := make([]byte, 4)
	binary.BigEndian.PutUint32(respBody[0:4], connID)
	if err := conn.writeReply(CmdCloseOK, reqID, respBody); err != nil {
		slog.Debug("IPC close reply failed", "conn_id", connID, "err", err)
	}
}

func (s *IPCServer) handleSendTo(conn *ipcConn, reqID uint64, payload []byte) {
	// CmdSendTo is fire-and-forget: no reply on success OR error.
	// Same reasoning as handleSend — error replies would corrupt pending.
	if len(payload) < protocol.AddrSize+2 {
		return
	}

	dstAddr := protocol.UnmarshalAddr(payload[0:protocol.AddrSize])
	dstPort := binary.BigEndian.Uint16(payload[protocol.AddrSize : protocol.AddrSize+2])
	data := payload[protocol.AddrSize+2:]
	_ = s.daemon.SendDatagram(dstAddr, dstPort, data)
}

// handleBroadcast services CmdBroadcast — admin-token-gated fan-out to a
// whole network. Wire payload:
//
//	[netID(2)][dstPort(2)][tokenLen(2)][token...][data...]
//
// On success, replies with CmdBroadcastOK (no body). On failure, replies
// with CmdError carrying the daemon error message — typically "daemon has
// no admin token configured" or "invalid admin token".
func (s *IPCServer) handleBroadcast(conn *ipcConn, reqID uint64, payload []byte) {
	if len(payload) < 6 {
		s.sendError(conn, reqID, "broadcast: missing header")
		return
	}
	netID := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	tokenLen := binary.BigEndian.Uint16(payload[4:6])
	if len(payload) < 6+int(tokenLen) {
		s.sendError(conn, reqID, "broadcast: truncated token")
		return
	}
	token := string(payload[6 : 6+tokenLen])
	data := payload[6+tokenLen:]

	if err := s.daemon.BroadcastDatagram(netID, dstPort, data, token); err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("broadcast: %v", err))
		return
	}
	if err := conn.writeReply(CmdBroadcastOK, reqID, nil); err != nil {
		slog.Debug("IPC broadcast reply failed", "err", err)
	}
}

func (s *IPCServer) handleInfo(conn *ipcConn, reqID uint64) {
	info := s.daemon.Info()

	// Build peer list for JSON
	peers := make([]map[string]interface{}, len(info.PeerList))
	for i, p := range info.PeerList {
		peers[i] = map[string]interface{}{
			"node_id":       p.NodeID,
			"endpoint":      p.Endpoint,
			"encrypted":     p.Encrypted,
			"authenticated": p.Authenticated,
			"relay":         p.Relay,
		}
	}

	// Build connection list for JSON
	conns := make([]map[string]interface{}, len(info.ConnList))
	for i, c := range info.ConnList {
		conns[i] = map[string]interface{}{
			"id":            c.ID,
			"local_port":    c.LocalPort,
			"remote_addr":   c.RemoteAddr,
			"remote_port":   c.RemotePort,
			"state":         c.State,
			"cong_win":      c.CongWin,
			"ssthresh":      c.SSThresh,
			"in_flight":     c.InFlight,
			"srtt_ms":       float64(c.SRTT.Milliseconds()),
			"rttvar_ms":     float64(c.RTTVAR.Milliseconds()),
			"unacked":       c.Unacked,
			"ooo_buf":       c.OOOBuf,
			"peer_recv_win": c.PeerRecvWin,
			"recv_win":      c.RecvWin,
			"in_recovery":   c.InRecovery,
			"bytes_sent":    c.Stats.BytesSent,
			"bytes_recv":    c.Stats.BytesRecv,
			"segs_sent":     c.Stats.SegsSent,
			"segs_recv":     c.Stats.SegsRecv,
			"retransmits":   c.Stats.Retransmits,
			"fast_retx":     c.Stats.FastRetx,
			"sack_recv":     c.Stats.SACKRecv,
			"sack_sent":     c.Stats.SACKSent,
			"dup_acks":      c.Stats.DupACKs,
		}
	}

	data, err := json.Marshal(map[string]interface{}{
		"node_id":                   info.NodeID,
		"address":                   info.Address,
		"endpoint":                  info.Endpoint,
		"hostname":                  info.Hostname,
		"uptime_secs":               info.Uptime.Seconds(),
		"connections":               info.Connections,
		"ports":                     info.Ports,
		"peers":                     info.Peers,
		"encrypted_peers":           info.EncryptedPeers,
		"authenticated_peers":       info.AuthenticatedPeers,
		"encrypt":                   info.Encrypt,
		"identity":                  info.Identity,
		"public_key":                info.PublicKey,
		"email":                     info.Email,
		"bytes_sent":                info.BytesSent,
		"bytes_recv":                info.BytesRecv,
		"pkts_sent":                 info.PktsSent,
		"pkts_recv":                 info.PktsRecv,
		"tunnel_encryption_success": info.EncryptOK,
		"tunnel_encryption_failure": info.EncryptFail,
		"handshake_pending_count":   info.HandshakePendingCount,
		"version":                   info.Version,
		"networks":                  info.Networks,
		"peer_list":                 peers,
		"conn_list":                 conns,
		"accept_queue_drops":        info.AcceptQueueDrops,
		"webhook_queue_dropped":     info.WebhookQueueDropped,
		"webhook_circuit_skips":     info.WebhookCircuitSkips,
		"relay_peer_count":          info.RelayPeerCount,
		"beacon_addr":               info.BeaconAddr,
	})
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("info marshal: %v", err))
		return
	}
	if err := conn.writeReply(CmdInfoOK, reqID, data); err != nil {
		slog.Debug("IPC info reply failed", "err", err)
	}
}

func (s *IPCServer) handleHealth(conn *ipcConn, reqID uint64) {
	info := s.daemon.Info()
	data, err := json.Marshal(map[string]interface{}{
		"status":                  "ok",
		"uptime_seconds":          int64(info.Uptime.Seconds()),
		"connections":             info.Connections,
		"peers":                   info.Peers,
		"bytes_sent":              info.BytesSent,
		"bytes_recv":              info.BytesRecv,
		"encrypted_peers":         info.EncryptedPeers,
		"authenticated_peers":     info.AuthenticatedPeers,
		"handshake_pending_count": info.HandshakePendingCount,
		"relay_peer_count":        info.RelayPeerCount,
		"accept_queue_drops":      info.AcceptQueueDrops,
		"webhook_queue_dropped":   info.WebhookQueueDropped,
		"webhook_circuit_skips":   info.WebhookCircuitSkips,
		"beacon_addr":             info.BeaconAddr,
	})
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("health marshal: %v", err))
		return
	}
	if err := conn.writeReply(CmdHealthOK, reqID, data); err != nil {
		slog.Debug("IPC health reply failed", "err", err)
	}
}

func (s *IPCServer) handleResolveHostname(conn *ipcConn, reqID uint64, payload []byte) {
	hostname := string(payload)
	if hostname == "" {
		s.sendError(conn, reqID, "resolve_hostname: missing hostname")
		return
	}

	// Try the daemon's hostname cache first. The regConn mutex is shared
	// with the policy_runner's fetchMembers loop; on networks that trip
	// the list_nodes EOF cycle the lookup can block for seconds. Most
	// CLI invocations resolve the same hostname repeatedly (a chained
	// agent script doing dozens of `pilotctl send-message agent X`
	// calls), so a 60s positive cache turns those calls into IPC-only
	// round trips.
	now := time.Now()
	s.daemon.hostnameCacheMu.RLock()
	if e, ok := s.daemon.hostnameCache[hostname]; ok && now.Sub(e.cachedAt) < hostnameCacheTTL {
		cached := e.resp
		s.daemon.hostnameCacheMu.RUnlock()
		if data, err := json.Marshal(cached); err == nil {
			if err := conn.writeReply(CmdResolveHostnameOK, reqID, data); err != nil {
				slog.Debug("IPC resolve_hostname (cached) reply failed", "err", err)
			}
			return
		}
		// fall through on marshal error (shouldn't happen)
	} else {
		s.daemon.hostnameCacheMu.RUnlock()
	}

	result, err := s.daemon.regConn.ResolveHostname(hostname)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("resolve_hostname: %v", err))
		return
	}

	// Cache the successful response. Only cache positive results so
	// transient registry hiccups don't poison the cache with a bogus
	// "not found". Skip caching when the result points at our own
	// node — local hostname state is owned by the daemon and changes
	// through paths that don't always invalidate the cache (admin
	// tools talking directly to the registry, tests bypassing IPC).
	if nidVal, ok := result["node_id"].(float64); ok && uint32(nidVal) == s.daemon.NodeID() {
		// fall through — no cache write, no prewarm, no disk persist
	} else {
		s.daemon.hostnameCacheMu.Lock()
		s.daemon.hostnameCache[hostname] = &hostnameCacheEntry{resp: result, cachedAt: now}
		s.daemon.hostnameCacheMu.Unlock()
	}

	// Pre-warm the node-resolve cache so a follow-up DialAddr call from the
	// same pilotctl invocation skips the second registry round-trip in
	// ensureTunnel. Ran in a goroutine so the IPC reply isn't gated on it
	// — the caller has already gotten what they asked for; this is just
	// a latency-hiding bonus. Lock contention is rare since regConn.Send
	// is the same mutex; the policy_runner backoff keeps it free.
	if nodeIDVal, ok := result["node_id"].(float64); ok {
		nodeID := uint32(nodeIDVal)
		go func() {
			resolveResp, err := s.daemon.regConn.Resolve(nodeID, s.daemon.NodeID())
			if err != nil {
				slog.Debug("hostname resolve prewarm failed", "node_id", nodeID, "err", err)
				return
			}
			s.daemon.cacheResolve(nodeID, resolveResp)
		}()
	}

	// Also persist the hostname cache to disk so a daemon restart starts
	// warm. Async — don't gate the IPC reply on disk I/O.
	go s.daemon.persistHostnameCache()

	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("resolve_hostname marshal: %v", err))
		return
	}

	if err := conn.writeReply(CmdResolveHostnameOK, reqID, data); err != nil {
		slog.Debug("IPC resolve_hostname reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetHostname(conn *ipcConn, reqID uint64, payload []byte) {
	hostname := string(payload)
	// Snapshot the previous hostname so we can invalidate it from the
	// cache regardless of whether this is a set, change, or clear.
	s.daemon.addrMu.RLock()
	prevHostname := s.daemon.config.Hostname
	s.daemon.addrMu.RUnlock()
	result, err := s.daemon.regConn.SetHostname(s.daemon.NodeID(), hostname)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("set_hostname: %v", err))
		return
	}
	// Update daemon's local config so Info() reflects the change
	s.daemon.addrMu.Lock()
	s.daemon.config.Hostname = hostname
	s.daemon.addrMu.Unlock()
	// Invalidate any cache entries that this change could have made stale:
	// the old name (we may have cached resolutions for it) and the new
	// name (could be a re-bind from another node we previously cached).
	s.daemon.hostnameCacheMu.Lock()
	if prevHostname != "" {
		delete(s.daemon.hostnameCache, prevHostname)
	}
	if hostname != "" {
		delete(s.daemon.hostnameCache, hostname)
	}
	s.daemon.hostnameCacheMu.Unlock()
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("set_hostname marshal: %v", err))
		return
	}
	if err := conn.writeReply(CmdSetHostnameOK, reqID, data); err != nil {
		slog.Debug("IPC set_hostname reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetVisibility(conn *ipcConn, reqID uint64, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, reqID, "set_visibility: missing value")
		return
	}
	public := payload[0] == 1
	result, err := s.daemon.regConn.SetVisibility(s.daemon.NodeID(), public)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("set_visibility: %v", err))
		return
	}
	// Update daemon's local config so Info() reflects the change
	s.daemon.addrMu.Lock()
	s.daemon.config.Public = public
	s.daemon.addrMu.Unlock()
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("set_visibility marshal: %v", err))
		return
	}
	if err := conn.writeReply(CmdSetVisibilityOK, reqID, data); err != nil {
		slog.Debug("IPC set_visibility reply failed", "err", err)
	}
}

func (s *IPCServer) handleDeregister(conn *ipcConn, reqID uint64) {
	result, err := s.daemon.regConn.Deregister(s.daemon.NodeID())
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("deregister: %v", err))
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("deregister marshal: %v", err))
		return
	}
	if err := conn.writeReply(CmdDeregisterOK, reqID, data); err != nil {
		slog.Debug("IPC deregister reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetTags(conn *ipcConn, reqID uint64, payload []byte) {
	var tags []string
	if err := json.Unmarshal(payload, &tags); err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("set_tags: invalid JSON: %v", err))
		return
	}
	if len(tags) > 3 {
		s.sendError(conn, reqID, "set_tags: maximum 3 tags allowed")
		return
	}
	result, err := s.daemon.regConn.SetTags(s.daemon.NodeID(), tags)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("set_tags: %v", err))
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("set_tags marshal: %v", err))
		return
	}
	if err := conn.writeReply(CmdSetTagsOK, reqID, data); err != nil {
		slog.Debug("IPC set_tags reply failed", "err", err)
	}
}

func (s *IPCServer) handleRotateKey(conn *ipcConn, reqID uint64) {
	result, err := s.daemon.RotateKey()
	if err != nil {
		s.sendError(conn, reqID, err.Error())
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, reqID, fmt.Sprintf("rotate_key marshal: %v", err))
		return
	}
	if err := conn.writeReply(CmdRotateKeyOK, reqID, data); err != nil {
		slog.Debug("IPC rotate_key reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetWebhook(conn *ipcConn, reqID uint64, payload []byte) {
	url := string(payload) // empty string = clear webhook
	if url != "" {
		if err := ValidateWebhookURL(url); err != nil {
			s.sendError(conn, reqID, err.Error())
			return
		}
	}
	s.daemon.SetWebhookURL(url)
	result := map[string]interface{}{"webhook": url}
	data, _ := json.Marshal(result)
	if err := conn.writeReply(CmdSetWebhookOK, reqID, data); err != nil {
		slog.Debug("IPC set_webhook reply failed", "err", err)
	}
}

// Handshake IPC sub-commands
const (
	SubHandshakeSend    byte = 0x01
	SubHandshakeApprove byte = 0x02
	SubHandshakeReject  byte = 0x03
	SubHandshakePending byte = 0x04
	SubHandshakeTrusted byte = 0x05
	SubHandshakeRevoke  byte = 0x06
	SubHandshakeWait    byte = 0x07
)

func (s *IPCServer) handleHandshake(conn *ipcConn, reqID uint64, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, reqID, "handshake: missing sub-command")
		return
	}
	if s.daemon.handshakes == nil {
		s.sendError(conn, reqID, "handshake: service not registered")
		return
	}
	sub := payload[0]
	rest := payload[1:]

	switch sub {
	case SubHandshakeSend:
		if len(rest) < 4 {
			s.sendError(conn, reqID, "handshake request: missing node_id")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		justification := ""
		if len(rest) > 4 {
			justification = string(rest[4:])
		}
		if err := s.daemon.handshakes.SendRequest(nodeID, justification); err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("handshake request: %v", err))
			return
		}
		data, _ := json.Marshal(map[string]interface{}{
			"status":  "sent",
			"node_id": nodeID,
		})
		s.ipcWriteHandshakeOK(conn, reqID, data)

	case SubHandshakeApprove:
		if len(rest) < 4 {
			s.sendError(conn, reqID, "handshake approve: missing node_id")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		if err := s.daemon.handshakes.ApproveHandshake(nodeID); err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("handshake approve: %v", err))
			return
		}
		data, _ := json.Marshal(map[string]interface{}{
			"status":  "approved",
			"node_id": nodeID,
		})
		s.ipcWriteHandshakeOK(conn, reqID, data)

	case SubHandshakeReject:
		if len(rest) < 4 {
			s.sendError(conn, reqID, "handshake reject: missing node_id")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		reason := ""
		if len(rest) > 4 {
			reason = string(rest[4:])
		}
		if err := s.daemon.handshakes.RejectHandshake(nodeID, reason); err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("handshake reject: %v", err))
			return
		}
		data, _ := json.Marshal(map[string]interface{}{
			"status":  "rejected",
			"node_id": nodeID,
		})
		s.ipcWriteHandshakeOK(conn, reqID, data)

	case SubHandshakePending:
		pending := s.daemon.handshakes.PendingRequests()
		list := make([]map[string]interface{}, len(pending))
		for i, p := range pending {
			list[i] = map[string]interface{}{
				"node_id":       p.NodeID,
				"public_key":    p.PublicKey,
				"justification": p.Justification,
				"received_at":   p.ReceivedAt.Unix(),
			}
		}
		data, _ := json.Marshal(map[string]interface{}{
			"pending": list,
		})
		s.ipcWriteHandshakeOK(conn, reqID, data)

	case SubHandshakeTrusted:
		trusted := s.daemon.handshakes.TrustedPeers()
		list := make([]map[string]interface{}, len(trusted))
		for i, t := range trusted {
			list[i] = map[string]interface{}{
				"node_id":     t.NodeID,
				"public_key":  t.PublicKey,
				"approved_at": t.ApprovedAt.Unix(),
				"mutual":      t.Mutual,
				"network":     t.Network,
			}
		}
		data, _ := json.Marshal(map[string]interface{}{
			"trusted": list,
		})
		s.ipcWriteHandshakeOK(conn, reqID, data)

	case SubHandshakeRevoke:
		if len(rest) < 4 {
			s.sendError(conn, reqID, "handshake revoke: missing node_id")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		if err := s.daemon.handshakes.RevokeTrust(nodeID); err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("handshake revoke: %v", err))
			return
		}
		data, _ := json.Marshal(map[string]interface{}{
			"status":  "revoked",
			"node_id": nodeID,
		})
		s.ipcWriteHandshakeOK(conn, reqID, data)

	case SubHandshakeWait:
		if len(rest) < 8 {
			s.sendError(conn, reqID, "handshake wait: payload must be [nodeID(4)][timeoutMs(4)]")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		timeoutMs := binary.BigEndian.Uint32(rest[4:8])
		// Cap timeout at 30s — pilotctl is the typical caller and we
		// don't want a stuck wait blocking an IPC dispatch slot longer.
		if timeoutMs > 30000 {
			timeoutMs = 30000
		}
		ok := s.daemon.handshakes.WaitForTrust(nodeID, time.Duration(timeoutMs)*time.Millisecond)
		data, _ := json.Marshal(map[string]interface{}{
			"node_id": nodeID,
			"trusted": ok,
		})
		s.ipcWriteHandshakeOK(conn, reqID, data)

	default:
		s.sendError(conn, reqID, fmt.Sprintf("handshake: unknown sub-command 0x%02X", sub))
	}
}

func (s *IPCServer) ipcWriteHandshakeOK(conn *ipcConn, reqID uint64, data []byte) {
	if err := conn.writeReply(CmdHandshakeOK, reqID, data); err != nil {
		slog.Debug("IPC handshake reply failed", "err", err)
	}
}

func (s *IPCServer) ipcWriteNetworkOK(conn *ipcConn, reqID uint64, data []byte) {
	if err := conn.writeReply(CmdNetworkOK, reqID, data); err != nil {
		slog.Debug("IPC network reply failed", "err", err)
	}
}

func (s *IPCServer) handleNetwork(conn *ipcConn, reqID uint64, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, reqID, "network: missing sub-command")
		return
	}
	sub := payload[0]
	rest := payload[1:]

	switch sub {
	case SubNetworkList:
		result, err := s.daemon.regConn.ListNetworks()
		if err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("network list: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, reqID, data)

	case SubNetworkJoin:
		// [2-byte networkID][token...]
		if len(rest) < 2 {
			s.sendError(conn, reqID, "network join: missing network_id")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		token := ""
		if len(rest) > 2 {
			token = string(rest[2:])
		}
		result, err := s.daemon.regConn.JoinNetwork(
			s.daemon.NodeID(), netID, token, 0, s.daemon.config.AdminToken,
		)
		if err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("network join: %v", err))
			return
		}
		// Membership just changed — drop the cached snapshot so the next
		// Info() / Health() call resolves the fresh list (issue #93).
		s.daemon.invalidateNodeNetworksCache()
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, reqID, data)
		// Refresh port policy cache for the newly joined network
		go s.daemon.loadNetworkPolicies()
		// Start policy runner if the network has an expr_policy
		if epRaw, ok := result["expr_policy"]; ok {
			var policyJSON json.RawMessage
			switch v := epRaw.(type) {
			case string:
				policyJSON = json.RawMessage(v)
			case map[string]interface{}:
				policyJSON, _ = json.Marshal(v)
			}
			if len(policyJSON) > 0 {
				if err := s.daemon.StartPolicyRunner(netID, policyJSON); err != nil {
					slog.Warn("policy: failed to start runner on join", "network_id", netID, "err", err)
				}
			}
		}

	case SubNetworkLeave:
		// [2-byte networkID]
		if len(rest) < 2 {
			s.sendError(conn, reqID, "network leave: missing network_id")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		result, err := s.daemon.regConn.LeaveNetwork(
			s.daemon.NodeID(), netID, s.daemon.config.AdminToken,
		)
		if err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("network leave: %v", err))
			return
		}
		s.daemon.invalidateNodeNetworksCache()
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, reqID, data)

		// Clean up local state for the left network.
		go func() {
			s.daemon.StopPolicyRunner(netID)
			s.daemon.StopManagedEngine(netID)
			s.daemon.clearNetworkState(netID)
			s.daemon.loadNetworkPolicies()
		}()

	case SubNetworkMembers:
		// [2-byte networkID]
		if len(rest) < 2 {
			s.sendError(conn, reqID, "network members: missing network_id")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		result, err := s.daemon.regConn.ListNodes(netID, s.daemon.config.AdminToken)
		if err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("network members: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, reqID, data)

	case SubNetworkInvite:
		// [2-byte networkID][4-byte targetNodeID]
		if len(rest) < 6 {
			s.sendError(conn, reqID, "network invite: missing network_id or target_node_id")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		targetID := binary.BigEndian.Uint32(rest[2:6])
		result, err := s.daemon.regConn.InviteToNetwork(
			netID, s.daemon.NodeID(), targetID, s.daemon.config.AdminToken,
		)
		if err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("network invite: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, reqID, data)

	case SubNetworkPollInvites:
		result, err := s.daemon.regConn.PollInvites(s.daemon.NodeID())
		if err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("network poll-invites: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, reqID, data)

	case SubNetworkRespondInvite:
		// [2-byte networkID][1-byte accept]
		if len(rest) < 3 {
			s.sendError(conn, reqID, "network respond-invite: missing network_id or accept flag")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		accept := rest[2] == 1
		result, err := s.daemon.regConn.RespondInvite(
			s.daemon.NodeID(), netID, accept,
		)
		if err != nil {
			s.sendError(conn, reqID, fmt.Sprintf("network respond-invite: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, reqID, data)

	default:
		s.sendError(conn, reqID, fmt.Sprintf("network: unknown sub-command 0x%02X", sub))
	}
}

// startRecvPusher drains c.RecvBuf and pushes data to the IPC client.
// When RecvBuf closes (remote FIN), it sends CmdCloseOK to the driver.
// Both CmdRecv and the trailing CmdCloseOK go out as server-pushed
// envelopes (reqID=0) so the driver's read loop demuxes by cmd, not by
// any in-flight reqID.
func (s *IPCServer) startRecvPusher(conn *ipcConn, c *Connection) {
	go func() {
		for data := range c.RecvBuf {
			body := make([]byte, 4+len(data))
			binary.BigEndian.PutUint32(body[0:4], c.ID)
			copy(body[4:], data)
			if err := conn.writePush(CmdRecv, body); err != nil {
				slog.Debug("IPC recv push failed", "conn_id", c.ID, "err", err)
				conn.removeConn(c.ID)
				return
			}
		}
		closeBody := make([]byte, 4)
		binary.BigEndian.PutUint32(closeBody[0:4], c.ID)
		if err := conn.writePush(CmdCloseOK, closeBody); err != nil {
			slog.Debug("IPC close notify failed", "conn_id", c.ID, "err", err)
		}
		conn.removeConn(c.ID)
	}()
}

// sendError writes a CmdError envelope echoing the request's reqID so the
// driver routes the failure to the awaiting waiter (or the global error
// fallback when reqID==0). Body shape: [code(2)][message...].
func (s *IPCServer) sendError(conn *ipcConn, reqID uint64, msg string) {
	body := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(body[0:2], 1) // generic error code
	copy(body[2:], msg)
	if err := conn.writeReply(CmdError, reqID, body); err != nil {
		slog.Debug("IPC error reply failed", "msg", msg, "err", err)
	}
}

// Deliver a datagram to any listening IPC client
func (s *IPCServer) DeliverDatagram(srcAddr protocol.Addr, srcPort uint16, dstPort uint16, data []byte) {
	// Collect clients under lock, then write outside lock (M11 fix:
	// avoid holding mu during I/O, which could block routeLoop)
	s.mu.Lock()
	clients := make([]*ipcConn, 0, len(s.clients))
	for conn := range s.clients {
		clients = append(clients, conn)
	}
	s.mu.Unlock()

	// Send RecvFrom to all connected clients (the driver filters by port).
	// reqID=0 because this is a server-pushed unsolicited frame.
	body := make([]byte, protocol.AddrSize+2+2+len(data))
	srcAddr.MarshalTo(body, 0)
	binary.BigEndian.PutUint16(body[protocol.AddrSize:], srcPort)
	binary.BigEndian.PutUint16(body[protocol.AddrSize+2:], dstPort)
	copy(body[protocol.AddrSize+4:], data)

	// P2-004: fan out writes to each client in a dedicated goroutine so a
	// slow IPC peer can't wedge routeLoop for every other peer. ipcWrite
	// already serializes per-connection via the writer goroutine, so
	// concurrent enqueues are safe.
	for _, conn := range clients {
		conn := conn
		go func() {
			if err := conn.writePush(CmdRecvFrom, body); err != nil {
				slog.Debug("IPC datagram delivery failed", "err", err)
			}
		}()
	}
}

func (s *IPCServer) handleManaged(conn *ipcConn, reqID uint64, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, reqID, "managed: missing sub-command")
		return
	}
	sub := payload[0]
	rest := payload[1:]

	switch sub {
	case SubManagedStatus:
		// [2-byte netID] (optional — 0 means first/only engine)
		netID := uint16(0)
		if len(rest) >= 2 {
			netID = binary.BigEndian.Uint16(rest[0:2])
		}

		if pr := s.findPolicyRunner(netID); pr != nil {
			data, _ := json.Marshal(pr.Status())
			s.ipcWriteManagedOK(conn, reqID, data)
		} else if me := s.findManagedEngine(netID); me != nil {
			data, _ := json.Marshal(me.Status())
			s.ipcWriteManagedOK(conn, reqID, data)
		} else {
			s.sendError(conn, reqID, "managed: no active managed networks")
		}

	case SubManagedCycle:
		// [2-byte netID] (optional)
		netID := uint16(0)
		if len(rest) >= 2 {
			netID = binary.BigEndian.Uint16(rest[0:2])
		}

		var result map[string]interface{}
		if pr := s.findPolicyRunner(netID); pr != nil {
			result = pr.ForceCycle()
		} else if me := s.findManagedEngine(netID); me != nil {
			result = me.ForceCycle()
		} else {
			s.sendError(conn, reqID, "managed: no active managed networks")
			return
		}

		data, _ := json.Marshal(result)
		s.ipcWriteManagedOK(conn, reqID, data)

	case SubManagedReconcile:
		// [2-byte netID]. Poll the registry for the network's member list
		// and refresh the runner's peer set — without running a policy
		// cycle (no evict side effects). This is useful for tests
		// and operators who want a clean "my peer view matches the
		// registry" primitive.
		netID := uint16(0)
		if len(rest) >= 2 {
			netID = binary.BigEndian.Uint16(rest[0:2])
		}
		pr := s.findPolicyRunner(netID)
		if pr == nil {
			s.sendError(conn, reqID, "managed: no active policy runner for network")
			return
		}
		pr.ReconcileNow()
		data, _ := json.Marshal(map[string]interface{}{
			"type":       "managed_reconcile_ok",
			"network_id": netID,
			"peers":      len(pr.PeerList()),
		})
		s.ipcWriteManagedOK(conn, reqID, data)

	case SubManagedPolicy:
		// Sub-sub-command: [0x00=get][2-byte netID] or [0x01=set][2-byte netID][policy JSON...]
		if len(rest) < 3 {
			s.sendError(conn, reqID, "managed policy: missing sub-sub-command and network_id")
			return
		}
		action := rest[0]
		netID := binary.BigEndian.Uint16(rest[1:3])

		switch action {
		case 0x00: // get
			pr := s.daemon.GetPolicyRunner(netID)
			resp := map[string]interface{}{
				"type":       "managed_policy_ok",
				"network_id": netID,
			}
			if pr != nil {
				policyData, _ := pr.PolicyJSON()
				resp["expr_policy"] = json.RawMessage(policyData)
				resp["engine"] = "policy"
			} else if me := s.daemon.GetManagedEngine(netID); me != nil {
				resp["engine"] = "managed"
			} else {
				resp["engine"] = "none"
			}
			data, _ := json.Marshal(resp)
			s.ipcWriteManagedOK(conn, reqID, data)
		case 0x01: // set — reload policy from registry
			policyJSON := rest[3:]
			if len(policyJSON) == 0 {
				s.sendError(conn, reqID, "managed policy set: missing policy JSON")
				return
			}
			if err := s.daemon.StartPolicyRunner(netID, policyJSON); err != nil {
				s.sendError(conn, reqID, fmt.Sprintf("managed policy set: %v", err))
				return
			}
			data, _ := json.Marshal(map[string]interface{}{
				"type":       "managed_policy_ok",
				"network_id": netID,
				"applied":    true,
			})
			s.ipcWriteManagedOK(conn, reqID, data)
		default:
			s.sendError(conn, reqID, fmt.Sprintf("managed policy: unknown action 0x%02X", action))
		}

	case SubManagedMemberTags:
		// Sub-sub-command: [0x00=get][2-byte netID][4-byte nodeID] or [0x01=set][2-byte netID][4-byte nodeID][tags JSON...]
		if len(rest) < 7 {
			s.sendError(conn, reqID, "managed member-tags: missing action, network_id, or node_id")
			return
		}
		action := rest[0]
		tagNetID := binary.BigEndian.Uint16(rest[1:3])
		targetNodeID := binary.BigEndian.Uint32(rest[3:7])

		switch action {
		case 0x00: // get
			resp, err := s.daemon.regConn.GetMemberTags(tagNetID, targetNodeID)
			if err != nil {
				s.sendError(conn, reqID, fmt.Sprintf("member-tags get: %v", err))
				return
			}
			data, _ := json.Marshal(resp)
			s.ipcWriteManagedOK(conn, reqID, data)
		case 0x01: // set
			if len(rest) < 8 {
				s.sendError(conn, reqID, "managed member-tags set: missing tags JSON")
				return
			}
			var tags []string
			if err := json.Unmarshal(rest[7:], &tags); err != nil {
				s.sendError(conn, reqID, fmt.Sprintf("member-tags set: invalid tags JSON: %v", err))
				return
			}
			resp, err := s.daemon.regConn.SetMemberTags(tagNetID, targetNodeID, tags, s.daemon.config.AdminToken)
			if err != nil {
				s.sendError(conn, reqID, fmt.Sprintf("member-tags set: %v", err))
				return
			}
			data, _ := json.Marshal(resp)
			s.ipcWriteManagedOK(conn, reqID, data)
		default:
			s.sendError(conn, reqID, fmt.Sprintf("managed member-tags: unknown action 0x%02X", action))
		}

	default:
		s.sendError(conn, reqID, fmt.Sprintf("managed: unknown sub-command 0x%02X", sub))
	}
}

func (s *IPCServer) ipcWriteManagedOK(conn *ipcConn, reqID uint64, data []byte) {
	if err := conn.writeReply(CmdManagedOK, reqID, data); err != nil {
		slog.Debug("IPC managed reply failed", "err", err)
	}
}

// findManagedEngine returns the engine for a specific network, or the first
// engine if netID is 0.
func (s *IPCServer) findManagedEngine(netID uint16) *ManagedEngine {
	if netID != 0 {
		return s.daemon.GetManagedEngine(netID)
	}
	// Return first engine
	s.daemon.managedMu.Lock()
	defer s.daemon.managedMu.Unlock()
	for _, me := range s.daemon.managed {
		return me
	}
	return nil
}

// findPolicyRunner returns the policy runner for a specific network, or the
// first runner if netID is 0. Delegates to the registered policy manager.
func (s *IPCServer) findPolicyRunner(netID uint16) PolicyRunner {
	if netID != 0 {
		return s.daemon.GetPolicyRunner(netID)
	}
	if s.daemon.policyManager == nil {
		return nil
	}
	all := s.daemon.policyManager.All()
	if len(all) == 0 {
		return nil
	}
	return all[0]
}
