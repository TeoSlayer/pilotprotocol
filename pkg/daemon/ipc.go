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
	"runtime/debug"
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
	CmdSetTaskExec       byte = 0x1D
	CmdSetTaskExecOK     byte = 0x1E
	CmdNetwork           byte = 0x1F
	CmdNetworkOK         byte = 0x20
	CmdHealth            byte = 0x21
	CmdHealthOK          byte = 0x22
	CmdManaged           byte = 0x23
	CmdManagedOK         byte = 0x24
	CmdRotateKey         byte = 0x25
	CmdRotateKeyOK       byte = 0x26
	CmdMyPolo            byte = 0x27
	CmdMyPoloOK          byte = 0x28
	CmdBroadcast         byte = 0x29
	CmdBroadcastOK       byte = 0x2A
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
	SubManagedScore      byte = 0x01
	SubManagedStatus     byte = 0x02
	SubManagedRankings   byte = 0x03
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
// Concurrency model:
//   - sendCh has capacity ipcSendBuffer (256). Producers (handleBind,
//     handleHealth, etc.) push to it via ipcWrite.
//   - A single writer goroutine drains sendCh in order. Per-client message
//     ordering is preserved (the same guarantee the old mutex provided).
//   - If sendCh is full, ipcWrite blocks up to ipcWriteBackpressureTimeout
//     (100ms) then returns ErrIPCBackpressure rather than waiting forever.
//     Callers already handle write errors by dropping the conn.
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

	// dialCancels holds cancel funcs for in-flight DialConnection
	// goroutines this client started. On Close() we fire them all so
	// the daemon's dial loops bail out immediately instead of grinding
	// to their full retry budget (~14-31 s) leaving orphan SYN_SENT
	// entries behind. Tied to ipcConn lifetime; no separate plumbing.
	dialCancels []context.CancelFunc
}

// ipcSendBuffer is the per-conn outbound channel capacity. 256 is large
// enough to absorb a transient burst (binds + first packet replays) while
// small enough to keep memory bounded across MaxIPCClients (1024 × 256 ×
// avg 256B/msg ≈ 64 MB worst case).
const ipcSendBuffer = 256

// ipcWriteBackpressureTimeout caps how long ipcWrite waits to enqueue when
// the buffer is full. After this elapses the client gets ErrIPCBackpressure
// — signaling the daemon that this client cannot keep up; callers close
// the conn rather than wait forever (which is what the synchronous mutex
// effectively did).
const ipcWriteBackpressureTimeout = 100 * time.Millisecond

// ErrIPCBackpressure is returned when ipcWrite cannot enqueue within
// ipcWriteBackpressureTimeout. Indicates a stuck or too-slow IPC client.
var ErrIPCBackpressure = errors.New("ipc: backpressure (client too slow)")

// ErrIPCClosed is returned when ipcWrite is called after Close.
var ErrIPCClosed = errors.New("ipc: connection closed")

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
		Conn:      c,
		sendCh:    make(chan []byte, ipcSendBuffer),
		done:      make(chan struct{}),
		writeDone: make(chan struct{}),
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
//   - ErrIPCBackpressure if the buffer stays full for
//     ipcWriteBackpressureTimeout
func (c *ipcConn) ipcWrite(data []byte) error {
	// Fast-fail if already closed — avoids allocating a timer below.
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
	// Slow path: backpressure timer.
	timer := time.NewTimer(ipcWriteBackpressureTimeout)
	defer timer.Stop()
	select {
	case c.sendCh <- data:
		return nil
	case <-c.done:
		return ErrIPCClosed
	case <-timer.C:
		return ErrIPCBackpressure
	}
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
		c.dialCancels = nil
		c.rmu.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
	})
	return nil
}

// addDialCancel registers a context.CancelFunc tied to an in-flight
// DialConnection started by this IPC client. Called from handleDial
// before the dial blocks; the cancel fires on ipcConn.Close().
func (c *ipcConn) addDialCancel(cancel context.CancelFunc) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.dialCancels = append(c.dialCancels, cancel)
}

// dialCancelCount returns the number of entries in dialCancels (for testing).
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
	// Outermost defer: swallow panics so a buggy IPC handler doesn't kill
	// the daemon. The other deferred cleanup (ports/conns/registry) still
	// runs first because defers are LIFO.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("IPC handler panic recovered",
				"recover", r,
				"stack", string(debug.Stack()))
		}
	}()
	defer func() {
		// Clean up ports and connections owned by this client
		conn.rmu.Lock()
		ports := conn.ports
		conns := conn.conns
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

	for {
		msg, err := ipcutil.Read(conn)
		if err != nil {
			if err != io.EOF {
				slog.Error("IPC read error", "error", err)
			}
			return
		}
		if len(msg) < 1 {
			continue
		}

		cmd := msg[0]
		payload := msg[1:]

		switch cmd {
		case CmdBind:
			s.handleBind(conn, payload)
		case CmdDial:
			s.handleDial(conn, payload)
		case CmdSend:
			s.handleSend(conn, payload)
		case CmdClose:
			s.handleClose(conn, payload)
		case CmdSendTo:
			s.handleSendTo(conn, payload)
		case CmdBroadcast:
			s.handleBroadcast(conn, payload)
		case CmdInfo:
			s.handleInfo(conn)
		case CmdMyPolo:
			s.handleMyPolo(conn)
		case CmdHandshake:
			s.handleHandshake(conn, payload)
		case CmdResolveHostname:
			s.handleResolveHostname(conn, payload)
		case CmdSetHostname:
			s.handleSetHostname(conn, payload)
		case CmdSetVisibility:
			s.handleSetVisibility(conn, payload)
		case CmdDeregister:
			s.handleDeregister(conn)
		case CmdSetTags:
			s.handleSetTags(conn, payload)
		case CmdSetWebhook:
			s.handleSetWebhook(conn, payload)
		case CmdSetTaskExec:
			s.handleSetTaskExec(conn, payload)
		case CmdNetwork:
			s.handleNetwork(conn, payload)
		case CmdHealth:
			s.handleHealth(conn)
		case CmdManaged:
			s.handleManaged(conn, payload)
		case CmdRotateKey:
			s.handleRotateKey(conn)
		default:
			s.sendError(conn, fmt.Sprintf("unknown command: 0x%02X", cmd))
		}
	}
}

func (s *IPCServer) handleBind(conn *ipcConn, payload []byte) {
	if len(payload) < 2 {
		s.sendError(conn, "bind: missing port")
		return
	}
	port := binary.BigEndian.Uint16(payload[0:2])

	ln, err := s.daemon.ports.Bind(port)
	if err != nil {
		s.sendError(conn, err.Error())
		return
	}

	conn.trackPort(port)

	// Send bind OK
	resp := make([]byte, 3)
	resp[0] = CmdBindOK
	binary.BigEndian.PutUint16(resp[1:3], port)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC bind reply failed", "port", port, "err", err)
		return
	}

	// Start pushing accepted connections to this client
	go func() {
		for c := range ln.AcceptCh {
			conn.trackConn(c.ID)
			// H12 fix: include local port for per-port demux
			msg := make([]byte, 1+2+4+protocol.AddrSize+2)
			msg[0] = CmdAccept
			binary.BigEndian.PutUint16(msg[1:3], port)
			binary.BigEndian.PutUint32(msg[3:7], c.ID)
			c.RemoteAddr.MarshalTo(msg, 7)
			binary.BigEndian.PutUint16(msg[7+protocol.AddrSize:], c.RemotePort)
			if err := conn.ipcWrite(msg); err != nil {
				slog.Debug("IPC accept notify failed", "conn_id", c.ID, "err", err)
				return
			}

			s.startRecvPusher(conn, c)
		}
	}()
}

func (s *IPCServer) handleDial(conn *ipcConn, payload []byte) {
	if len(payload) < protocol.AddrSize+2 {
		s.sendError(conn, "dial: missing address/port")
		return
	}

	// P2-002: reject dial if this client already owns MaxConnsPerIPCClient
	// connections. Avoids the single-client DoS where one buggy driver
	// exhausts the global connection table.
	if n := conn.connCount(); n >= MaxConnsPerIPCClient {
		s.sendError(conn, fmt.Sprintf("dial: per-client connection quota (%d) reached", MaxConnsPerIPCClient))
		return
	}

	dstAddr := protocol.UnmarshalAddr(payload[0:protocol.AddrSize])
	dstPort := binary.BigEndian.Uint16(payload[protocol.AddrSize:])

	// Per-dial cancellable context tied to this IPC connection's lifetime.
	// When the IPC client closes (Ctrl+C, crash), ipcConn.Close fires this
	// cancel and the dial loop exits inside its select instead of grinding
	// through the full 14-31 s retry budget leaving an orphaned SYN_SENT.
	dialCtx, dialCancel := context.WithCancel(context.Background())
	conn.addDialCancel(dialCancel)
	defer dialCancel() // also fires on normal completion

	c, err := s.daemon.DialConnectionContext(dialCtx, dstAddr, dstPort)
	if err != nil {
		s.sendError(conn, err.Error())
		return
	}

	conn.trackConn(c.ID)

	// Send dial OK
	resp := make([]byte, 5)
	resp[0] = CmdDialOK
	binary.BigEndian.PutUint32(resp[1:5], c.ID)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC dial reply failed", "conn_id", c.ID, "err", err)
		return
	}

	s.startRecvPusher(conn, c)
}

func (s *IPCServer) handleSend(conn *ipcConn, payload []byte) {
	if len(payload) < 4 {
		s.sendError(conn, "send: missing conn_id")
		return
	}
	connID := binary.BigEndian.Uint32(payload[0:4])
	data := payload[4:]

	c := s.daemon.ports.GetConnection(connID)
	if c == nil {
		s.sendError(conn, fmt.Sprintf("connection %d not found", connID))
		return
	}

	if err := s.daemon.SendData(c, data); err != nil {
		s.sendError(conn, fmt.Sprintf("send: %v", err))
	}
}

func (s *IPCServer) handleClose(conn *ipcConn, payload []byte) {
	if len(payload) < 4 {
		s.sendError(conn, "close: missing conn_id")
		return
	}
	connID := binary.BigEndian.Uint32(payload[0:4])

	c := s.daemon.ports.GetConnection(connID)
	if c != nil {
		s.daemon.CloseConnection(c)
	}
	conn.removeConn(connID)

	resp := make([]byte, 5)
	resp[0] = CmdCloseOK
	binary.BigEndian.PutUint32(resp[1:5], connID)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC close reply failed", "conn_id", connID, "err", err)
	}
}

func (s *IPCServer) handleSendTo(conn *ipcConn, payload []byte) {
	if len(payload) < protocol.AddrSize+2 {
		s.sendError(conn, "sendto: missing address/port")
		return
	}

	dstAddr := protocol.UnmarshalAddr(payload[0:protocol.AddrSize])
	dstPort := binary.BigEndian.Uint16(payload[protocol.AddrSize : protocol.AddrSize+2])
	data := payload[protocol.AddrSize+2:]

	if err := s.daemon.SendDatagram(dstAddr, dstPort, data); err != nil {
		s.sendError(conn, fmt.Sprintf("sendto: %v", err))
	}
}

// handleBroadcast services CmdBroadcast — admin-token-gated fan-out to a
// whole network. Wire payload:
//
//	[netID(2)][dstPort(2)][tokenLen(2)][token...][data...]
//
// On success, replies with CmdBroadcastOK (no body). On failure, replies
// with CmdError carrying the daemon error message — typically "daemon has
// no admin token configured" or "invalid admin token".
func (s *IPCServer) handleBroadcast(conn *ipcConn, payload []byte) {
	if len(payload) < 6 {
		s.sendError(conn, "broadcast: missing header")
		return
	}
	netID := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	tokenLen := binary.BigEndian.Uint16(payload[4:6])
	if len(payload) < 6+int(tokenLen) {
		s.sendError(conn, "broadcast: truncated token")
		return
	}
	token := string(payload[6 : 6+tokenLen])
	data := payload[6+tokenLen:]

	if err := s.daemon.BroadcastDatagram(netID, dstPort, data, token); err != nil {
		s.sendError(conn, fmt.Sprintf("broadcast: %v", err))
		return
	}
	if err := conn.ipcWrite([]byte{CmdBroadcastOK}); err != nil {
		slog.Debug("IPC broadcast reply failed", "err", err)
	}
}

// handleMyPolo asks the registry for this daemon's own polo score.
// Polo is private — only self-read is permitted, and the request is
// signed by regConn so the registry can verify ownership.
func (s *IPCServer) handleMyPolo(conn *ipcConn) {
	if s.daemon.regConn == nil {
		s.sendError(conn, "my_polo: registry not available")
		return
	}
	score, err := s.daemon.regConn.GetPoloScore(s.daemon.NodeID())
	if err != nil {
		s.sendError(conn, fmt.Sprintf("my_polo: %v", err))
		return
	}
	data, _ := json.Marshal(map[string]interface{}{"polo_score": score})
	resp := make([]byte, 1+len(data))
	resp[0] = CmdMyPoloOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC my_polo reply failed", "err", err)
	}
}

func (s *IPCServer) handleInfo(conn *ipcConn) {
	info := s.daemon.Info()

	// Build peer list for JSON
	peers := make([]map[string]interface{}, len(info.PeerList))
	for i, p := range info.PeerList {
		peers[i] = map[string]interface{}{
			"node_id":       p.NodeID,
			"endpoint":      p.Endpoint,
			"encrypted":     p.Encrypted,
			"authenticated": p.Authenticated,
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
	})
	if err != nil {
		s.sendError(conn, fmt.Sprintf("info marshal: %v", err))
		return
	}
	resp := make([]byte, 1+len(data))
	resp[0] = CmdInfoOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC info reply failed", "err", err)
	}
}

func (s *IPCServer) handleHealth(conn *ipcConn) {
	info := s.daemon.Info()
	data, err := json.Marshal(map[string]interface{}{
		"status":         "ok",
		"uptime_seconds": int64(info.Uptime.Seconds()),
		"connections":    info.Connections,
		"peers":          info.Peers,
		"bytes_sent":     info.BytesSent,
		"bytes_recv":     info.BytesRecv,
	})
	if err != nil {
		s.sendError(conn, fmt.Sprintf("health marshal: %v", err))
		return
	}
	resp := make([]byte, 1+len(data))
	resp[0] = CmdHealthOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC health reply failed", "err", err)
	}
}

func (s *IPCServer) handleResolveHostname(conn *ipcConn, payload []byte) {
	hostname := string(payload)
	if hostname == "" {
		s.sendError(conn, "resolve_hostname: missing hostname")
		return
	}

	result, err := s.daemon.regConn.ResolveHostname(hostname)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("resolve_hostname: %v", err))
		return
	}

	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("resolve_hostname marshal: %v", err))
		return
	}

	resp := make([]byte, 1+len(data))
	resp[0] = CmdResolveHostnameOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC resolve_hostname reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetHostname(conn *ipcConn, payload []byte) {
	hostname := string(payload)
	result, err := s.daemon.regConn.SetHostname(s.daemon.NodeID(), hostname)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("set_hostname: %v", err))
		return
	}
	// Update daemon's local config so Info() reflects the change
	s.daemon.addrMu.Lock()
	s.daemon.config.Hostname = hostname
	s.daemon.addrMu.Unlock()
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("set_hostname marshal: %v", err))
		return
	}
	resp := make([]byte, 1+len(data))
	resp[0] = CmdSetHostnameOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC set_hostname reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetVisibility(conn *ipcConn, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, "set_visibility: missing value")
		return
	}
	public := payload[0] == 1
	result, err := s.daemon.regConn.SetVisibility(s.daemon.NodeID(), public)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("set_visibility: %v", err))
		return
	}
	// Update daemon's local config so Info() reflects the change
	s.daemon.addrMu.Lock()
	s.daemon.config.Public = public
	s.daemon.addrMu.Unlock()
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("set_visibility marshal: %v", err))
		return
	}
	resp := make([]byte, 1+len(data))
	resp[0] = CmdSetVisibilityOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC set_visibility reply failed", "err", err)
	}
}

func (s *IPCServer) handleDeregister(conn *ipcConn) {
	result, err := s.daemon.regConn.Deregister(s.daemon.NodeID())
	if err != nil {
		s.sendError(conn, fmt.Sprintf("deregister: %v", err))
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("deregister marshal: %v", err))
		return
	}
	resp := make([]byte, 1+len(data))
	resp[0] = CmdDeregisterOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC deregister reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetTags(conn *ipcConn, payload []byte) {
	var tags []string
	if err := json.Unmarshal(payload, &tags); err != nil {
		s.sendError(conn, fmt.Sprintf("set_tags: invalid JSON: %v", err))
		return
	}
	if len(tags) > 3 {
		s.sendError(conn, "set_tags: maximum 3 tags allowed")
		return
	}
	result, err := s.daemon.regConn.SetTags(s.daemon.NodeID(), tags)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("set_tags: %v", err))
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("set_tags marshal: %v", err))
		return
	}
	resp := make([]byte, 1+len(data))
	resp[0] = CmdSetTagsOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC set_tags reply failed", "err", err)
	}
}

func (s *IPCServer) handleRotateKey(conn *ipcConn) {
	result, err := s.daemon.RotateKey()
	if err != nil {
		s.sendError(conn, err.Error())
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("rotate_key marshal: %v", err))
		return
	}
	resp := make([]byte, 1+len(data))
	resp[0] = CmdRotateKeyOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC rotate_key reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetWebhook(conn *ipcConn, payload []byte) {
	url := string(payload) // empty string = clear webhook
	if url != "" {
		if err := ValidateWebhookURL(url); err != nil {
			s.sendError(conn, err.Error())
			return
		}
	}
	s.daemon.SetWebhookURL(url)
	result := map[string]interface{}{"webhook": url}
	data, _ := json.Marshal(result)
	resp := make([]byte, 1+len(data))
	resp[0] = CmdSetWebhookOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC set_webhook reply failed", "err", err)
	}
}

func (s *IPCServer) handleSetTaskExec(conn *ipcConn, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, "set_task_exec: missing value")
		return
	}
	enabled := payload[0] == 1
	result, err := s.daemon.regConn.SetTaskExec(s.daemon.NodeID(), enabled)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("set_task_exec: %v", err))
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.sendError(conn, fmt.Sprintf("set_task_exec marshal: %v", err))
		return
	}
	resp := make([]byte, 1+len(data))
	resp[0] = CmdSetTaskExecOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC set_task_exec reply failed", "err", err)
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
)

func (s *IPCServer) handleHandshake(conn *ipcConn, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, "handshake: missing sub-command")
		return
	}
	sub := payload[0]
	rest := payload[1:]

	switch sub {
	case SubHandshakeSend:
		if len(rest) < 4 {
			s.sendError(conn, "handshake request: missing node_id")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		justification := ""
		if len(rest) > 4 {
			justification = string(rest[4:])
		}
		if err := s.daemon.handshakes.SendRequest(nodeID, justification); err != nil {
			s.sendError(conn, fmt.Sprintf("handshake request: %v", err))
			return
		}
		data, _ := json.Marshal(map[string]interface{}{
			"status":  "sent",
			"node_id": nodeID,
		})
		s.ipcWriteHandshakeOK(conn, data)

	case SubHandshakeApprove:
		if len(rest) < 4 {
			s.sendError(conn, "handshake approve: missing node_id")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		if err := s.daemon.handshakes.ApproveHandshake(nodeID); err != nil {
			s.sendError(conn, fmt.Sprintf("handshake approve: %v", err))
			return
		}
		data, _ := json.Marshal(map[string]interface{}{
			"status":  "approved",
			"node_id": nodeID,
		})
		s.ipcWriteHandshakeOK(conn, data)

	case SubHandshakeReject:
		if len(rest) < 4 {
			s.sendError(conn, "handshake reject: missing node_id")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		reason := ""
		if len(rest) > 4 {
			reason = string(rest[4:])
		}
		if err := s.daemon.handshakes.RejectHandshake(nodeID, reason); err != nil {
			s.sendError(conn, fmt.Sprintf("handshake reject: %v", err))
			return
		}
		data, _ := json.Marshal(map[string]interface{}{
			"status":  "rejected",
			"node_id": nodeID,
		})
		s.ipcWriteHandshakeOK(conn, data)

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
		s.ipcWriteHandshakeOK(conn, data)

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
		s.ipcWriteHandshakeOK(conn, data)

	case SubHandshakeRevoke:
		if len(rest) < 4 {
			s.sendError(conn, "handshake revoke: missing node_id")
			return
		}
		nodeID := binary.BigEndian.Uint32(rest[0:4])
		if err := s.daemon.handshakes.RevokeTrust(nodeID); err != nil {
			s.sendError(conn, fmt.Sprintf("handshake revoke: %v", err))
			return
		}
		data, _ := json.Marshal(map[string]interface{}{
			"status":  "revoked",
			"node_id": nodeID,
		})
		s.ipcWriteHandshakeOK(conn, data)

	default:
		s.sendError(conn, fmt.Sprintf("handshake: unknown sub-command 0x%02X", sub))
	}
}

func (s *IPCServer) ipcWriteHandshakeOK(conn *ipcConn, data []byte) {
	resp := make([]byte, 1+len(data))
	resp[0] = CmdHandshakeOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC handshake reply failed", "err", err)
	}
}

func (s *IPCServer) ipcWriteNetworkOK(conn *ipcConn, data []byte) {
	resp := make([]byte, 1+len(data))
	resp[0] = CmdNetworkOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
		slog.Debug("IPC network reply failed", "err", err)
	}
}

func (s *IPCServer) handleNetwork(conn *ipcConn, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, "network: missing sub-command")
		return
	}
	sub := payload[0]
	rest := payload[1:]

	switch sub {
	case SubNetworkList:
		result, err := s.daemon.regConn.ListNetworks()
		if err != nil {
			s.sendError(conn, fmt.Sprintf("network list: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, data)

	case SubNetworkJoin:
		// [2-byte networkID][token...]
		if len(rest) < 2 {
			s.sendError(conn, "network join: missing network_id")
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
			s.sendError(conn, fmt.Sprintf("network join: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, data)
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
			s.sendError(conn, "network leave: missing network_id")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		result, err := s.daemon.regConn.LeaveNetwork(
			s.daemon.NodeID(), netID, s.daemon.config.AdminToken,
		)
		if err != nil {
			s.sendError(conn, fmt.Sprintf("network leave: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, data)

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
			s.sendError(conn, "network members: missing network_id")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		result, err := s.daemon.regConn.ListNodes(netID, s.daemon.config.AdminToken)
		if err != nil {
			s.sendError(conn, fmt.Sprintf("network members: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, data)

	case SubNetworkInvite:
		// [2-byte networkID][4-byte targetNodeID]
		if len(rest) < 6 {
			s.sendError(conn, "network invite: missing network_id or target_node_id")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		targetID := binary.BigEndian.Uint32(rest[2:6])
		result, err := s.daemon.regConn.InviteToNetwork(
			netID, s.daemon.NodeID(), targetID, s.daemon.config.AdminToken,
		)
		if err != nil {
			s.sendError(conn, fmt.Sprintf("network invite: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, data)

	case SubNetworkPollInvites:
		result, err := s.daemon.regConn.PollInvites(s.daemon.NodeID())
		if err != nil {
			s.sendError(conn, fmt.Sprintf("network poll-invites: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, data)

	case SubNetworkRespondInvite:
		// [2-byte networkID][1-byte accept]
		if len(rest) < 3 {
			s.sendError(conn, "network respond-invite: missing network_id or accept flag")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		accept := rest[2] == 1
		result, err := s.daemon.regConn.RespondInvite(
			s.daemon.NodeID(), netID, accept,
		)
		if err != nil {
			s.sendError(conn, fmt.Sprintf("network respond-invite: %v", err))
			return
		}
		data, _ := json.Marshal(result)
		s.ipcWriteNetworkOK(conn, data)

	default:
		s.sendError(conn, fmt.Sprintf("network: unknown sub-command 0x%02X", sub))
	}
}

// startRecvPusher drains c.RecvBuf and pushes data to the IPC client.
// When RecvBuf closes (remote FIN), it sends CmdCloseOK to the driver.
func (s *IPCServer) startRecvPusher(conn *ipcConn, c *Connection) {
	go func() {
		for data := range c.RecvBuf {
			msg := make([]byte, 1+4+len(data))
			msg[0] = CmdRecv
			binary.BigEndian.PutUint32(msg[1:5], c.ID)
			copy(msg[5:], data)
			if err := conn.ipcWrite(msg); err != nil {
				slog.Debug("IPC recv push failed", "conn_id", c.ID, "err", err)
				conn.removeConn(c.ID)
				return
			}
		}
		closeMsg := make([]byte, 5)
		closeMsg[0] = CmdCloseOK
		binary.BigEndian.PutUint32(closeMsg[1:5], c.ID)
		if err := conn.ipcWrite(closeMsg); err != nil {
			slog.Debug("IPC close notify failed", "conn_id", c.ID, "err", err)
		}
		conn.removeConn(c.ID)
	}()
}

func (s *IPCServer) sendError(conn *ipcConn, msg string) {
	resp := make([]byte, 1+2+len(msg))
	resp[0] = CmdError
	binary.BigEndian.PutUint16(resp[1:3], 1) // generic error code
	copy(resp[3:], msg)
	if err := conn.ipcWrite(resp); err != nil {
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

	// Send RecvFrom to all connected clients (the driver filters by port)
	msg := make([]byte, 1+protocol.AddrSize+2+2+len(data))
	msg[0] = CmdRecvFrom
	srcAddr.MarshalTo(msg, 1)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize:], srcPort)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize+2:], dstPort)
	copy(msg[1+protocol.AddrSize+4:], data)

	// P2-004: fan out writes to each client in a dedicated goroutine so a
	// slow IPC peer can't wedge routeLoop for every other peer. ipcWrite
	// already serializes per-connection via wmu, so concurrency is safe.
	for _, conn := range clients {
		conn := conn
		go func() {
			if err := conn.ipcWrite(msg); err != nil {
				slog.Debug("IPC datagram delivery failed", "err", err)
			}
		}()
	}
}

func (s *IPCServer) handleManaged(conn *ipcConn, payload []byte) {
	if len(payload) < 1 {
		s.sendError(conn, "managed: missing sub-command")
		return
	}
	sub := payload[0]
	rest := payload[1:]

	switch sub {
	case SubManagedScore:
		// [2-byte netID][4-byte nodeID][4-byte delta (int32)][topic...]
		if len(rest) < 10 {
			s.sendError(conn, "managed score: missing fields (need netID + nodeID + delta)")
			return
		}
		netID := binary.BigEndian.Uint16(rest[0:2])
		nodeID := binary.BigEndian.Uint32(rest[2:6])
		delta := int(int32(binary.BigEndian.Uint32(rest[6:10])))
		topic := ""
		if len(rest) > 10 {
			topic = string(rest[10:])
		}

		// Prefer the PolicyRunner when present — a manual score increment
		// should land in the same store the policy engine reads from
		// (see SubManagedRankings comment).
		if pr := s.daemon.GetPolicyRunner(netID); pr != nil {
			if err := pr.Score(nodeID, delta, topic); err != nil {
				s.sendError(conn, fmt.Sprintf("managed score: %v", err))
				return
			}
		} else if me := s.daemon.GetManagedEngine(netID); me != nil {
			if err := me.Score(nodeID, delta, topic); err != nil {
				s.sendError(conn, fmt.Sprintf("managed score: %v", err))
				return
			}
		} else {
			s.sendError(conn, fmt.Sprintf("managed: no engine for network %d", netID))
			return
		}

		data, _ := json.Marshal(map[string]interface{}{
			"type":    "managed_score_ok",
			"node_id": nodeID,
			"delta":   delta,
			"topic":   topic,
		})
		s.ipcWriteManagedOK(conn, data)

	case SubManagedStatus:
		// [2-byte netID] (optional — 0 means first/only engine)
		netID := uint16(0)
		if len(rest) >= 2 {
			netID = binary.BigEndian.Uint16(rest[0:2])
		}

		if pr := s.findPolicyRunner(netID); pr != nil {
			data, _ := json.Marshal(pr.Status())
			s.ipcWriteManagedOK(conn, data)
		} else if me := s.findManagedEngine(netID); me != nil {
			data, _ := json.Marshal(me.Status())
			s.ipcWriteManagedOK(conn, data)
		} else {
			s.sendError(conn, "managed: no active managed networks")
		}

	case SubManagedRankings:
		// [2-byte netID] (optional)
		netID := uint16(0)
		if len(rest) >= 2 {
			netID = binary.BigEndian.Uint16(rest[0:2])
		}

		// Prefer the PolicyRunner when present: when both a policy and
		// rules are attached to a network, the policy drives per-peer
		// scoring (executeScore on connect/dial/datagram), so the
		// runner's peer state is authoritative. ManagedEngine.peers only
		// gets scored via manual `pilotctl managed score` and would
		// otherwise shadow the live policy-driven view with stale zeros.
		var rankings []map[string]interface{}
		if pr := s.findPolicyRunner(netID); pr != nil {
			rankings = pr.Rankings()
		} else if me := s.findManagedEngine(netID); me != nil {
			rankings = me.Rankings()
		} else {
			s.sendError(conn, "managed: no active managed networks")
			return
		}

		data, _ := json.Marshal(map[string]interface{}{
			"type":     "managed_rankings_ok",
			"rankings": rankings,
		})
		s.ipcWriteManagedOK(conn, data)

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
			s.sendError(conn, "managed: no active managed networks")
			return
		}

		data, _ := json.Marshal(result)
		s.ipcWriteManagedOK(conn, data)

	case SubManagedReconcile:
		// [2-byte netID]. Poll the registry for the network's member list
		// and refresh the runner's peer set — without running a policy
		// cycle (no score/evict side effects). This is useful for tests
		// and operators who want a clean "my peer view matches the
		// registry" primitive.
		netID := uint16(0)
		if len(rest) >= 2 {
			netID = binary.BigEndian.Uint16(rest[0:2])
		}
		pr := s.findPolicyRunner(netID)
		if pr == nil {
			s.sendError(conn, "managed: no active policy runner for network")
			return
		}
		pr.ReconcileNow()
		data, _ := json.Marshal(map[string]interface{}{
			"type":       "managed_reconcile_ok",
			"network_id": netID,
			"peers":      len(pr.Rankings()),
		})
		s.ipcWriteManagedOK(conn, data)

	case SubManagedPolicy:
		// Sub-sub-command: [0x00=get][2-byte netID] or [0x01=set][2-byte netID][policy JSON...]
		if len(rest) < 3 {
			s.sendError(conn, "managed policy: missing sub-sub-command and network_id")
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
				policyData, _ := json.Marshal(pr.Policy().Doc)
				resp["expr_policy"] = json.RawMessage(policyData)
				resp["engine"] = "policy"
			} else if me := s.daemon.GetManagedEngine(netID); me != nil {
				resp["engine"] = "managed"
			} else {
				resp["engine"] = "none"
			}
			data, _ := json.Marshal(resp)
			s.ipcWriteManagedOK(conn, data)
		case 0x01: // set — reload policy from registry
			policyJSON := rest[3:]
			if len(policyJSON) == 0 {
				s.sendError(conn, "managed policy set: missing policy JSON")
				return
			}
			if err := s.daemon.StartPolicyRunner(netID, policyJSON); err != nil {
				s.sendError(conn, fmt.Sprintf("managed policy set: %v", err))
				return
			}
			data, _ := json.Marshal(map[string]interface{}{
				"type":       "managed_policy_ok",
				"network_id": netID,
				"applied":    true,
			})
			s.ipcWriteManagedOK(conn, data)
		default:
			s.sendError(conn, fmt.Sprintf("managed policy: unknown action 0x%02X", action))
		}

	case SubManagedMemberTags:
		// Sub-sub-command: [0x00=get][2-byte netID][4-byte nodeID] or [0x01=set][2-byte netID][4-byte nodeID][tags JSON...]
		if len(rest) < 7 {
			s.sendError(conn, "managed member-tags: missing action, network_id, or node_id")
			return
		}
		action := rest[0]
		tagNetID := binary.BigEndian.Uint16(rest[1:3])
		targetNodeID := binary.BigEndian.Uint32(rest[3:7])

		switch action {
		case 0x00: // get
			resp, err := s.daemon.regConn.GetMemberTags(tagNetID, targetNodeID)
			if err != nil {
				s.sendError(conn, fmt.Sprintf("member-tags get: %v", err))
				return
			}
			data, _ := json.Marshal(resp)
			s.ipcWriteManagedOK(conn, data)
		case 0x01: // set
			if len(rest) < 8 {
				s.sendError(conn, "managed member-tags set: missing tags JSON")
				return
			}
			var tags []string
			if err := json.Unmarshal(rest[7:], &tags); err != nil {
				s.sendError(conn, fmt.Sprintf("member-tags set: invalid tags JSON: %v", err))
				return
			}
			resp, err := s.daemon.regConn.SetMemberTags(tagNetID, targetNodeID, tags, s.daemon.config.AdminToken)
			if err != nil {
				s.sendError(conn, fmt.Sprintf("member-tags set: %v", err))
				return
			}
			data, _ := json.Marshal(resp)
			s.ipcWriteManagedOK(conn, data)
		default:
			s.sendError(conn, fmt.Sprintf("managed member-tags: unknown action 0x%02X", action))
		}

	default:
		s.sendError(conn, fmt.Sprintf("managed: unknown sub-command 0x%02X", sub))
	}
}

func (s *IPCServer) ipcWriteManagedOK(conn *ipcConn, data []byte) {
	resp := make([]byte, 1+len(data))
	resp[0] = CmdManagedOK
	copy(resp[1:], data)
	if err := conn.ipcWrite(resp); err != nil {
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
// first runner if netID is 0.
func (s *IPCServer) findPolicyRunner(netID uint16) *PolicyRunner {
	if netID != 0 {
		return s.daemon.GetPolicyRunner(netID)
	}
	s.daemon.policyMu.Lock()
	defer s.daemon.policyMu.Unlock()
	for _, pr := range s.daemon.policyRunners {
		return pr
	}
	return nil
}
