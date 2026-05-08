// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// IPC commands (must match daemon/ipc.go)
const (
	cmdBind              byte = 0x01
	cmdBindOK            byte = 0x02
	cmdDial              byte = 0x03
	cmdDialOK            byte = 0x04
	cmdAccept            byte = 0x05
	cmdSend              byte = 0x06
	cmdRecv              byte = 0x07
	cmdClose             byte = 0x08
	cmdCloseOK           byte = 0x09
	cmdError             byte = 0x0A
	cmdSendTo            byte = 0x0B
	cmdRecvFrom          byte = 0x0C
	cmdInfo              byte = 0x0D
	cmdInfoOK            byte = 0x0E
	cmdHandshake         byte = 0x0F
	cmdHandshakeOK       byte = 0x10
	cmdResolveHostname   byte = 0x11
	cmdResolveHostnameOK byte = 0x12
	cmdSetHostname       byte = 0x13
	cmdSetHostnameOK     byte = 0x14
	cmdSetVisibility     byte = 0x15
	cmdSetVisibilityOK   byte = 0x16
	cmdDeregister        byte = 0x17
	cmdDeregisterOK      byte = 0x18
	cmdSetTags           byte = 0x19
	cmdSetTagsOK         byte = 0x1A
	cmdSetWebhook        byte = 0x1B
	cmdSetWebhookOK      byte = 0x1C
	cmdNetwork           byte = 0x1F
	cmdNetworkOK         byte = 0x20
	cmdHealth            byte = 0x21
	cmdHealthOK          byte = 0x22
	cmdManaged           byte = 0x23
	cmdManagedOK         byte = 0x24
	cmdRotateKey         byte = 0x25
	cmdRotateKeyOK       byte = 0x26
	cmdBroadcast         byte = 0x29
	cmdBroadcastOK       byte = 0x2A
	cmdCancel            byte = 0x2B // issue #99: tell daemon to abandon a timed-out request
)

// Network sub-commands (must match daemon SubNetwork* constants)
const (
	subNetworkList          byte = 0x01
	subNetworkJoin          byte = 0x02
	subNetworkLeave         byte = 0x03
	subNetworkMembers       byte = 0x04
	subNetworkInvite        byte = 0x05
	subNetworkPollInvites   byte = 0x06
	subNetworkRespondInvite byte = 0x07
)

// Managed sub-commands (must match daemon SubManaged* constants)
const (
	subManagedStatus     byte = 0x02
	subManagedCycle      byte = 0x04
	subManagedPolicy     byte = 0x05
	subManagedMemberTags byte = 0x06
	subManagedReconcile  byte = 0x07
)

// ipcEnvelopeHeaderSize matches daemon.IPCEnvelopeHeaderSize: 1 byte cmd
// + 8 bytes reqID. Issue #99: reqID demultiplexes responses across
// concurrent in-flight requests.
const ipcEnvelopeHeaderSize = 1 + 8

// Datagram represents a received unreliable datagram.
type Datagram struct {
	SrcAddr protocol.Addr
	SrcPort uint16
	DstPort uint16
	Data    []byte
}

// pendingResponse carries the response to a sendAndWait waiter — either
// the cmd-OK payload (ok=true) or the error text from cmdError.
type pendingResponse struct {
	cmd     byte
	payload []byte
}

type ipcClient struct {
	conn net.Conn

	// writeMu serializes ipcutil.Write calls on conn so two goroutines
	// can't interleave a length-prefixed envelope. Held only across the
	// 12-byte header + body write — never during a wait or read. Issue
	// #99: previously the same `mu` covered both the write and the
	// handlers-map mutation, which serialized all driver goroutines on
	// a single conn. The split lets handlers register concurrently.
	writeMu sync.Mutex

	// reqMu protects pending. Held briefly for register/dispatch.
	reqMu   sync.Mutex
	pending map[uint64]chan *pendingResponse // reqID → waiter

	// nextReqID is bumped atomically. We start at 1 so reqID==0 cleanly
	// means "server-pushed unsolicited frame" on the wire.
	nextReqID atomic.Uint64

	recvMu   sync.Mutex
	recvChs  map[uint32]chan []byte // conn_id → data channel
	pendRecv   map[uint32][][]byte // conn_id → buffered data before recvCh registered
	pendAccept map[uint16][][]byte // port → buffered cmdAccept payloads before acceptCh registered (post-#99 race fix)

	acceptMu  sync.Mutex
	acceptChs map[uint16]chan []byte // H12 fix: per-port accept channels

	dgCh   chan *Datagram // incoming datagrams
	doneCh chan struct{}  // closed when readLoop exits

	closeOnce sync.Once
}

func newIPCClient(socketPath string) (*ipcClient, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}

	c := &ipcClient{
		conn:      conn,
		pending:   make(map[uint64]chan *pendingResponse),
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:   make(map[uint32][][]byte),
		pendAccept: make(map[uint16][][]byte),
		acceptChs:  make(map[uint16]chan []byte),
		dgCh:      make(chan *Datagram, 256),
		doneCh:    make(chan struct{}),
	}

	go c.readLoop()
	return c, nil
}

func (c *ipcClient) close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.conn.Close()
	})
	return err
}

// readLoop demultiplexes incoming envelopes. Wire format:
//
//	[uint32-len][uint8-cmd][uint64-reqID][payload...]
//
// reqID==0  → server-pushed unsolicited frame (CmdRecv, CmdAccept,
//             CmdRecvFrom, plus the post-FIN CmdCloseOK from recvPusher).
// reqID!=0 → response to the request that bore the same reqID. The
//            waiter is registered in c.pending; on dispatch it is
//            removed and the channel receives one pendingResponse.
func (c *ipcClient) readLoop() {
	defer c.cleanup()
	for {
		msg, err := ipcutil.Read(c.conn)
		if err != nil {
			return
		}
		if len(msg) < ipcEnvelopeHeaderSize {
			continue
		}

		cmd := msg[0]
		reqID := binary.BigEndian.Uint64(msg[1:9])
		payload := msg[ipcEnvelopeHeaderSize:]

		if reqID == 0 {
			// Server-pushed: route by cmd.
			c.dispatchPush(cmd, payload)
			continue
		}

		// Response to a specific request. Look up the waiter and dispatch
		// exactly once. If no waiter exists (caller timed out or the
		// reqID mismatched), drop silently — this used to be the
		// "silent reply drop" hazard but is now harmless because the
		// waiter has already returned a timeout error.
		c.reqMu.Lock()
		ch, ok := c.pending[reqID]
		if ok {
			delete(c.pending, reqID)
		}
		c.reqMu.Unlock()
		if !ok {
			continue
		}
		// Channel is buffered (capacity 1), so send is non-blocking.
		ch <- &pendingResponse{cmd: cmd, payload: append([]byte(nil), payload...)}
	}
}

// dispatchPush routes server-pushed (reqID==0) frames to their per-cmd
// destination. CmdRecv and CmdCloseOK route by conn ID; CmdAccept by
// listener port; CmdRecvFrom into the global datagram channel.
func (c *ipcClient) dispatchPush(cmd byte, payload []byte) {
	switch cmd {
	case cmdRecv:
		if len(payload) >= 4 {
			connID := binary.BigEndian.Uint32(payload[0:4])
			data := append([]byte(nil), payload[4:]...)
			c.recvMu.Lock()
			ch, ok := c.recvChs[connID]
			if ok {
				c.recvMu.Unlock()
				// Drop the recvMu BEFORE blocking on the channel send
				// so Conn.Close() / unregisterRecvCh can take the lock
				// while readLoop is parked. Without this, a slow Conn
				// holds recvMu indirectly (through readLoop) and other
				// IPC operations stall.
				ch <- data
			} else {
				c.pendRecv[connID] = append(c.pendRecv[connID], data)
				c.recvMu.Unlock()
			}
		}
	case cmdCloseOK:
		// Server-pushed CmdCloseOK fires from recvPusher when the remote
		// FINs. Close the per-conn recv channel so blocked reads see EOF.
		if len(payload) >= 4 {
			connID := binary.BigEndian.Uint32(payload[0:4])
			c.recvMu.Lock()
			ch, ok := c.recvChs[connID]
			if ok {
				delete(c.recvChs, connID)
				close(ch)
			}
			c.recvMu.Unlock()
		}
	case cmdRecvFrom:
		if len(payload) >= protocol.AddrSize+4 {
			srcAddr := protocol.UnmarshalAddr(payload[0:protocol.AddrSize])
			srcPort := binary.BigEndian.Uint16(payload[protocol.AddrSize:])
			dstPort := binary.BigEndian.Uint16(payload[protocol.AddrSize+2:])
			data := append([]byte(nil), payload[protocol.AddrSize+4:]...)
			select {
			case c.dgCh <- &Datagram{SrcAddr: srcAddr, SrcPort: srcPort, DstPort: dstPort, Data: data}:
			default:
			}
		}
	case cmdAccept:
		if len(payload) >= 2 {
			port := binary.BigEndian.Uint16(payload[0:2])
			rest := append([]byte(nil), payload[2:]...)
			c.acceptMu.Lock()
			ch, ok := c.acceptChs[port]
			if ok {
				c.acceptMu.Unlock()
				select {
				case ch <- rest:
				default:
				}
			} else {
				// Buffer until registerAcceptCh is called. The race
				// (post-#99): with concurrent daemon dispatch, the
				// daemon can push cmdAccept BEFORE the driver registers
				// acceptChs[port] — Listen() registers AFTER the
				// cmdBind reply, but a peer's dial can race the bind
				// reply through different worker goroutines on the
				// daemon side. Same pattern as pendRecv for cmdRecv.
				c.pendAccept[port] = append(c.pendAccept[port], rest)
				c.acceptMu.Unlock()
			}
		}
	default:
		// Unknown unsolicited cmd — drop. The daemon should never send
		// reqID=0 with a cmd outside this set; if a test or future
		// addition does, dropping is the safe default.
	}
}

// cleanup closes all pending channels when readLoop exits (daemon disconnect).
func (c *ipcClient) cleanup() {
	close(c.doneCh)

	// Fail every in-flight waiter with daemon-disconnected.
	c.reqMu.Lock()
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.reqMu.Unlock()

	// Close all receive channels
	c.recvMu.Lock()
	for id, ch := range c.recvChs {
		close(ch)
		delete(c.recvChs, id)
	}
	c.recvMu.Unlock()

	// Close all accept channels (H12 fix)
	c.acceptMu.Lock()
	for port, ch := range c.acceptChs {
		close(ch)
		delete(c.acceptChs, port)
	}
	c.acceptMu.Unlock()
}

// writeFrame builds a `[cmd][reqID(8)][body...]` envelope and writes it
// under writeMu so multiple goroutines don't interleave bytes.
func (c *ipcClient) writeFrame(cmd byte, reqID uint64, body []byte) error {
	buf := make([]byte, ipcEnvelopeHeaderSize+len(body))
	buf[0] = cmd
	binary.BigEndian.PutUint64(buf[1:9], reqID)
	copy(buf[9:], body)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return ipcutil.Write(c.conn, buf)
}

// send is a fire-and-forget request — used for cmdSend and cmdSendTo
// where the daemon doesn't reply on success. We still allocate a reqID
// so the daemon's error path (sendError) can echo it back; the driver
// just doesn't wait for the (non-existent) success reply.
//
// data is the full message body the caller built: `[cmd][body...]`.
// We split off the cmd byte and prepend a fresh reqID via writeFrame.
func (c *ipcClient) send(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("ipc: empty message")
	}
	return c.writeFrame(data[0], c.nextReqID.Add(1), data[1:])
}

// sendAndWait sends a request and waits for the matching reply.
// expectCmd is checked against the dispatched response cmd; mismatch
// (e.g. cmdError) returns a daemon-formatted error. Per issue #99,
// every in-flight request has its own reqID and waiter channel, so
// concurrent calls do not stomp on each other.
func (c *ipcClient) sendAndWait(data []byte, expectCmd byte) ([]byte, error) {
	return c.sendAndWaitTimeout(data, expectCmd, 0)
}

// sendAndWaitTimeout is the canonical entry point. timeout=0 means
// "wait forever" (until daemon disconnect); positive timeout caps the
// wait and returns "dial timeout" if the daemon doesn't respond.
//
// Note: caller-supplied data starts with the cmd byte: `[cmd][body...]`.
// We allocate a fresh reqID, register the waiter, then writeFrame the
// envelope. The waiter unregisters itself on every exit path so a
// timed-out/cancelled request doesn't leak a slot in the pending map.
func (c *ipcClient) sendAndWaitTimeout(data []byte, expectCmd byte, timeout time.Duration) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("ipc: empty request")
	}
	reqID := c.nextReqID.Add(1)
	ch := make(chan *pendingResponse, 1)

	c.reqMu.Lock()
	c.pending[reqID] = ch
	c.reqMu.Unlock()

	// Cleanup helper: remove our waiter if it's still registered. If
	// readLoop already dispatched, the entry is gone and this is a no-op.
	unregister := func() {
		c.reqMu.Lock()
		delete(c.pending, reqID)
		c.reqMu.Unlock()
	}

	if err := c.writeFrame(data[0], reqID, data[1:]); err != nil {
		unregister()
		return nil, err
	}

	var timer <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		timer = t.C
	}

	select {
	case resp, ok := <-ch:
		// Channel was closed by cleanup: daemon disconnected.
		if !ok {
			return nil, fmt.Errorf("daemon disconnected")
		}
		if resp.cmd == cmdError {
			if len(resp.payload) >= 2 {
				return nil, fmt.Errorf("daemon: %s", string(resp.payload[2:]))
			}
			return nil, fmt.Errorf("daemon error")
		}
		if resp.cmd != expectCmd {
			return nil, fmt.Errorf("ipc: unexpected reply cmd 0x%02X (expected 0x%02X)", resp.cmd, expectCmd)
		}
		return resp.payload, nil
	case <-c.doneCh:
		return nil, fmt.Errorf("daemon disconnected")
	case <-timer:
		unregister()
		// Tell the daemon the driver has lost interest in this reqID
		// so it can cancel the dispatch goroutine instead of grinding
		// through the full retry budget. Best-effort: if the write
		// fails (daemon dead, socket closed) we still return the
		// timeout error to the caller — they don't care.
		body := make([]byte, 8)
		binary.BigEndian.PutUint64(body[0:8], reqID)
		_ = c.writeFrame(cmdCancel, 0, body)
		return nil, fmt.Errorf("dial timeout")
	}
}

// H12 fix: per-port accept channel management.
// Drains any cmdAccept frames buffered in pendAccept (the post-#99
// race window between cmdBind reply and acceptChs registration).
func (c *ipcClient) registerAcceptCh(port uint16) chan []byte {
	ch := make(chan []byte, 64)
	c.acceptMu.Lock()
	c.acceptChs[port] = ch
	pending := c.pendAccept[port]
	delete(c.pendAccept, port)
	c.acceptMu.Unlock()
	for _, data := range pending {
		select {
		case ch <- data:
		default:
		}
	}
	return ch
}

func (c *ipcClient) registerRecvCh(connID uint32) chan []byte {
	ch := make(chan []byte, 256)
	c.recvMu.Lock()
	c.recvChs[connID] = ch
	// Drain any data that arrived before registration. Hold recvMu
	// across the drain so a concurrent dispatchPush(cmdCloseOK) for the
	// same connID can't race with these sends — without this guard, the
	// FIN handler at dispatchPush:250 closes the channel mid-drain and
	// chansend1 panics on a closed channel (issue #105 §4.8 race).
	// The drain is bounded by len(pendRecv[connID]) which is small —
	// data only buffers in pendRecv during the brief window between
	// the daemon dispatching cmdRecv and the driver's Accept calling
	// registerRecvCh, and never exceeds a single slow-path frame batch.
	pending := c.pendRecv[connID]
	delete(c.pendRecv, connID)
	for _, data := range pending {
		ch <- data
	}
	c.recvMu.Unlock()
	return ch
}

func (c *ipcClient) unregisterRecvCh(connID uint32) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	delete(c.recvChs, connID)
}
