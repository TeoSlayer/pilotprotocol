// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// IPC commands (must match daemon/ipc.go)
const (
	cmdBind               byte = 0x01
	cmdBindOK             byte = 0x02
	cmdDial               byte = 0x03
	cmdDialOK             byte = 0x04
	cmdAccept             byte = 0x05
	cmdSend               byte = 0x06
	cmdRecv               byte = 0x07
	cmdClose              byte = 0x08
	cmdCloseOK            byte = 0x09
	cmdError              byte = 0x0A
	cmdSendTo             byte = 0x0B
	cmdRecvFrom           byte = 0x0C
	cmdInfo               byte = 0x0D
	cmdInfoOK             byte = 0x0E
	cmdHandshake          byte = 0x0F
	cmdHandshakeOK        byte = 0x10
	cmdResolveHostname    byte = 0x11
	cmdResolveHostnameOK  byte = 0x12
	cmdSetHostname        byte = 0x13
	cmdSetHostnameOK      byte = 0x14
	cmdSetVisibility      byte = 0x15
	cmdSetVisibilityOK    byte = 0x16
	cmdDeregister         byte = 0x17
	cmdDeregisterOK       byte = 0x18
	cmdSetTags            byte = 0x19
	cmdSetTagsOK          byte = 0x1A
	cmdSetWebhook         byte = 0x1B
	cmdSetWebhookOK       byte = 0x1C
	cmdSetWebhookTopics   byte = 0x1D
	cmdSetWebhookTopicsOK byte = 0x1E
	cmdNetwork            byte = 0x1F
	cmdNetworkOK          byte = 0x20
	cmdHealth             byte = 0x21
	cmdHealthOK           byte = 0x22
	cmdManaged            byte = 0x23
	cmdManagedOK          byte = 0x24
	cmdRotateKey          byte = 0x25
	cmdRotateKeyOK        byte = 0x26
	cmdBroadcast          byte = 0x29
	cmdBroadcastOK        byte = 0x2A
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

// ipcEnvelopeHeaderSize matches daemon.IPCEnvelopeHeaderSize: 1 byte cmd.
const ipcEnvelopeHeaderSize = 1

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

	// writeMu serializes frame writes so concurrent goroutines don't
	// interleave bytes on the wire. Held only for the write itself.
	writeMu sync.Mutex

	// waitSem is a channel-based semaphore (capacity 1) that ensures at
	// most one request/reply pair is in-flight at a time. Using a channel
	// instead of sync.Mutex lets goroutines waiting for the semaphore be
	// woken on doneCh close, preventing a deadlock when the daemon closes
	// while many goroutines are queued behind a slow sendAndWait.
	waitSem chan struct{}         // capacity 1
	pending chan *pendingResponse // capacity 16; buffers reply frames from readLoop

	recvMu     sync.Mutex
	recvChs    map[uint32]chan []byte // conn_id → data channel
	pendRecv   map[uint32][][]byte    // conn_id → buffered data before recvCh registered
	pendAccept map[uint16][][]byte    // port → buffered cmdAccept payloads before acceptCh registered (post-#99 race fix)

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
		conn:       conn,
		waitSem:    make(chan struct{}, 1),
		pending:    make(chan *pendingResponse, 16),
		recvChs:    make(map[uint32]chan []byte),
		pendRecv:   make(map[uint32][][]byte),
		pendAccept: make(map[uint16][][]byte),
		acceptChs:  make(map[uint16]chan []byte),
		dgCh:       make(chan *Datagram, 256),
		doneCh:     make(chan struct{}),
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
//	[uint32-len][uint8-cmd][payload...]
//
// Server-pushed frames (cmdRecv, cmdCloseOK, cmdRecvFrom, cmdAccept) are
// routed by cmd to their per-connection channels. cmdCloseOK is always
// a server-push (remote FIN); Driver.Disconnect uses send() not
// sendAndWait() so it never waits for cmdCloseOK in pending.
// Known response cmds are forwarded to c.pending for sendAndWait.
// Unknown cmds are silently dropped — they never reach pending, so
// sendAndWaitTimeout can use a single read without a discard loop.
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
		payload := msg[ipcEnvelopeHeaderSize:]

		switch cmd {
		case cmdRecv, cmdRecvFrom, cmdAccept, cmdCloseOK:
			// Server-pushed frames: route to per-connection channels.
			c.dispatchPush(cmd, payload)
		case cmdBindOK, cmdDialOK, cmdError, cmdInfoOK, cmdHandshakeOK,
			cmdResolveHostnameOK, cmdSetHostnameOK, cmdSetVisibilityOK,
			cmdDeregisterOK, cmdSetTagsOK, cmdSetWebhookOK, cmdSetWebhookTopicsOK, cmdNetworkOK,
			cmdHealthOK, cmdManagedOK, cmdRotateKeyOK, cmdBroadcastOK:
			// Known response cmds: route to pending for the in-flight sendAndWait.
			select {
			case c.pending <- &pendingResponse{cmd: cmd, payload: append([]byte(nil), payload...)}:
			default:
			}
			// default: unknown cmd — silently drop (version mismatch, test injection, etc.)
		}
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

// cleanup closes channels when readLoop exits (daemon disconnect).
func (c *ipcClient) cleanup() {
	close(c.doneCh)

	// Drain all buffered responses.
	for {
		select {
		case <-c.pending:
		default:
			goto drained
		}
	}
drained:

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

// writeFrame builds a `[cmd][body...]` envelope and writes it under
// writeMu so frames don't interleave on the wire.
func (c *ipcClient) writeFrame(cmd byte, body []byte) error {
	buf := make([]byte, ipcEnvelopeHeaderSize+len(body))
	buf[0] = cmd
	copy(buf[1:], body)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return ipcutil.Write(c.conn, buf)
}

// send is a fire-and-forget write — used for cmdSend/cmdSendTo where
// the daemon does not reply. Acquires only writeMu (not waitMu), so
// concurrent fire-and-forget sends are never blocked behind a reply wait.
func (c *ipcClient) send(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("ipc: empty message")
	}
	return c.writeFrame(data[0], data[1:])
}

// sendAndWait sends a request and waits for the reply.
func (c *ipcClient) sendAndWait(data []byte, expectCmd byte) ([]byte, error) {
	return c.sendAndWaitTimeout(data, expectCmd, 0)
}

// sendAndWaitTimeout serialises at most one request/reply pair at a time
// via waitSem. timeout=0 means wait forever. The timer is started BEFORE
// acquiring the semaphore so the timeout applies to queue wait + reply
// wait combined — without this, goroutines queued behind the semaphore
// can't time out and pile up indefinitely under high concurrency.
func (c *ipcClient) sendAndWaitTimeout(data []byte, expectCmd byte, timeout time.Duration) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("ipc: empty request")
	}

	// Start the timer before acquiring the semaphore so queued goroutines
	// can bail out instead of waiting forever.
	var timer <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		timer = t.C
	}

	// Acquire the serialisation semaphore. Channel-based (not sync.Mutex)
	// so goroutines blocked here are woken by doneCh or timer.
	select {
	case c.waitSem <- struct{}{}:
	case <-c.doneCh:
		return nil, fmt.Errorf("daemon disconnected")
	case <-timer:
		return nil, fmt.Errorf("dial timeout")
	}
	defer func() { <-c.waitSem }()

	// Drain all stale replies buffered before this request was sent.
	for {
		select {
		case <-c.pending:
		default:
			goto drained
		}
	}
drained:

	if err := c.writeFrame(data[0], data[1:]); err != nil {
		return nil, err
	}

	// Unknown cmds are dropped in readLoop, so the first frame in pending
	// is always either the expected response or cmdError.
	select {
	case resp := <-c.pending:
		if resp.cmd == cmdError {
			if len(resp.payload) >= 2 {
				return nil, fmt.Errorf("daemon: %s", string(resp.payload[2:]))
			}
			return nil, fmt.Errorf("daemon error")
		}
		if resp.cmd != expectCmd {
			return nil, fmt.Errorf("ipc: unexpected reply 0x%02X (want 0x%02X)", resp.cmd, expectCmd)
		}
		return resp.payload, nil
	case <-c.doneCh:
		return nil, fmt.Errorf("daemon disconnected")
	case <-timer:
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
