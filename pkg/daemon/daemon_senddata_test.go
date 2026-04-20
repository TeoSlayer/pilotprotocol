package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// --- helpers ---

// newSendDataFixture returns a daemon + peer UDP socket + established connection
// wired so that sendSegment delivers to the peer socket.
func newSendDataFixture(t *testing.T, peerNode uint32) (*Daemon, *net.UDPConn, *Connection) {
	t.Helper()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.tunnels.Close() })

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peerConn.Close() })
	d.AddTunnelPeer(peerNode, peerConn.LocalAddr().(*net.UDPAddr))

	conn := d.ports.NewConnection(2000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x22222222}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.SendSeq = 1000
	conn.CongWin = InitialCongWin
	conn.PeerRecvWin = 1 << 20
	return d, peerConn, conn
}

func readOneSegment(t *testing.T, pc *net.UDPConn, dur time.Duration) *protocol.Packet {
	t.Helper()
	pc.SetReadDeadline(time.Now().Add(dur))
	buf := make([]byte, 65535)
	n, _, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n < 4 {
		t.Fatalf("short packet: %d bytes", n)
	}
	pkt, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return pkt
}

// --- SendData ---

func TestSendDataNonEstablishedReturnsError(t *testing.T) {
	d := New(Config{})
	conn := d.ports.NewConnection(1, protocol.Addr{Network: 0, Node: 1}, 1)
	conn.State = StateSynSent
	if err := d.SendData(conn, []byte("x")); err == nil {
		t.Fatal("expected error for non-established connection")
	}
}

func TestSendDataNoDelayUsesSendDataImmediate(t *testing.T) {
	const peerNode uint32 = 0xD0D0D0D0
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = true

	payload := []byte("fast-path")
	if err := d.SendData(conn, payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if string(pkt.Payload) != string(payload) {
		t.Fatalf("payload = %q, want %q", pkt.Payload, payload)
	}
}

func TestSendDataNagleBuffersAndFlushesImmediatelyWithNoInflight(t *testing.T) {
	const peerNode uint32 = 0xD1D1D1D1
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = false
	// No Unacked entries → Nagle flushes right away

	payload := []byte("small-write")
	if err := d.SendData(conn, payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if string(pkt.Payload) != string(payload) {
		t.Fatalf("payload = %q, want %q", pkt.Payload, payload)
	}
}

// --- nagleFlush ---

func TestNagleFlushEmptyBufIsNoop(t *testing.T) {
	d := New(Config{})
	conn := d.ports.NewConnection(1, protocol.Addr{Network: 0, Node: 1}, 1)
	conn.State = StateEstablished
	if err := d.nagleFlush(conn); err != nil {
		t.Fatalf("nagleFlush: %v", err)
	}
}

func TestNagleFlushFullMSSSendsSegment(t *testing.T) {
	const peerNode uint32 = 0xD2D2D2D2
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = false
	conn.NagleBuf = make([]byte, MaxSegmentSize)
	for i := range conn.NagleBuf {
		conn.NagleBuf[i] = byte('A' + (i % 26))
	}

	if err := d.nagleFlush(conn); err != nil {
		t.Fatalf("nagleFlush: %v", err)
	}
	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if len(pkt.Payload) != MaxSegmentSize {
		t.Fatalf("payload len = %d, want %d", len(pkt.Payload), MaxSegmentSize)
	}
	conn.NagleMu.Lock()
	remaining := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if remaining != 0 {
		t.Fatalf("NagleBuf remaining = %d, want 0", remaining)
	}
}

func TestNagleFlushSubMSSWithUnackedBlocksThenNagleChFlushes(t *testing.T) {
	const peerNode uint32 = 0xD3D3D3D3
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = false
	conn.NagleBuf = []byte("pending-small")
	// Simulate in-flight so Nagle blocks.
	conn.RetxMu.Lock()
	conn.Unacked = append(conn.Unacked, &retxEntry{
		data:     []byte("inflight"),
		seq:      500,
		sentAt:   time.Now(),
		attempts: 1,
	})
	conn.RetxMu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- d.nagleFlush(conn) }()

	// Signal that all data is ACKed.
	time.Sleep(10 * time.Millisecond)
	conn.RetxMu.Lock()
	conn.Unacked = conn.Unacked[:0]
	conn.RetxMu.Unlock()
	select {
	case conn.NagleCh <- struct{}{}:
	default:
		t.Fatal("NagleCh send should not block")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("nagleFlush: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("nagleFlush did not return")
	}

	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if string(pkt.Payload) != "pending-small" {
		t.Fatalf("payload = %q, want 'pending-small'", pkt.Payload)
	}
}

func TestNagleFlushRetxStopReturnsErrConnClosed(t *testing.T) {
	const peerNode uint32 = 0xD4D4D4D4
	d, _, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = false
	conn.NagleBuf = []byte("blocked")
	conn.RetxStop = make(chan struct{})
	// Create in-flight so nagleFlush waits.
	conn.RetxMu.Lock()
	conn.Unacked = append(conn.Unacked, &retxEntry{
		data: []byte("x"), seq: 1, sentAt: time.Now(), attempts: 1,
	})
	conn.RetxMu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- d.nagleFlush(conn) }()

	time.Sleep(10 * time.Millisecond)
	close(conn.RetxStop)

	select {
	case err := <-errCh:
		if err != protocol.ErrConnClosed {
			t.Fatalf("err = %v, want protocol.ErrConnClosed", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("nagleFlush did not return after RetxStop close")
	}
}

// --- Stop / doStop ---

func TestStopIsIdempotent(t *testing.T) {
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	// stopCh must be closed.
	select {
	case <-d.stopCh:
	default:
		t.Fatal("stopCh should be closed after Stop()")
	}
}

func TestDoStopWithEstablishedConnectionSendsFIN(t *testing.T) {
	const peerNode uint32 = 0xD5D5D5D5
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.SendSeq = 7777

	// doStop sends FIN to established conns.
	done := make(chan struct{})
	go func() {
		d.doStop()
		close(done)
	}()

	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if pkt.Flags&protocol.FlagFIN == 0 {
		t.Fatalf("expected FlagFIN, got flags=%b", pkt.Flags)
	}
	if pkt.Seq != 7777 {
		t.Fatalf("FIN seq = %d, want 7777", pkt.Seq)
	}

	select {
	case <-done:
	case <-time.After(4 * time.Second): // doStop may wait up to 3s for deregister
		t.Fatal("doStop did not return")
	}

	// Connection should be removed.
	if got := d.ports.FindConnection(2000, conn.RemoteAddr, 80); got != nil {
		t.Fatal("connection should be removed after doStop")
	}
}

func TestDoStopWithNoConnectionsCompletesCleanly(t *testing.T) {
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		d.doStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("doStop did not return")
	}
}

// --- heartbeatLoop ---

func TestHeartbeatLoopExitsOnStopCh(t *testing.T) {
	// Use a huge keepalive interval so the ticker never fires, and the jitter
	// is bounded at 5s by the implementation — but we exit via stopCh first.
	d := New(Config{KeepaliveInterval: 1 * time.Hour})
	done := make(chan struct{})
	go func() {
		d.heartbeatLoop()
		close(done)
	}()

	// The loop sleeps up to 5s for jitter before entering select; we need to
	// wait at least that long before close(stopCh) guarantees exit.
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("heartbeatLoop did not exit after stopCh close")
	}
}
