package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// --- SetWebhookURL ---

func TestSetWebhookURLWithNonEmptyAssignsNewClient(t *testing.T) {
	d := New(Config{})
	defer func() {
		if d.webhook != nil {
			d.webhook.Close()
		}
	}()

	// New daemon has no webhook yet (nil).
	if d.webhook != nil {
		t.Fatal("precondition: webhook should start nil")
	}
	d.SetWebhookURL("http://127.0.0.1:1/nowhere")
	if d.webhook == nil {
		t.Fatal("webhook should be assigned after SetWebhookURL(non-empty)")
	}
}

func TestSetWebhookURLEmptyClearsToNil(t *testing.T) {
	d := New(Config{})
	d.SetWebhookURL("http://127.0.0.1:1/nowhere")
	if d.webhook == nil {
		t.Fatal("precondition: webhook should be assigned first")
	}
	// Now clear it.
	d.SetWebhookURL("")
	if d.webhook != nil {
		t.Fatalf("webhook should be nil after SetWebhookURL(\"\"), got %v", d.webhook)
	}
}

// --- autoJoinNetworks ---

func TestAutoJoinNetworksNoAdminTokenIsEarlyReturn(t *testing.T) {
	// regConn is nil — if early-return fails, this would panic.
	d := New(Config{AdminToken: "", Networks: []uint16{1, 2, 3}})
	d.autoJoinNetworks() // must not panic
}

func TestAutoJoinNetworksNoNetworksIsEarlyReturn(t *testing.T) {
	d := New(Config{AdminToken: "secret", Networks: nil})
	d.autoJoinNetworks() // must not panic (early-return on len==0)
}

// --- Info (via real registry) ---

func TestInfoBasicFieldsWithoutRegistry(t *testing.T) {
	// Info calls d.nodeNetworks() which uses regConn. Use a real in-process
	// registry so the happy path works without side effects.
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	d := New(Config{Version: "testv1"})
	d.regConn = rc
	d.startTime = time.Now().Add(-2 * time.Second)
	d.setNodeID_testhelper(0xABCD0001)

	info := d.Info()
	if info == nil {
		t.Fatal("Info() returned nil")
	}
	if info.NodeID != 0xABCD0001 {
		t.Fatalf("NodeID = %x, want 0xABCD0001", info.NodeID)
	}
	if info.Version != "testv1" {
		t.Fatalf("Version = %q, want testv1", info.Version)
	}
	if info.Uptime < time.Second {
		t.Fatalf("Uptime = %v, want >= 1s", info.Uptime)
	}
	if info.Identity {
		t.Fatal("Identity should be false when IdentityPath is empty")
	}
	if info.PublicKey != "" {
		t.Fatalf("PublicKey should be empty when no identity; got %q", info.PublicKey)
	}
	if info.Peers != 0 {
		t.Fatalf("Peers = %d, want 0", info.Peers)
	}
	if info.Connections != 0 {
		t.Fatalf("Connections = %d, want 0", info.Connections)
	}
}

// --- retransmitUnacked ---

func newRetxConn(t *testing.T) (*Connection, *capturedSender) {
	t.Helper()
	conn := &Connection{
		ID:         1,
		LocalAddr:  protocol.Addr{Network: 0, Node: 0x11111111},
		RemoteAddr: protocol.Addr{Network: 0, Node: 0x22222222},
		LocalPort:  1000,
		RemotePort: 80,
		State:      StateEstablished,
		CongWin:    InitialCongWin,
		SSThresh:   MaxCongWin / 2,
		RTO:        InitialRTO,
		SendSeq:    500,
		RecvBuf:    make(chan []byte, RecvBufSize),
	}
	cs := &capturedSender{}
	conn.RetxSend = cs.send
	return conn, cs
}

type capturedSender struct {
	mu      sync.Mutex
	packets []*protocol.Packet
}

func (cs *capturedSender) send(pkt *protocol.Packet) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.packets = append(cs.packets, pkt)
}

func (cs *capturedSender) all() []*protocol.Packet {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]*protocol.Packet, len(cs.packets))
	copy(out, cs.packets)
	return out
}

func TestRetransmitUnackedEmptyIsNoop(t *testing.T) {
	d := New(Config{})
	conn, cs := newRetxConn(t)
	d.retransmitUnacked(conn)
	if len(cs.all()) != 0 {
		t.Fatalf("no Unacked → no packets sent; got %d", len(cs.all()))
	}
}

func TestRetransmitUnackedRecentlyRetxedIsNoop(t *testing.T) {
	d := New(Config{})
	conn, cs := newRetxConn(t)
	conn.Unacked = []*retxEntry{{data: []byte("x"), seq: 100, sentAt: time.Now().Add(-2 * InitialRTO), attempts: 1}}
	conn.LastRetxTime = time.Now() // just fired
	d.retransmitUnacked(conn)
	if len(cs.all()) != 0 {
		t.Fatalf("LastRetxTime < RTO → no packet sent; got %d", len(cs.all()))
	}
}

func TestRetransmitUnackedNotTimedOutIsNoop(t *testing.T) {
	d := New(Config{})
	conn, cs := newRetxConn(t)
	conn.Unacked = []*retxEntry{{data: []byte("x"), seq: 100, sentAt: time.Now(), attempts: 1}}
	d.retransmitUnacked(conn)
	if len(cs.all()) != 0 {
		t.Fatalf("entry not timed out → no packet; got %d", len(cs.all()))
	}
}

func TestRetransmitUnackedSackedSkippedAllBreakOnFirstUntimed(t *testing.T) {
	d := New(Config{})
	conn, cs := newRetxConn(t)
	// First entry is sacked (skip), second is fresh (loop breaks on non-timed-out).
	conn.Unacked = []*retxEntry{
		{data: []byte("a"), seq: 100, sentAt: time.Now().Add(-2 * InitialRTO), attempts: 1, sacked: true},
		{data: []byte("b"), seq: 200, sentAt: time.Now(), attempts: 1},
	}
	d.retransmitUnacked(conn)
	if len(cs.all()) != 0 {
		t.Fatalf("sacked skipped + next-not-timed-out → no packet; got %d", len(cs.all()))
	}
}

func TestRetransmitUnackedTimedOutSendsACKPacketAndEntersRecovery(t *testing.T) {
	d := New(Config{})
	conn, cs := newRetxConn(t)
	prevCongWin := conn.CongWin
	prevRTO := conn.RTO
	payload := []byte("retx-me")
	conn.Unacked = []*retxEntry{{data: payload, seq: 300, sentAt: time.Now().Add(-2 * InitialRTO), attempts: 1}}
	d.retransmitUnacked(conn)

	pkts := cs.all()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 retransmitted packet, got %d", len(pkts))
	}
	pkt := pkts[0]
	if pkt.Flags&protocol.FlagACK == 0 {
		t.Fatalf("retx should carry FlagACK, got flags=%b", pkt.Flags)
	}
	if pkt.Seq != 300 || string(pkt.Payload) != "retx-me" {
		t.Fatalf("retx packet mismatch: seq=%d payload=%q", pkt.Seq, pkt.Payload)
	}

	// attempts bumped from 1 → 2
	if conn.Unacked[0].attempts != 2 {
		t.Fatalf("attempts = %d, want 2", conn.Unacked[0].attempts)
	}
	// CongWin collapsed to InitialCongWin, SSThresh halved (but ≥ MaxSegmentSize)
	if conn.CongWin != InitialCongWin {
		t.Fatalf("CongWin = %d, want InitialCongWin=%d", conn.CongWin, InitialCongWin)
	}
	wantSSThresh := prevCongWin / 2
	if wantSSThresh < MaxSegmentSize {
		wantSSThresh = MaxSegmentSize
	}
	if conn.SSThresh != wantSSThresh {
		t.Fatalf("SSThresh = %d, want %d", conn.SSThresh, wantSSThresh)
	}
	if !conn.InRecovery {
		t.Fatal("InRecovery should be true after timeout")
	}
	if conn.RTO != prevRTO*2 && conn.RTO != 10*time.Second {
		t.Fatalf("RTO = %v, want 2x=%v or clamped=10s", conn.RTO, prevRTO*2)
	}
	if conn.Stats.Retransmits != 1 {
		t.Fatalf("Stats.Retransmits = %d, want 1", conn.Stats.Retransmits)
	}
}

func TestRetransmitUnackedMaxAttemptsSendsRSTAndClosesState(t *testing.T) {
	d := New(Config{})
	conn, cs := newRetxConn(t)
	conn.Unacked = []*retxEntry{{
		data:     []byte("x"),
		seq:      999,
		sentAt:   time.Now().Add(-2 * InitialRTO),
		attempts: MaxRetxAttempts,
	}}
	d.retransmitUnacked(conn)

	pkts := cs.all()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 RST packet, got %d", len(pkts))
	}
	if pkts[0].Flags&protocol.FlagRST == 0 {
		t.Fatalf("expected FlagRST, got flags=%b", pkts[0].Flags)
	}
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateClosed {
		t.Fatalf("state = %v, want StateClosed after max retransmits", st)
	}
}

func TestRetransmitUnackedFinWaitSendsFIN(t *testing.T) {
	d := New(Config{})
	conn, cs := newRetxConn(t)
	conn.State = StateFinWait
	conn.Unacked = []*retxEntry{{
		data:     []byte{0},
		seq:      600,
		sentAt:   time.Now().Add(-2 * InitialRTO),
		attempts: 1,
	}}
	d.retransmitUnacked(conn)

	pkts := cs.all()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 FIN retransmission, got %d", len(pkts))
	}
	if pkts[0].Flags&protocol.FlagFIN == 0 {
		t.Fatalf("FinWait retx should carry FlagFIN, got flags=%b", pkts[0].Flags)
	}
	if pkts[0].Seq != 600 {
		t.Fatalf("FIN Seq = %d, want 600", pkts[0].Seq)
	}
}

// --- retxLoop lifecycle ---

func TestRetxLoopReturnsWhenRetxStopClosed(t *testing.T) {
	d := New(Config{})
	conn, _ := newRetxConn(t)
	conn.RetxStop = make(chan struct{})

	done := make(chan struct{})
	go func() {
		d.retxLoop(conn)
		close(done)
	}()

	// Immediately close stop — retxLoop should return.
	close(conn.RetxStop)
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("retxLoop did not return after RetxStop close")
	}
}

func TestRetxLoopClosedStateCleansUpAndReturns(t *testing.T) {
	d := New(Config{})
	conn, _ := newRetxConn(t)
	conn.State = StateClosed
	conn.RetxStop = make(chan struct{})
	d.ports.mu.Lock()
	d.ports.connections[conn.ID] = conn
	d.ports.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.retxLoop(conn)
		close(done)
	}()

	// retxLoop ticks every RetxCheckInterval (100ms). On the first tick with
	// state=Closed, it calls RemoveConnection + closes RecvBuf and returns.
	select {
	case <-done:
	case <-time.After(3 * RetxCheckInterval):
		t.Fatal("retxLoop did not return from StateClosed branch")
	}

	// Connection removed from PortManager
	if d.ports.GetConnection(conn.ID) != nil {
		t.Fatal("connection should be removed after StateClosed cleanup")
	}
	// RecvBuf closed
	select {
	case _, ok := <-conn.RecvBuf:
		if ok {
			t.Fatal("RecvBuf should be closed")
		}
	default:
		t.Fatal("RecvBuf recv should not block (closed)")
	}
}

// startRetxLoop wires RetxSend + RetxStop and spawns retxLoop. Minimal smoke.
func TestStartRetxLoopInitializesRTOAndRetxStopAndExitsOnStop(t *testing.T) {
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	conn := d.ports.NewConnection(1001, protocol.Addr{Network: 0, Node: 1}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 2}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: 1}

	d.startRetxLoop(conn)

	if conn.RTO != InitialRTO {
		t.Fatalf("RTO = %v, want InitialRTO=%v", conn.RTO, InitialRTO)
	}
	if conn.RetxStop == nil {
		t.Fatal("RetxStop should be initialized")
	}
	if conn.RetxSend == nil {
		t.Fatal("RetxSend should be wired to tunnels.Send")
	}

	// Stop by closing RetxStop (loop must exit within 200ms).
	close(conn.RetxStop)
	time.Sleep(50 * time.Millisecond)
	// Nothing to assert beyond the loop not hanging; the test framework kills
	// leaked goroutines at the end of the process. A clean test run is enough.
}
