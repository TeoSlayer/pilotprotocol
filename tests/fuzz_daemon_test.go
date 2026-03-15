package tests

import (
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------------------------------------------------------------------------
// SACK Encode/Decode
// ---------------------------------------------------------------------------

func FuzzSACKRoundTrip(f *testing.F) {
	f.Add(uint32(100), uint32(200), uint32(300), uint32(400))
	f.Add(uint32(0), uint32(1), uint32(0xFFFFFFFF), uint32(0xFFFFFFFE))
	f.Add(uint32(0), uint32(0), uint32(0), uint32(0))

	f.Fuzz(func(t *testing.T, l1, r1, l2, r2 uint32) {
		blocks := []daemon.SACKBlock{
			{Left: l1, Right: r1},
			{Left: l2, Right: r2},
		}
		encoded := daemon.EncodeSACK(blocks)
		if encoded == nil {
			t.Fatal("EncodeSACK returned nil for non-empty blocks")
		}
		decoded, ok := daemon.DecodeSACK(encoded)
		if !ok {
			t.Fatal("DecodeSACK failed on valid data")
		}
		if len(decoded) != 2 {
			t.Fatalf("expected 2 blocks, got %d", len(decoded))
		}
		if decoded[0].Left != l1 || decoded[0].Right != r1 {
			t.Fatalf("block 0 mismatch: got {%d,%d}, want {%d,%d}", decoded[0].Left, decoded[0].Right, l1, r1)
		}
		if decoded[1].Left != l2 || decoded[1].Right != r2 {
			t.Fatalf("block 1 mismatch: got {%d,%d}, want {%d,%d}", decoded[1].Left, decoded[1].Right, l2, r2)
		}
	})
}

func FuzzDecodeSACK(f *testing.F) {
	// Valid SACK: "SACK" + count(1) + N*8 bytes
	f.Add([]byte("SACK\x01\x00\x00\x00\x64\x00\x00\x00\xC8"))
	f.Add([]byte{})
	f.Add([]byte("SACK"))
	f.Add([]byte("SACK\x00"))         // count=0
	f.Add([]byte("SACK\x05"))         // count=5 (>4)
	f.Add([]byte("SACK\x01"))         // count=1, no data
	f.Add([]byte("NOTSACK\x01\x00")) // wrong magic

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = daemon.DecodeSACK(data)
	})
}

func TestSACKEncodeEmpty(t *testing.T) {
	result := daemon.EncodeSACK(nil)
	if result != nil {
		t.Fatal("EncodeSACK(nil) should return nil")
	}
	result = daemon.EncodeSACK([]daemon.SACKBlock{})
	if result != nil {
		t.Fatal("EncodeSACK([]) should return nil")
	}
}

func TestSACKEncodeMax4Blocks(t *testing.T) {
	blocks := make([]daemon.SACKBlock, 6)
	for i := range blocks {
		blocks[i] = daemon.SACKBlock{Left: uint32(i * 100), Right: uint32(i*100 + 50)}
	}
	encoded := daemon.EncodeSACK(blocks)
	decoded, ok := daemon.DecodeSACK(encoded)
	if !ok {
		t.Fatal("DecodeSACK failed")
	}
	if len(decoded) != 4 {
		t.Fatalf("expected max 4 blocks, got %d", len(decoded))
	}
}

func TestSACKEncode1Block(t *testing.T) {
	blocks := []daemon.SACKBlock{{Left: 100, Right: 200}}
	encoded := daemon.EncodeSACK(blocks)
	if len(encoded) != 5+8 { // SACK(4) + count(1) + 1*8
		t.Fatalf("expected 13 bytes, got %d", len(encoded))
	}
	decoded, ok := daemon.DecodeSACK(encoded)
	if !ok || len(decoded) != 1 {
		t.Fatal("round-trip failed for 1 block")
	}
}

func TestSACKDecodeInvalidMagic(t *testing.T) {
	data := []byte("NACK\x01\x00\x00\x00\x64\x00\x00\x00\xC8")
	_, ok := daemon.DecodeSACK(data)
	if ok {
		t.Fatal("should reject invalid magic")
	}
}

func TestSACKDecodeCountZero(t *testing.T) {
	data := []byte("SACK\x00")
	_, ok := daemon.DecodeSACK(data)
	if ok {
		t.Fatal("should reject count=0")
	}
}

func TestSACKDecodeTruncated(t *testing.T) {
	// Claims 2 blocks but only has data for 1
	data := []byte("SACK\x02\x00\x00\x00\x64\x00\x00\x00\xC8")
	_, ok := daemon.DecodeSACK(data)
	if ok {
		t.Fatal("should reject truncated SACK data")
	}
}

func TestSACKDecodeCountOver4(t *testing.T) {
	data := []byte("SACK\x05")
	_, ok := daemon.DecodeSACK(data)
	if ok {
		t.Fatal("should reject count > 4")
	}
}

func TestSACKBoundaryValues(t *testing.T) {
	blocks := []daemon.SACKBlock{
		{Left: 0, Right: 0},
		{Left: 0xFFFFFFFF, Right: 0xFFFFFFFF},
	}
	encoded := daemon.EncodeSACK(blocks)
	decoded, ok := daemon.DecodeSACK(encoded)
	if !ok || len(decoded) != 2 {
		t.Fatal("boundary values round-trip failed")
	}
	if decoded[0].Left != 0 || decoded[0].Right != 0 {
		t.Fatal("zero block mismatch")
	}
	if decoded[1].Left != 0xFFFFFFFF || decoded[1].Right != 0xFFFFFFFF {
		t.Fatal("max block mismatch")
	}
}

// ---------------------------------------------------------------------------
// ConnState String
// ---------------------------------------------------------------------------

func TestConnStateString(t *testing.T) {
	tests := []struct {
		state daemon.ConnState
		want  string
	}{
		{daemon.StateClosed, "CLOSED"},
		{daemon.StateListen, "LISTEN"},
		{daemon.StateSynSent, "SYN_SENT"},
		{daemon.StateSynReceived, "SYN_RECV"},
		{daemon.StateEstablished, "ESTABLISHED"},
		{daemon.StateFinWait, "FIN_WAIT"},
		{daemon.StateCloseWait, "CLOSE_WAIT"},
		{daemon.StateTimeWait, "TIME_WAIT"},
		{daemon.ConnState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("ConnState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// PortManager
// ---------------------------------------------------------------------------

func TestPortManagerBindUnbind(t *testing.T) {
	pm := daemon.NewPortManager()

	ln, err := pm.Bind(100)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if ln == nil {
		t.Fatal("expected listener")
	}

	// Double bind should fail
	_, err = pm.Bind(100)
	if err == nil {
		t.Fatal("expected error for duplicate bind")
	}

	pm.Unbind(100)

	// Rebind should succeed after unbind
	ln2, err := pm.Bind(100)
	if err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	if ln2 == nil {
		t.Fatal("expected listener after rebind")
	}
	pm.Unbind(100)
}

func TestPortManagerGetListener(t *testing.T) {
	pm := daemon.NewPortManager()

	if pm.GetListener(100) != nil {
		t.Fatal("expected nil for unbound port")
	}

	pm.Bind(100)
	if pm.GetListener(100) == nil {
		t.Fatal("expected listener for bound port")
	}
	pm.Unbind(100)
}

func TestPortManagerNewConnection(t *testing.T) {
	pm := daemon.NewPortManager()

	remote := protocol.Addr{Network: 1, Node: 42}
	conn := pm.NewConnection(100, remote, 200)
	if conn == nil {
		t.Fatal("expected connection")
	}
	if conn.LocalPort != 100 || conn.RemotePort != 200 {
		t.Fatal("port mismatch")
	}
	if conn.RemoteAddr != remote {
		t.Fatal("remote addr mismatch")
	}

	// Get by ID
	if pm.GetConnection(conn.ID) != conn {
		t.Fatal("GetConnection should return same pointer")
	}

	// Find by tuple
	found := pm.FindConnection(100, remote, 200)
	if found != conn {
		t.Fatal("FindConnection should return same connection")
	}

	// Find non-existent
	if pm.FindConnection(999, remote, 200) != nil {
		t.Fatal("expected nil for non-existent port")
	}
}

func TestPortManagerRemoveConnection(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)
	id := conn.ID

	pm.RemoveConnection(id)
	if pm.GetConnection(id) != nil {
		t.Fatal("connection should be removed")
	}

	// Double remove should not panic
	pm.RemoveConnection(id)
}

func TestPortManagerAllocEphemeralPort(t *testing.T) {
	pm := daemon.NewPortManager()

	seen := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		port := pm.AllocEphemeralPort()
		if port < protocol.PortEphemeralMin || port > protocol.PortEphemeralMax {
			t.Fatalf("ephemeral port %d out of range [%d, %d]", port, protocol.PortEphemeralMin, protocol.PortEphemeralMax)
		}
		seen[port] = true
	}
	if len(seen) != 100 {
		t.Fatalf("expected 100 unique ports, got %d", len(seen))
	}
}

func TestPortManagerConnectionCount(t *testing.T) {
	pm := daemon.NewPortManager()

	if pm.TotalActiveConnections() != 0 {
		t.Fatal("expected 0 active connections")
	}

	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)
	conn.Mu.Lock()
	conn.State = daemon.StateEstablished
	conn.Mu.Unlock()

	if pm.TotalActiveConnections() != 1 {
		t.Fatalf("expected 1 active, got %d", pm.TotalActiveConnections())
	}
	if pm.ConnectionCountForPort(100) != 1 {
		t.Fatalf("expected 1 on port 100, got %d", pm.ConnectionCountForPort(100))
	}
	if pm.ConnectionCountForPort(999) != 0 {
		t.Fatal("expected 0 on port 999")
	}
}

func TestPortManagerStaleConnections(t *testing.T) {
	pm := daemon.NewPortManager()

	conn1 := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)
	conn1.Mu.Lock()
	conn1.State = daemon.StateClosed
	conn1.Mu.Unlock()

	conn2 := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 2}, 200)
	conn2.Mu.Lock()
	conn2.State = daemon.StateEstablished
	conn2.Mu.Unlock()

	stale := pm.StaleConnections(0)
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale, got %d", len(stale))
	}
	if stale[0].ID != conn1.ID {
		t.Fatal("wrong stale connection")
	}
}

func TestPortManagerIdleConnections(t *testing.T) {
	pm := daemon.NewPortManager()

	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)
	conn.Mu.Lock()
	conn.State = daemon.StateEstablished
	conn.LastActivity = time.Now().Add(-5 * time.Minute)
	conn.Mu.Unlock()

	idle := pm.IdleConnections(1 * time.Minute)
	if len(idle) != 1 {
		t.Fatalf("expected 1 idle, got %d", len(idle))
	}

	idle = pm.IdleConnections(10 * time.Minute)
	if len(idle) != 0 {
		t.Fatalf("expected 0 idle with 10m threshold, got %d", len(idle))
	}
}

func TestPortManagerAllConnections(t *testing.T) {
	pm := daemon.NewPortManager()
	pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)
	pm.NewConnection(100, protocol.Addr{Network: 1, Node: 2}, 200)
	pm.NewConnection(100, protocol.Addr{Network: 1, Node: 3}, 200)

	all := pm.AllConnections()
	if len(all) != 3 {
		t.Fatalf("expected 3, got %d", len(all))
	}
}

func TestPortManagerConcurrentAccess(t *testing.T) {
	pm := daemon.NewPortManager()
	var wg sync.WaitGroup

	// Concurrent binds on different ports
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			pm.Bind(port)
			pm.GetListener(port)
			pm.Unbind(port)
		}(uint16(2000 + i))
	}

	// Concurrent connection creates
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n uint32) {
			defer wg.Done()
			conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: n}, 200)
			pm.GetConnection(conn.ID)
			pm.TotalActiveConnections()
			pm.RemoveConnection(conn.ID)
		}(uint32(i))
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Connection: BytesInFlight, EffectiveWindow, RecvWindow
// ---------------------------------------------------------------------------

func TestConnectionBytesInFlight(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	// No unacked → 0
	conn.RetxMu.Lock()
	if conn.BytesInFlight() != 0 {
		t.Fatal("expected 0 bytes in flight")
	}
	conn.RetxMu.Unlock()

	// Track some sends
	conn.TrackSend(0, make([]byte, 1000))
	conn.TrackSend(1000, make([]byte, 500))

	conn.RetxMu.Lock()
	bif := conn.BytesInFlight()
	conn.RetxMu.Unlock()
	if bif != 1500 {
		t.Fatalf("expected 1500 bytes in flight, got %d", bif)
	}
}

func TestConnectionEffectiveWindow(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	conn.RetxMu.Lock()
	// Default CongWin = InitialCongWin, PeerRecvWin = 0 (unlimited)
	ew := conn.EffectiveWindow()
	if ew != daemon.InitialCongWin {
		t.Fatalf("expected %d, got %d", daemon.InitialCongWin, ew)
	}

	// Set a smaller peer window
	conn.PeerRecvWin = 1000
	ew = conn.EffectiveWindow()
	if ew != 1000 {
		t.Fatalf("expected 1000 (peer limit), got %d", ew)
	}

	// CongWin = 0 → falls back to InitialCongWin
	conn.CongWin = 0
	ew = conn.EffectiveWindow()
	if ew != 1000 { // peer limit still smaller
		t.Fatalf("expected 1000, got %d", ew)
	}
	conn.RetxMu.Unlock()
}

func TestConnectionRecvWindow(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	// Fresh connection → recv buffer is empty, window = capacity
	win := conn.RecvWindow()
	if win == 0 {
		t.Fatal("expected non-zero recv window for empty buffer")
	}

	// Fill some of the receive buffer
	conn.RecvBuf <- []byte("data")
	win2 := conn.RecvWindow()
	if win2 >= win {
		t.Fatal("recv window should decrease after adding data")
	}
}

// ---------------------------------------------------------------------------
// DeliverInOrder
// ---------------------------------------------------------------------------

func TestDeliverInOrderSequential(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)
	conn.Mu.Lock()
	conn.State = daemon.StateEstablished
	conn.Mu.Unlock()

	// Deliver seq 0
	ack := conn.DeliverInOrder(0, []byte("hello"))
	if ack != 5 {
		t.Fatalf("expected ack=5, got %d", ack)
	}

	// Deliver seq 5
	ack = conn.DeliverInOrder(5, []byte("world"))
	if ack != 10 {
		t.Fatalf("expected ack=10, got %d", ack)
	}
}

func TestDeliverInOrderOutOfOrder(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	// Deliver seq 10 first (out of order)
	ack := conn.DeliverInOrder(10, []byte("later"))
	if ack != 0 { // still expecting seq 0
		t.Fatalf("expected ack=0, got %d", ack)
	}

	// Deliver seq 0 (fills the gap)
	ack = conn.DeliverInOrder(0, []byte("0123456789"))
	// Should deliver both: 0-9, then 10-14
	if ack != 15 {
		t.Fatalf("expected ack=15, got %d", ack)
	}
}

func TestDeliverInOrderDuplicate(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	conn.DeliverInOrder(0, []byte("hello"))

	// Resend seq 0 → should be ignored
	ack := conn.DeliverInOrder(0, []byte("hello"))
	if ack != 5 {
		t.Fatalf("expected ack=5 for duplicate, got %d", ack)
	}
}

func TestDeliverInOrderClosedRecvBuf(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	conn.CloseRecvBuf()

	// Should not panic after close
	ack := conn.DeliverInOrder(0, []byte("hello"))
	_ = ack
}

// ---------------------------------------------------------------------------
// SACKBlocks
// ---------------------------------------------------------------------------

func TestSACKBlocksEmpty(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	conn.RecvMu.Lock()
	blocks := conn.SACKBlocks()
	conn.RecvMu.Unlock()

	if blocks != nil {
		t.Fatal("expected nil SACK blocks for empty OOO buffer")
	}
}

func TestSACKBlocksWithOOO(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	// Add out-of-order segments
	conn.DeliverInOrder(100, []byte("block1"))
	conn.DeliverInOrder(200, []byte("block2"))

	conn.RecvMu.Lock()
	blocks := conn.SACKBlocks()
	conn.RecvMu.Unlock()

	if len(blocks) == 0 {
		t.Fatal("expected SACK blocks for OOO data")
	}
}

// ---------------------------------------------------------------------------
// ProcessSACK
// ---------------------------------------------------------------------------

func TestProcessSACKMarksSacked(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	conn.TrackSend(0, make([]byte, 100))
	conn.TrackSend(100, make([]byte, 100))
	conn.TrackSend(200, make([]byte, 100))

	// SACK block covers seq 100-200
	conn.ProcessSACK([]daemon.SACKBlock{
		{Left: 100, Right: 200},
	})

	conn.Mu.Lock()
	sackRecv := conn.Stats.SACKRecv
	conn.Mu.Unlock()
	if sackRecv != 1 {
		t.Fatalf("expected SACKRecv=1, got %d", sackRecv)
	}
}

// ---------------------------------------------------------------------------
// CloseRecvBuf idempotent
// ---------------------------------------------------------------------------

func TestCloseRecvBufIdempotent(t *testing.T) {
	pm := daemon.NewPortManager()
	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 1}, 200)

	conn.CloseRecvBuf()
	conn.CloseRecvBuf() // should not panic
	conn.CloseRecvBuf() // still should not panic
}

// ---------------------------------------------------------------------------
// TaskQueue
// ---------------------------------------------------------------------------

func TestFuzzTaskQueueFIFO(t *testing.T) {
	q := daemon.NewTaskQueue()

	q.Add("task-1")
	q.Add("task-2")
	q.Add("task-3")

	if q.Len() != 3 {
		t.Fatalf("expected 3, got %d", q.Len())
	}

	if q.Peek() != "task-1" {
		t.Fatalf("expected task-1 at head, got %q", q.Peek())
	}

	got := q.Pop()
	if got != "task-1" {
		t.Fatalf("expected task-1, got %q", got)
	}

	got = q.Pop()
	if got != "task-2" {
		t.Fatalf("expected task-2, got %q", got)
	}

	got = q.Pop()
	if got != "task-3" {
		t.Fatalf("expected task-3, got %q", got)
	}

	got = q.Pop()
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestFuzzTaskQueueRemove(t *testing.T) {
	q := daemon.NewTaskQueue()
	q.Add("a")
	q.Add("b")
	q.Add("c")

	if !q.Remove("b") {
		t.Fatal("expected true for removing existing task")
	}
	if q.Len() != 2 {
		t.Fatalf("expected 2, got %d", q.Len())
	}

	// Remove non-existent
	if q.Remove("z") {
		t.Fatal("expected false for non-existent task")
	}
}

func TestFuzzTaskQueueRemoveHead(t *testing.T) {
	q := daemon.NewTaskQueue()
	q.Add("a")
	q.Add("b")

	q.Remove("a")
	if q.Peek() != "b" {
		t.Fatalf("expected b after removing head, got %q", q.Peek())
	}
}

func TestFuzzTaskQueueEmptyOperations(t *testing.T) {
	q := daemon.NewTaskQueue()

	if q.Peek() != "" {
		t.Fatal("expected empty Peek on empty queue")
	}
	if q.Pop() != "" {
		t.Fatal("expected empty Pop on empty queue")
	}
	if q.Len() != 0 {
		t.Fatal("expected Len=0")
	}
	if q.GetHeadStagedAt() != "" {
		t.Fatal("expected empty GetHeadStagedAt on empty queue")
	}
}

func TestFuzzTaskQueueList(t *testing.T) {
	q := daemon.NewTaskQueue()
	q.Add("x")
	q.Add("y")

	list := q.List()
	if len(list) != 2 || list[0] != "x" || list[1] != "y" {
		t.Fatalf("unexpected list: %v", list)
	}
}

func TestFuzzTaskQueueStagedAt(t *testing.T) {
	q := daemon.NewTaskQueue()

	// First task becomes head immediately with a timestamp
	q.Add("first")
	staged := q.GetHeadStagedAt()
	if staged == "" {
		t.Fatal("expected non-empty staged timestamp for head task")
	}

	staged2 := q.GetStagedAt("first")
	if staged2 != staged {
		t.Fatal("GetStagedAt should match GetHeadStagedAt")
	}

	// Non-head task has no staged time
	q.Add("second")
	if q.GetStagedAt("second") != "" {
		t.Fatal("non-head task should not have staged time")
	}

	// Pop first → second becomes head with new timestamp
	q.Pop()
	staged3 := q.GetHeadStagedAt()
	if staged3 == "" {
		t.Fatal("new head should get staged timestamp after Pop")
	}
}

func TestFuzzTaskQueueConcurrent(t *testing.T) {
	q := daemon.NewTaskQueue()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			taskID := "task-" + string(rune('A'+id%26))
			q.Add(taskID)
			q.Len()
			q.Peek()
			q.List()
			q.GetHeadStagedAt()
		}(i)
	}
	wg.Wait()

	// Drain
	for q.Len() > 0 {
		q.Pop()
	}
}

// ---------------------------------------------------------------------------
// ConnectionList
// ---------------------------------------------------------------------------

func TestConnectionList(t *testing.T) {
	pm := daemon.NewPortManager()

	conn := pm.NewConnection(100, protocol.Addr{Network: 1, Node: 42}, 200)
	conn.Mu.Lock()
	conn.State = daemon.StateEstablished
	conn.Mu.Unlock()

	list := pm.ConnectionList()
	if len(list) != 1 {
		t.Fatalf("expected 1 connection in list, got %d", len(list))
	}
	if list[0].State != "ESTABLISHED" {
		t.Fatalf("expected ESTABLISHED, got %q", list[0].State)
	}
	if list[0].LocalPort != 100 || list[0].RemotePort != 200 {
		t.Fatal("port mismatch in ConnectionList")
	}
}

// ---------------------------------------------------------------------------
// TunnelManager basic
// ---------------------------------------------------------------------------

func TestTunnelManagerPeerManagement(t *testing.T) {
	tm := daemon.NewTunnelManager()
	defer tm.Close()

	if tm.PeerCount() != 0 {
		t.Fatal("expected 0 peers")
	}
	if tm.HasPeer(42) {
		t.Fatal("expected no peer 42")
	}
}

func TestTunnelManagerRelayPeer(t *testing.T) {
	tm := daemon.NewTunnelManager()
	defer tm.Close()

	if tm.IsRelayPeer(1) {
		t.Fatal("expected no relay for peer 1")
	}
	tm.SetRelayPeer(1, true)
	if !tm.IsRelayPeer(1) {
		t.Fatal("expected relay for peer 1")
	}
	tm.SetRelayPeer(1, false)
	if tm.IsRelayPeer(1) {
		t.Fatal("expected no relay after unsetting")
	}
}

func TestTunnelManagerSetNodeID(t *testing.T) {
	tm := daemon.NewTunnelManager()
	defer tm.Close()

	tm.SetNodeID(42)
	// No public getter, but should not panic
}

func TestTunnelManagerEnableEncryption(t *testing.T) {
	tm := daemon.NewTunnelManager()
	defer tm.Close()

	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
}

func TestTunnelManagerHasCrypto(t *testing.T) {
	tm := daemon.NewTunnelManager()
	defer tm.Close()

	if tm.HasCrypto(1) {
		t.Fatal("expected no crypto for unknown peer")
	}
	if tm.IsEncrypted(1) {
		t.Fatal("expected not encrypted for unknown peer")
	}
}

func TestTunnelManagerPeerList(t *testing.T) {
	tm := daemon.NewTunnelManager()
	defer tm.Close()

	list := tm.PeerList()
	if len(list) != 0 {
		t.Fatalf("expected empty peer list, got %d", len(list))
	}
}

func TestTunnelManagerLocalAddr(t *testing.T) {
	tm := daemon.NewTunnelManager()
	defer tm.Close()

	if tm.LocalAddr() != nil {
		t.Fatal("expected nil LocalAddr before Listen")
	}
}
