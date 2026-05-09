// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------------------------------------------------------------------------
// SACK encode / decode
// ---------------------------------------------------------------------------

func TestEncodeSACKEmpty(t *testing.T) {
	t.Parallel()
	if got := EncodeSACK(nil); got != nil {
		t.Errorf("got %v, want nil for empty input", got)
	}
	if got := EncodeSACK([]SACKBlock{}); got != nil {
		t.Errorf("got %v, want nil for empty slice", got)
	}
}

func TestEncodeSACKRoundTrip(t *testing.T) {
	t.Parallel()
	blocks := []SACKBlock{{1, 100}, {200, 300}}
	enc := EncodeSACK(blocks)
	// "SACK" + 1-byte count + 2 * 8 bytes
	if len(enc) != 5+16 {
		t.Fatalf("unexpected length %d", len(enc))
	}
	if string(enc[0:4]) != "SACK" {
		t.Errorf("missing magic")
	}
	if enc[4] != 2 {
		t.Errorf("count = %d, want 2", enc[4])
	}
	dec, ok := DecodeSACK(enc)
	if !ok {
		t.Fatal("decode failed")
	}
	if len(dec) != 2 || dec[0] != blocks[0] || dec[1] != blocks[1] {
		t.Errorf("round-trip mismatch: %v", dec)
	}
}

func TestEncodeSACKClampsToFour(t *testing.T) {
	t.Parallel()
	blocks := []SACKBlock{{1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}, {11, 12}}
	enc := EncodeSACK(blocks)
	if enc[4] != 4 {
		t.Errorf("count = %d, want 4 (clamped)", enc[4])
	}
	if len(enc) != 5+32 {
		t.Errorf("len = %d, want 37", len(enc))
	}
}

func TestDecodeSACKRejectsBad(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"too short":     {0, 1, 2},
		"wrong magic":   {'A', 'B', 'C', 'D', 0x01},
		"zero count":    append([]byte("SACK"), 0x00),
		"count > 4":     append([]byte("SACK"), 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
		"payload short": append([]byte("SACK"), 0x01, 0x00, 0x00),
	}
	for name, data := range cases {
		if _, ok := DecodeSACK(data); ok {
			t.Errorf("%s: unexpectedly decoded", name)
		}
	}
}

// ---------------------------------------------------------------------------
// ConnState.String
// ---------------------------------------------------------------------------

func TestConnStateStringAll(t *testing.T) {
	t.Parallel()
	cases := map[ConnState]string{
		StateClosed:      "CLOSED",
		StateListen:      "LISTEN",
		StateSynSent:     "SYN_SENT",
		StateSynReceived: "SYN_RECV",
		StateEstablished: "ESTABLISHED",
		StateFinWait:     "FIN_WAIT",
		StateCloseWait:   "CLOSE_WAIT",
		StateTimeWait:    "TIME_WAIT",
		ConnState(99):    "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", s, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// PortManager
// ---------------------------------------------------------------------------

func TestPortManagerBindUnbind(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	ln, err := pm.Bind(80)
	if err != nil {
		t.Fatal(err)
	}
	if ln == nil || ln.Port != 80 {
		t.Fatalf("bad listener %+v", ln)
	}
	if got := pm.GetListener(80); got != ln {
		t.Errorf("GetListener mismatch")
	}
	// Duplicate bind should error
	if _, err := pm.Bind(80); err == nil {
		t.Error("expected duplicate-bind error")
	}
	pm.Unbind(80)
	if got := pm.GetListener(80); got != nil {
		t.Errorf("listener present after unbind: %+v", got)
	}
	// Unbind idempotent — no panic on missing port
	pm.Unbind(80)
}

func TestPortManagerNewConnectionIDIncrements(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	a := pm.NewConnection(80, protocol.Addr{}, 100)
	b := pm.NewConnection(80, protocol.Addr{}, 101)
	if a.ID == 0 || b.ID == 0 || a.ID == b.ID {
		t.Errorf("IDs not unique-nonzero: a=%d b=%d", a.ID, b.ID)
	}
}

func TestPortManagerNewConnectionIDWrapsSkippingZero(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	pm.nextConnID = ^uint32(0) // max uint32, next increment wraps to 0
	c1 := pm.NewConnection(80, protocol.Addr{}, 100)
	c2 := pm.NewConnection(80, protocol.Addr{}, 101)
	if c1.ID != ^uint32(0) {
		t.Errorf("c1.ID = %d, want max", c1.ID)
	}
	// After the wrap, nextConnID was 0 → reset to 1, so c2.ID = 1
	if c2.ID != 1 {
		t.Errorf("c2.ID = %d, want 1 (wrap skipped 0)", c2.ID)
	}
}

func TestConnectionCountForPort(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	c1 := pm.NewConnection(80, protocol.Addr{}, 1)
	c1.State = StateEstablished
	c2 := pm.NewConnection(80, protocol.Addr{}, 2)
	c2.State = StateClosed // closed should be excluded
	c3 := pm.NewConnection(80, protocol.Addr{}, 3)
	c3.State = StateTimeWait // time-wait excluded
	c4 := pm.NewConnection(81, protocol.Addr{}, 4)
	c4.State = StateEstablished
	if got := pm.ConnectionCountForPort(80); got != 1 {
		t.Errorf("port 80 count = %d, want 1", got)
	}
	if got := pm.ConnectionCountForPort(81); got != 1 {
		t.Errorf("port 81 count = %d, want 1", got)
	}
	if got := pm.ConnectionCountForPort(999); got != 0 {
		t.Errorf("port 999 count = %d, want 0", got)
	}
}

func TestTotalActiveConnections(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	pm.NewConnection(80, protocol.Addr{}, 1).State = StateEstablished
	pm.NewConnection(80, protocol.Addr{}, 2).State = StateClosed
	pm.NewConnection(80, protocol.Addr{}, 3).State = StateTimeWait
	pm.NewConnection(80, protocol.Addr{}, 4).State = StateSynSent
	if got := pm.TotalActiveConnections(); got != 2 {
		t.Errorf("got %d, want 2 (closed+time_wait excluded)", got)
	}
}

func TestAllocEphemeralPortInRange(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	port := pm.AllocEphemeralPort()
	if port < protocol.PortEphemeralMin || port > protocol.PortEphemeralMax {
		t.Errorf("port %d out of ephemeral range", port)
	}
}

func TestAllocEphemeralPortSequential(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	seen := make(map[uint16]bool)
	for i := 0; i < 10; i++ {
		p := pm.AllocEphemeralPort()
		if seen[p] {
			t.Errorf("duplicate ephemeral port %d", p)
		}
		seen[p] = true
	}
}

func TestGetConnectionMissingReturnsNil(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	if got := pm.GetConnection(9999); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestFindConnection(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	addr := protocol.Addr{}
	c := pm.NewConnection(80, addr, 100)
	if got := pm.FindConnection(80, addr, 100); got != c {
		t.Errorf("FindConnection mismatch")
	}
	if got := pm.FindConnection(80, addr, 999); got != nil {
		t.Errorf("expected nil for unknown remote port, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// seqAfter / seqAfterOrEqual (RFC 1982 wraparound arithmetic)
// ---------------------------------------------------------------------------

func TestSeqAfter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b uint32
		want bool
	}{
		{10, 5, true},
		{5, 10, false},
		{5, 5, false},
		{1, ^uint32(0), true},     // 1 is "after" max (wraparound)
		{^uint32(0), 1, false},    // max is "before" 1 after wrap
		{1 << 30, 0, true},        // clearly after (2^30 difference)
		{(1 << 31) + 1, 0, false}, // just past boundary → interpreted as before
	}
	for _, tc := range cases {
		if got := seqAfter(tc.a, tc.b); got != tc.want {
			t.Errorf("seqAfter(%d,%d) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestSeqAfterOrEqual(t *testing.T) {
	t.Parallel()
	if !seqAfterOrEqual(5, 5) {
		t.Error("seqAfterOrEqual(5,5) should be true")
	}
	if !seqAfterOrEqual(10, 5) {
		t.Error("seqAfterOrEqual(10,5) should be true")
	}
	if seqAfterOrEqual(5, 10) {
		t.Error("seqAfterOrEqual(5,10) should be false")
	}
}

// ---------------------------------------------------------------------------
// RecvWindow / BytesInFlight / EffectiveWindow / WindowAvailable
// ---------------------------------------------------------------------------

func TestRecvWindowFree(t *testing.T) {
	t.Parallel()
	c := &Connection{RecvBuf: make(chan []byte, 10)}
	if got := c.RecvWindow(); got != 10 {
		t.Errorf("empty buf: got %d, want 10", got)
	}
	c.RecvBuf <- []byte("x")
	c.RecvBuf <- []byte("y")
	if got := c.RecvWindow(); got != 8 {
		t.Errorf("after 2 enqueue: got %d, want 8", got)
	}
}

func TestBytesInFlight(t *testing.T) {
	t.Parallel()
	c := &Connection{}
	c.TrackSend(1, []byte("hello"))
	c.TrackSend(6, []byte("world"))
	if got := c.BytesInFlight(); got != 10 {
		t.Errorf("got %d, want 10", got)
	}
}

func TestEffectiveWindowClampsToPeer(t *testing.T) {
	t.Parallel()
	c := &Connection{CongWin: 100_000, PeerRecvWin: 4096}
	if got := c.EffectiveWindow(); got != 4096 {
		t.Errorf("got %d, want 4096 (peer wins)", got)
	}
	// PeerRecvWin -1 = sentinel (no advertisement yet) → use CongWin
	c = &Connection{CongWin: 2048, PeerRecvWin: -1}
	if got := c.EffectiveWindow(); got != 2048 {
		t.Errorf("got %d, want 2048", got)
	}
	// CongWin 0 → fall back to InitialCongWin; PeerRecvWin -1 = sentinel
	c = &Connection{CongWin: 0, PeerRecvWin: -1}
	if got := c.EffectiveWindow(); got != InitialCongWin {
		t.Errorf("got %d, want %d", got, InitialCongWin)
	}
}

func TestWindowAvailable(t *testing.T) {
	t.Parallel()
	// PeerRecvWin -1 = sentinel (no advertisement received yet) → use CongWin.
	c := &Connection{CongWin: 10, PeerRecvWin: -1}
	c.TrackSend(1, []byte("abcde")) // 5 in flight, win 10
	if !c.WindowAvailable() {
		t.Error("expected available")
	}
	c.TrackSend(6, []byte("fghij")) // 10 in flight
	if c.WindowAvailable() {
		t.Error("expected full")
	}
}

// ---------------------------------------------------------------------------
// SACKBlocks + hasOOOSeg + ProcessSACK
// ---------------------------------------------------------------------------

func TestSACKBlocksEmpty(t *testing.T) {
	t.Parallel()
	c := &Connection{}
	if got := c.SACKBlocks(); got != nil {
		t.Errorf("empty OOOBuf: got %v, want nil", got)
	}
}

func TestSACKBlocksMergesContiguous(t *testing.T) {
	t.Parallel()
	c := &Connection{OOOBuf: []*recvSegment{
		{seq: 200, data: []byte("ccc")},
		{seq: 100, data: []byte("aaa")},
		{seq: 103, data: []byte("bbb")},
	}}
	blocks := c.SACKBlocks()
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want 2", len(blocks))
	}
	if blocks[0] != (SACKBlock{100, 106}) {
		t.Errorf("block 0 = %+v, want {100,106}", blocks[0])
	}
	if blocks[1] != (SACKBlock{200, 203}) {
		t.Errorf("block 1 = %+v, want {200,203}", blocks[1])
	}
}

func TestSACKBlocksLimitedToFour(t *testing.T) {
	t.Parallel()
	var bufs []*recvSegment
	for i := uint32(0); i < 6; i++ {
		// non-contiguous: seq 0, 10, 20, 30, 40, 50 with 3-byte segments
		bufs = append(bufs, &recvSegment{seq: i * 10, data: []byte("xxx")})
	}
	c := &Connection{OOOBuf: bufs}
	blocks := c.SACKBlocks()
	if len(blocks) != 4 {
		t.Errorf("got %d blocks, want 4 (limit)", len(blocks))
	}
}

func TestHasOOOSeg(t *testing.T) {
	t.Parallel()
	c := &Connection{OOOBuf: []*recvSegment{{seq: 100, data: []byte("x")}}}
	if !c.hasOOOSeg(100) {
		t.Error("hasOOOSeg(100) should be true")
	}
	if c.hasOOOSeg(101) {
		t.Error("hasOOOSeg(101) should be false")
	}
}

func TestProcessSACKMarksEntries(t *testing.T) {
	t.Parallel()
	c := &Connection{}
	c.TrackSend(100, []byte("hello"))
	c.TrackSend(200, []byte("world"))
	c.TrackSend(300, []byte("!!!"))
	// Mark middle entry only
	c.ProcessSACK([]SACKBlock{{Left: 200, Right: 205}})
	if !c.Unacked[1].sacked {
		t.Error("middle entry should be sacked")
	}
	if c.Unacked[0].sacked || c.Unacked[2].sacked {
		t.Error("non-matching entries should not be sacked")
	}
}

// ---------------------------------------------------------------------------
// CloseRecvBuf + DeliverInOrder basic paths
// ---------------------------------------------------------------------------

func TestCloseRecvBufIdempotent(t *testing.T) {
	t.Parallel()
	c := &Connection{RecvBuf: make(chan []byte, 1)}
	c.CloseRecvBuf()
	c.CloseRecvBuf() // would panic on double-close without sync.Once
	if !c.RecvClosed {
		t.Error("RecvClosed should be true")
	}
	select {
	case _, ok := <-c.RecvBuf:
		if ok {
			t.Error("RecvBuf should be closed")
		}
	default:
		t.Error("RecvBuf receive did not succeed on closed channel")
	}
}

func TestDeliverInOrderInOrderAdvancesExpected(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 4),
		ExpectedSeq: 100,
	}
	next := c.DeliverInOrder(100, []byte("hello"))
	if next != 105 {
		t.Errorf("got next=%d, want 105", next)
	}
	select {
	case got := <-c.RecvBuf:
		if string(got) != "hello" {
			t.Errorf("delivered %q", got)
		}
	default:
		t.Error("nothing delivered")
	}
}

func TestDeliverInOrderBuffersOutOfOrder(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 4),
		ExpectedSeq: 100,
	}
	// Arrives before 100 — should buffer
	next := c.DeliverInOrder(105, []byte("world"))
	if next != 100 {
		t.Errorf("OOO arrival: got next=%d, want 100", next)
	}
	if len(c.OOOBuf) != 1 {
		t.Fatalf("OOOBuf len = %d, want 1", len(c.OOOBuf))
	}
	// Now deliver 100 — should drain 105 too
	next = c.DeliverInOrder(100, []byte("hello"))
	if next != 110 {
		t.Errorf("after fill: got next=%d, want 110", next)
	}
	if len(c.OOOBuf) != 0 {
		t.Errorf("OOOBuf should be drained, have %d", len(c.OOOBuf))
	}
}

func TestDeliverInOrderDuplicateIgnored(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 4),
		ExpectedSeq: 100,
	}
	// seq before ExpectedSeq — duplicate, must be ignored
	next := c.DeliverInOrder(90, []byte("old"))
	if next != 100 {
		t.Errorf("got %d, want 100 (duplicate ignored)", next)
	}
	if len(c.RecvBuf) != 0 {
		t.Error("nothing should be delivered")
	}
}

func TestDeliverInOrderOnClosedReturnsImmediately(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 4),
		ExpectedSeq: 100,
		RecvClosed:  true,
	}
	next := c.DeliverInOrder(100, []byte("x"))
	if next != 100 {
		t.Errorf("closed: got %d, want 100 unchanged", next)
	}
	if len(c.RecvBuf) != 0 {
		t.Error("nothing should be delivered when closed")
	}
}

// ---------------------------------------------------------------------------
// ValidateWebhookURL
// ---------------------------------------------------------------------------

func TestValidateWebhookURLAccepts(t *testing.T) {
	t.Parallel()
	ok := []string{
		"http://example.com/hook",
		"https://api.example.com/v1/events",
		"http://127.0.0.1:8080/x",
		"http://8.8.8.8/x",
	}
	for _, u := range ok {
		if err := ValidateWebhookURL(u); err != nil {
			t.Errorf("%s: unexpected error %v", u, err)
		}
	}
}

func TestValidateWebhookURLRejects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"bad scheme":           "ftp://example.com/x",
		"link-local":           "http://169.254.169.254/latest/meta-data/",
		"multicast link-local": "http://224.0.0.251/x",
		"gcp metadata host":    "http://metadata.google.internal/x",
		"gcp metadata alt":     "http://metadata.google.com/x",
	}
	for name, u := range cases {
		if err := ValidateWebhookURL(u); err == nil {
			t.Errorf("%s (%s): expected error", name, u)
		}
	}
}

func TestValidateWebhookURLUnparseable(t *testing.T) {
	t.Parallel()
	// net/url.Parse accepts almost everything, so use something genuinely invalid
	if err := ValidateWebhookURL("http://[::1:bad"); err == nil {
		t.Error("expected parse error")
	}
}

// ---------------------------------------------------------------------------
// isPrivateAddr / matchLANSubnet pure helpers
// ---------------------------------------------------------------------------

func TestIsPrivateAddr(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"192.168.1.5:4000":  true,
		"10.0.0.1:4000":     true,
		"172.16.5.4:4000":   true,
		"127.0.0.1:4000":    true,  // loopback
		"169.254.5.5:4000":  true,  // link-local unicast
		"8.8.8.8:4000":      false, // public
		"34.148.103.117:80": false, // public GCP
		"bad":               false, // SplitHostPort fails
		"host:80":           false, // not an IP
	}
	for in, want := range cases {
		if got := isPrivateAddr(in); got != want {
			t.Errorf("isPrivateAddr(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestMatchLANSubnet(t *testing.T) {
	t.Parallel()
	ours := []string{"192.168.1.5:4000", "10.0.0.5:4000"}
	// Same /24 as ours
	theirs := []interface{}{"192.168.1.99:4000"}
	if got := matchLANSubnet(ours, theirs); got != "192.168.1.99:4000" {
		t.Errorf("got %q, want match on 192.168.1.99", got)
	}
	// Different subnet
	if got := matchLANSubnet(ours, []interface{}{"192.168.2.99:4000"}); got != "" {
		t.Errorf("expected empty for different /24, got %q", got)
	}
	// Non-string element ignored
	if got := matchLANSubnet(ours, []interface{}{123, "not-an-addr", "10.0.0.99:80"}); got != "10.0.0.99:80" {
		t.Errorf("got %q, want 10.0.0.99:80 after skipping garbage", got)
	}
	// IPv6 peer skipped
	if got := matchLANSubnet(ours, []interface{}{"[fe80::1]:80"}); got != "" {
		t.Errorf("IPv6 peer should not match, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Endpoint / resolve cache helpers on Daemon
// ---------------------------------------------------------------------------

func TestCacheEndpointStoresAndRetrieves(t *testing.T) {
	t.Parallel()
	d := &Daemon{epCache: map[uint32]*endpointEntry{}}
	d.cacheEndpoint(42, "1.2.3.4:5")
	got, ok := d.cachedEndpoint(42)
	if !ok || got != "1.2.3.4:5" {
		t.Errorf("got (%q,%v), want (1.2.3.4:5,true)", got, ok)
	}
	// CachedEndpoint is the exported wrapper
	gotE, okE := d.CachedEndpoint(42)
	if !okE || gotE != "1.2.3.4:5" {
		t.Errorf("CachedEndpoint: got (%q,%v)", gotE, okE)
	}
}

func TestCachedEndpointMissing(t *testing.T) {
	t.Parallel()
	d := &Daemon{epCache: map[uint32]*endpointEntry{}}
	if got, ok := d.cachedEndpoint(999); ok || got != "" {
		t.Errorf("missing: got (%q,%v)", got, ok)
	}
}

func TestIsEndpointStale(t *testing.T) {
	t.Parallel()
	d := &Daemon{epCache: map[uint32]*endpointEntry{}}
	// Missing entry → stale
	if !d.isEndpointStale(1) {
		t.Error("missing should be stale")
	}
	// Fresh
	d.cacheEndpoint(1, "x")
	if d.isEndpointStale(1) {
		t.Error("fresh should not be stale")
	}
	// Force stale via direct mutation
	d.epCache[1].cachedAt = time.Now().Add(-EndpointCacheTTL - time.Second)
	if !d.isEndpointStale(1) {
		t.Error("expired should be stale")
	}
}

func TestCacheResolveRoundTrip(t *testing.T) {
	t.Parallel()
	d := &Daemon{resolveCache: map[uint32]*resolveEntry{}}
	if _, ok := d.cachedResolve(1); ok {
		t.Error("empty cache should miss")
	}
	payload := map[string]interface{}{"endpoint": "1.2.3.4:5"}
	d.cacheResolve(1, payload)
	got, ok := d.cachedResolve(1)
	if !ok || got["endpoint"] != "1.2.3.4:5" {
		t.Errorf("got (%v,%v)", got, ok)
	}
	// TTL expiry
	d.resolveCache[1].cachedAt = time.Now().Add(-ResolveCacheTTL - time.Second)
	if _, ok := d.cachedResolve(1); ok {
		t.Error("expired entry should miss")
	}
}

// ---------------------------------------------------------------------------
// knownNetworkSet / clearNetworkState
// ---------------------------------------------------------------------------

func TestKnownNetworkSetUnion(t *testing.T) {
	t.Parallel()
	// Note: post-T2.3 the daemon no longer holds policyRunners directly
	// (PolicyManager interface owns them). knownNetworkSet now derives
	// from the surfaces still on the daemon (netPolicies, managed,
	// memberTags). Test scope tightened to those.
	d := &Daemon{
		netPolicies: map[uint16][]uint16{1: {80}, 0: {}}, // 0 filtered out
		managed:     map[uint16]*ManagedEngine{3: {}},
		memberTags:  map[uint16][]string{4: {"tag"}},
	}
	set := d.knownNetworkSet()
	want := []uint16{1, 3, 4}
	if len(set) != len(want) {
		t.Errorf("got %v (len %d), want %v", set, len(set), want)
	}
	for _, n := range want {
		if !set[n] {
			t.Errorf("missing %d", n)
		}
	}
	if set[0] {
		t.Error("network 0 should be excluded from netPolicies iteration")
	}
}

func TestClearNetworkStateRemovesEntries(t *testing.T) {
	t.Parallel()
	d := &Daemon{
		netPolicies: map[uint16][]uint16{7: {80}},
		memberTags:  map[uint16][]string{7: {"a"}},
	}
	d.clearNetworkState(7)
	if _, ok := d.netPolicies[7]; ok {
		t.Error("netPolicies should be cleared")
	}
	if _, ok := d.memberTags[7]; ok {
		t.Error("memberTags should be cleared")
	}
}

// ---------------------------------------------------------------------------
// NodeID + GetManagedEngine + GetPolicyRunner accessor sanity
// ---------------------------------------------------------------------------

func TestNodeIDReturnsConfigured(t *testing.T) {
	t.Parallel()
	d := &Daemon{nodeID: 0xDEADBEEF}
	if got := d.NodeID(); got != 0xDEADBEEF {
		t.Errorf("got %08x, want DEADBEEF", got)
	}
}

func TestGetPolicyRunnerMissing(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	if got := d.GetPolicyRunner(99); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestGetManagedEngineMissing(t *testing.T) {
	t.Parallel()
	d := &Daemon{managed: map[uint16]*ManagedEngine{}}
	if got := d.GetManagedEngine(99); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// Satisfy binary/unused-import detector for edge cases
// ---------------------------------------------------------------------------
var _ = binary.BigEndian
