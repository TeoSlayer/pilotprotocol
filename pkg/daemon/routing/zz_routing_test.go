// SPDX-License-Identifier: AGPL-3.0-or-later

package routing_test

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/routing"
)

// ----------------------------------------------------------------------------
// Mocks / fakes
// ----------------------------------------------------------------------------

// fakeSocket is a routing.SocketSender implementation that records every
// frame written so tests can assert wire format.
type fakeSocket struct {
	mu       sync.Mutex
	sends    []sentFrame
	failWith error // if non-nil, Send returns this error and records nothing
}

type sentFrame struct {
	frame []byte
	dst   *net.UDPAddr
}

func (f *fakeSocket) Send(frame []byte, dst *net.UDPAddr) (int, error) {
	if f.failWith != nil {
		return 0, f.failWith
	}
	cp := make([]byte, len(frame))
	copy(cp, frame)
	f.mu.Lock()
	f.sends = append(f.sends, sentFrame{frame: cp, dst: dst})
	f.mu.Unlock()
	return len(frame), nil
}

func (f *fakeSocket) snapshot() []sentFrame {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]sentFrame, len(f.sends))
	copy(out, f.sends)
	return out
}

// fakeBeaconLister is a routing.BeaconLister implementation for FetchBeaconList
// tests.
type fakeBeaconLister struct {
	resp map[string]interface{}
	err  error
}

func (f *fakeBeaconLister) Send(_ map[string]interface{}) (map[string]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

// ----------------------------------------------------------------------------
// 1. Beacon FNV select
// ----------------------------------------------------------------------------

func TestPickBeacon_DeterministicSameKey(t *testing.T) {
	t.Parallel()
	list := []string{"a:1", "b:2", "c:3", "d:4"}
	key := []byte("identity-key-stable-bytes-1234")
	first := routing.PickBeacon(list, key)
	for i := 0; i < 100; i++ {
		got := routing.PickBeacon(list, key)
		if got != first {
			t.Fatalf("non-deterministic pick: %q != %q", got, first)
		}
	}
}

func TestPickBeacon_DifferentKeysSpread(t *testing.T) {
	t.Parallel()
	list := []string{"a:1", "b:2", "c:3", "d:4"}
	// Use varying-length keys with different bytes to defeat any unfortunate
	// modular alignment in FNV-32a output for tightly correlated inputs.
	keys := [][]byte{
		[]byte("alpha"),
		[]byte("beta-key-2"),
		[]byte("gamma"),
		[]byte("delta-something-different"),
		[]byte("epsilon"),
		[]byte("zeta"),
		[]byte("identity-of-node-42"),
		[]byte("identity-of-node-1337"),
		[]byte("ed25519-pubkey-bytes-aaaa"),
		[]byte("ed25519-pubkey-bytes-bbbb"),
		[]byte("ed25519-pubkey-bytes-cccc"),
		[]byte("ed25519-pubkey-bytes-dddd"),
		[]byte("x"),
		[]byte("xx"),
		[]byte("xxx"),
		[]byte("xxxx"),
	}
	picks := map[string]struct{}{}
	for _, k := range keys {
		picks[routing.PickBeacon(list, k)] = struct{}{}
	}
	if len(picks) < 2 {
		t.Fatalf("expected >=2 distinct picks across varied keys, got %d (%v)", len(picks), picks)
	}
}

func TestPickBeacon_DifferentKeysCanDiffer(t *testing.T) {
	t.Parallel()
	list := []string{"a:1", "b:2", "c:3"}
	// Try several key pairs; at least one pair must produce different picks
	// (otherwise FNV is degenerate).
	differs := false
	for i := 0; i < 32; i++ {
		k1 := []byte{byte(i)}
		k2 := []byte{byte(i + 1), 0xff}
		if routing.PickBeacon(list, k1) != routing.PickBeacon(list, k2) {
			differs = true
			break
		}
	}
	if !differs {
		t.Fatal("expected at least one differing key pair to produce different picks")
	}
}

func TestPickBeacon_EmptyAndSingle(t *testing.T) {
	t.Parallel()
	if got := routing.PickBeacon(nil, []byte("k")); got != "" {
		t.Fatalf("empty list should return \"\", got %q", got)
	}
	if got := routing.PickBeacon([]string{"only:1"}, []byte("any")); got != "only:1" {
		t.Fatalf("single-entry list should always return that entry, got %q", got)
	}
}

// ----------------------------------------------------------------------------
// 2. ComputeRefreshDecision
// ----------------------------------------------------------------------------

func TestComputeRefreshDecision_InitialPick(t *testing.T) {
	t.Parallel()
	state := routing.NewBeaconSelectionState([]string{"boot:1"})
	d := routing.ComputeRefreshDecision(state, []string{"disc1:1", "disc2:2"}, []byte("k"))
	if !d.ShouldSwap {
		t.Fatal("first decision must swap (currentPick is empty)")
	}
	if d.NewPick == "" {
		t.Fatal("NewPick must be non-empty when list is non-empty")
	}
	if len(d.NewList) != 3 {
		t.Fatalf("expected 3 merged entries, got %d", len(d.NewList))
	}
}

func TestComputeRefreshDecision_NoSwapWhenStable(t *testing.T) {
	t.Parallel()
	state := routing.NewBeaconSelectionState([]string{"boot:1", "boot:2"})
	key := []byte("stable-key")
	d1 := routing.ComputeRefreshDecision(state, nil, key)
	state.ApplyRefreshDecision(d1)
	d2 := routing.ComputeRefreshDecision(state, nil, key)
	if d2.ShouldSwap {
		t.Fatalf("identical input should not swap; pick was %q", d2.NewPick)
	}
}

func TestComputeRefreshDecision_EmptyInputs(t *testing.T) {
	t.Parallel()
	state := routing.NewBeaconSelectionState(nil)
	d := routing.ComputeRefreshDecision(state, nil, []byte("k"))
	if d.ShouldSwap || d.NewPick != "" || len(d.NewList) != 0 {
		t.Fatalf("empty inputs should yield empty no-swap decision: %+v", d)
	}
}

func TestComputeRefreshDecision_SingleBootstrap(t *testing.T) {
	t.Parallel()
	state := routing.NewBeaconSelectionState([]string{"only:9000"})
	d := routing.ComputeRefreshDecision(state, nil, []byte("any"))
	if d.NewPick != "only:9000" {
		t.Fatalf("single-bootstrap pick should be that entry, got %q", d.NewPick)
	}
	if !d.ShouldSwap {
		t.Fatal("first pick must swap")
	}
}

func TestComputeRefreshDecision_SwapWhenCurrentRemoved(t *testing.T) {
	t.Parallel()
	state := routing.NewBeaconSelectionState([]string{"a:1", "b:2"})
	key := []byte("k")
	d1 := routing.ComputeRefreshDecision(state, nil, key)
	state.ApplyRefreshDecision(d1)
	prev := state.GetCurrentPick()
	if prev == "" {
		t.Fatal("expected non-empty initial pick")
	}
	// Simulate operator-config that drops `prev` from bootstrap by building a
	// fresh state without it. Use whatever survives.
	var survivor string
	if prev == "a:1" {
		survivor = "b:2"
	} else {
		survivor = "a:1"
	}
	state2 := routing.NewBeaconSelectionState([]string{survivor})
	// seed currentPick = prev so we can detect "no longer present" branch.
	state2.ApplyRefreshDecision(routing.RefreshDecision{
		NewList:    []string{prev},
		NewPick:    prev,
		ShouldSwap: true,
	})
	d2 := routing.ComputeRefreshDecision(state2, nil, key)
	if !d2.ShouldSwap {
		t.Fatalf("removed-current should force swap; got %+v", d2)
	}
	if d2.NewPick != survivor {
		t.Fatalf("expected NewPick=%q, got %q", survivor, d2.NewPick)
	}
}

// ----------------------------------------------------------------------------
// 3. Beacon cache I/O
// ----------------------------------------------------------------------------

func TestBeaconCache_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.json")
	addrs := []string{"beacon1.example.com:9001", "beacon2.example.com:9001"}

	if err := routing.SaveBeaconCache(identityPath, addrs); err != nil {
		t.Fatalf("SaveBeaconCache: %v", err)
	}
	got, err := routing.LoadBeaconCache(identityPath)
	if err != nil {
		t.Fatalf("LoadBeaconCache: %v", err)
	}
	if len(got) != len(addrs) {
		t.Fatalf("expected %d addrs, got %d (%v)", len(addrs), len(got), got)
	}
	for i, a := range addrs {
		if got[i] != a {
			t.Fatalf("addr[%d]: want %q got %q", i, a, got[i])
		}
	}
}

func TestBeaconCache_MissingPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "no-such-identity.json")
	got, err := routing.LoadBeaconCache(identityPath)
	if err != nil {
		t.Fatalf("expected nil error on missing cache, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result on missing cache, got %v", got)
	}
}

func TestBeaconCache_EmptyIdentityPath(t *testing.T) {
	t.Parallel()
	if err := routing.SaveBeaconCache("", []string{"x:1"}); err != nil {
		t.Fatalf("SaveBeaconCache(\"\") should be no-op nil, got %v", err)
	}
	got, err := routing.LoadBeaconCache("")
	if err != nil {
		t.Fatalf("LoadBeaconCache(\"\") should be no-op nil, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result, got %v", got)
	}
}

func TestBeaconCache_FiltersUnreachableOnLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "id.json")
	// Write a cache that includes an RFC1918 entry on disk; LoadBeaconCache
	// must drop it.
	mixed := []string{"203.0.113.1:9001", "10.0.0.5:9001", "127.0.0.1:9001"}
	if err := routing.SaveBeaconCache(identityPath, mixed); err != nil {
		t.Fatalf("SaveBeaconCache: %v", err)
	}
	got, err := routing.LoadBeaconCache(identityPath)
	if err != nil {
		t.Fatalf("LoadBeaconCache: %v", err)
	}
	for _, a := range got {
		host, _, _ := net.SplitHostPort(a)
		ip := net.ParseIP(host)
		if ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
			t.Fatalf("LoadBeaconCache returned unreachable %q", a)
		}
	}
	if len(got) != 1 || got[0] != "203.0.113.1:9001" {
		t.Fatalf("expected just public addr, got %v", got)
	}
}

// ----------------------------------------------------------------------------
// 4. Relay state
// ----------------------------------------------------------------------------

func TestRelay_SetAndQuery(t *testing.T) {
	t.Parallel()
	m := routing.New()
	if m.IsRelayPeer(42) {
		t.Fatal("fresh manager should not have peer 42 in relay")
	}
	m.SetRelayPeer(42, true)
	if !m.IsRelayPeer(42) {
		t.Fatal("SetRelayPeer(true) not reflected")
	}
	if m.IsRelayPinned(42) {
		t.Fatal("SetRelayPeer must not pin")
	}
	if c := m.RelayPeerCount(); c != 1 {
		t.Fatalf("RelayPeerCount=%d want 1", c)
	}
}

func TestRelay_Pinned(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetRelayPeerPinned(7, true)
	if !m.IsRelayPeer(7) || !m.IsRelayPinned(7) {
		t.Fatal("SetRelayPeerPinned should set both flag and pin")
	}
	// Pinned peers must NOT auto-clear on direct observations —
	// registry relay_only=true and beacon-admitted symmetric-NAT peers
	// require an explicit SetRelayPeerPinned(id, false) to leave relay.
	stray := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 4000}
	cleared := m.ClearRelayOnDirect(7, stray)
	if cleared {
		t.Fatal("ClearRelayOnDirect must not clear pinned peers")
	}
	if !m.IsRelayPeer(7) {
		t.Fatal("pinned peer still must be relay after ClearRelayOnDirect")
	}
	if !m.IsRelayPinned(7) {
		t.Fatal("pin must persist")
	}
}

func TestRelay_PinnedClearExplicit(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetRelayPeerPinned(9, true)
	m.SetRelayPeerPinned(9, false)
	if m.IsRelayPinned(9) {
		t.Fatal("explicit pin-clear must drop pin")
	}
}

func TestRelay_UnpinnedClearsAfterDirectThreshold(t *testing.T) {
	t.Parallel()
	m := routing.New()
	// SetRelayPeer (not Pinned) — dial-timeout relay, not authoritative.
	m.SetRelayPeer(13, true)
	if !m.IsRelayPeer(13) {
		t.Fatal("SetRelayPeer: relay flag must be set")
	}
	from := &net.UDPAddr{IP: net.ParseIP("198.51.100.13"), Port: 4000}
	for i := 0; i < routing.DirectClearsRequired-1; i++ {
		cleared := m.ClearRelayOnDirect(13, from)
		if cleared {
			t.Fatalf("must not clear before %d direct receipts (iter %d)", routing.DirectClearsRequired, i)
		}
		if !m.IsRelayPeer(13) {
			t.Fatalf("still relay after %d direct receipts", i+1)
		}
	}
	cleared := m.ClearRelayOnDirect(13, from)
	if !cleared {
		t.Fatalf("must clear relay after %d consecutive direct receipts", routing.DirectClearsRequired)
	}
	if m.IsRelayPeer(13) {
		t.Fatal("relay flag must be false after auto-clear")
	}
}

func TestRelay_RemovePeerWipesState(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetRelayPeerPinned(11, true)
	m.RecordDirectRecv(11, time.Now())
	m.RemovePeer(11)
	if m.IsRelayPeer(11) || m.IsRelayPinned(11) || m.HasDirectRecv(11) {
		t.Fatal("RemovePeer should wipe all per-peer state")
	}
}

// ----------------------------------------------------------------------------
// 5. Blackhole — 3 misses in 8s asserts; 1 success resets
// ----------------------------------------------------------------------------

func TestBlackhole_NoBeaconNoFlip(t *testing.T) {
	t.Parallel()
	m := routing.New()
	// No beacon set → MaybeFlipBlackhole always returns false.
	m.RecordDirectRecv(1, time.Now().Add(-1*time.Hour))
	shouldRelay, flipped, _, _ := m.MaybeFlipBlackhole(1)
	if shouldRelay || flipped {
		t.Fatalf("no beacon → no flip; got shouldRelay=%v flipped=%v", shouldRelay, flipped)
	}
}

func TestBlackhole_ThreeMissesFlips(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetBeaconAddrUDP(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001})
	// Stamp last direct recv well past the 8s threshold.
	stale := time.Now().Add(-(routing.DirectBlackholeThreshold + time.Second))
	m.RecordDirectRecv(1, stale)

	// First miss
	r1, f1, _, miss1 := m.MaybeFlipBlackhole(1)
	if r1 || f1 || miss1 != 1 {
		t.Fatalf("miss 1: shouldRelay=%v flipped=%v misses=%d", r1, f1, miss1)
	}
	// Second miss
	r2, f2, _, miss2 := m.MaybeFlipBlackhole(1)
	if r2 || f2 || miss2 != 2 {
		t.Fatalf("miss 2: shouldRelay=%v flipped=%v misses=%d", r2, f2, miss2)
	}
	// Third miss → flip
	r3, f3, _, miss3 := m.MaybeFlipBlackhole(1)
	if !r3 || !f3 {
		t.Fatalf("miss 3 should flip: shouldRelay=%v flipped=%v misses=%d", r3, f3, miss3)
	}
	if !m.IsRelayPeer(1) {
		t.Fatal("after flip, peer should be in relay")
	}
	if !m.IsRelayPinned(1) {
		t.Fatal("blackhole flip must pin")
	}
}

func TestBlackhole_FreshDirectRecvResets(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetBeaconAddrUDP(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001})
	stale := time.Now().Add(-(routing.DirectBlackholeThreshold + time.Second))
	m.RecordDirectRecv(2, stale)
	// Accumulate 2 misses
	m.MaybeFlipBlackhole(2)
	m.MaybeFlipBlackhole(2)
	if c := m.BlackholeMissCount(2); c != 2 {
		t.Fatalf("expected 2 misses, got %d", c)
	}
	// Fresh direct recv resets miss counter.
	from := &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 4000}
	m.ClearRelayOnDirect(2, from)
	if c := m.BlackholeMissCount(2); c != 0 {
		t.Fatalf("expected miss count cleared after direct recv, got %d", c)
	}
}

func TestBlackhole_RecentDirectRecvNoMiss(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetBeaconAddrUDP(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001})
	m.RecordDirectRecv(3, time.Now()) // recent
	for i := 0; i < 5; i++ {
		shouldRelay, flipped, _, _ := m.MaybeFlipBlackhole(3)
		if shouldRelay || flipped {
			t.Fatalf("recent direct recv must not flip (iter %d)", i)
		}
	}
	if m.BlackholeMissCount(3) != 0 {
		t.Fatal("recent direct recv should never increment miss count")
	}
}

func TestBlackhole_HandleSendErrorICMP(t *testing.T) {
	t.Parallel()
	m := routing.New()
	for i := 0; i < routing.SendErrThreshold-1; i++ {
		flipped, _ := m.HandleSendError(99, syscall.ECONNREFUSED)
		if flipped {
			t.Fatalf("flipped early at i=%d", i)
		}
	}
	flipped, count := m.HandleSendError(99, syscall.ECONNREFUSED)
	if !flipped {
		t.Fatalf("expected flip at threshold; count=%d", count)
	}
	if !m.IsRelayPeer(99) || !m.IsRelayPinned(99) {
		t.Fatal("ICMP-threshold flip must set + pin")
	}
}

func TestBlackhole_HandleSendErrorNonICMP(t *testing.T) {
	t.Parallel()
	m := routing.New()
	for i := 0; i < routing.SendErrThreshold*2; i++ {
		flipped, _ := m.HandleSendError(100, errors.New("generic write error"))
		if flipped {
			t.Fatal("non-ICMP error must never flip")
		}
	}
	if m.IsRelayPeer(100) {
		t.Fatal("peer should not be in relay from non-ICMP errors")
	}
}

// ----------------------------------------------------------------------------
// 6. WriteFrame relay decision
// ----------------------------------------------------------------------------

func TestWriteFrame_DirectWhenNotPinned(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetLocalNodeIDFn(func() uint32 { return 0xCAFEBABE })
	sock := &fakeSocket{}
	m.SetSocket(sock)

	dst := &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 4000}
	frame := []byte{0x50, 0x49, 0x4C, 0x53, 0xde, 0xad, 0xbe, 0xef}
	out, err := m.WriteFrame(0xAAAA, dst, frame, routing.CounterTarget{})
	if err != nil {
		t.Fatalf("WriteFrame direct: %v", err)
	}
	if out.WasRelay {
		t.Fatal("expected direct, got relay")
	}
	if out.BytesSent != len(frame) {
		t.Fatalf("BytesSent=%d, want %d", out.BytesSent, len(frame))
	}
	got := sock.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 send, got %d", len(got))
	}
	if !addrsEqual(got[0].dst, dst) {
		t.Fatalf("dst: got %v want %v", got[0].dst, dst)
	}
	if !equalBytes(got[0].frame, frame) {
		t.Fatalf("frame mismatch: got %x want %x", got[0].frame, frame)
	}
}

func TestWriteFrame_RelayWhenPinned(t *testing.T) {
	t.Parallel()
	m := routing.New()
	const ourID uint32 = 0x11223344
	const peerID uint32 = 0xAABBCCDD
	m.SetLocalNodeIDFn(func() uint32 { return ourID })
	beacon := &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 9001}
	m.SetBeaconAddrUDP(beacon)
	m.SetRelayPeerPinned(peerID, true)
	sock := &fakeSocket{}
	m.SetSocket(sock)

	frame := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02}
	out, err := m.WriteFrame(peerID, nil, frame, routing.CounterTarget{})
	if err != nil {
		t.Fatalf("WriteFrame relay: %v", err)
	}
	if !out.WasRelay {
		t.Fatal("expected relay, got direct")
	}
	got := sock.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 send, got %d", len(got))
	}
	if !addrsEqual(got[0].dst, beacon) {
		t.Fatalf("relay dst: got %v want beacon %v", got[0].dst, beacon)
	}
	wire := got[0].frame
	if len(wire) != 1+4+4+len(frame) {
		t.Fatalf("relay-wire len=%d want %d", len(wire), 1+4+4+len(frame))
	}
	if wire[0] != protocol.BeaconMsgRelay {
		t.Fatalf("wire[0]=0x%02x want 0x%02x (BeaconMsgRelay)", wire[0], protocol.BeaconMsgRelay)
	}
	if got := binary.BigEndian.Uint32(wire[1:5]); got != ourID {
		t.Fatalf("sender nodeID=0x%08x want 0x%08x", got, ourID)
	}
	if got := binary.BigEndian.Uint32(wire[5:9]); got != peerID {
		t.Fatalf("dst nodeID=0x%08x want 0x%08x", got, peerID)
	}
	if !equalBytes(wire[9:], frame) {
		t.Fatalf("payload mismatch: got %x want %x", wire[9:], frame)
	}
}

// TestWriteFrame_ForceRelayWrapsFreshPeer pins compat-mode behavior:
// when forceRelay is set, every outbound — even to a fresh peer with
// no prior blackhole observations — must be wrapped in BeaconMsgRelay
// and addressed to the beacon. Regression test for the v1.10.1 bug
// where managed-claw daemons silently failed to talk to UDP-only
// peers because the first send went raw through the WSS pipe and the
// beacon dropped it as an unknown protocol packet.
func TestWriteFrame_ForceRelayWrapsFreshPeer(t *testing.T) {
	t.Parallel()
	m := routing.New()
	const ourID uint32 = 0xC0FFEE01
	const peerID uint32 = 0xBADCAFE0
	m.SetLocalNodeIDFn(func() uint32 { return ourID })
	beacon := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 9001}
	m.SetBeaconAddrUDP(beacon)
	sock := &fakeSocket{}
	m.SetSocket(sock)

	// Critical: peer is FRESH — no SetRelayPeer / SetRelayPeerPinned /
	// blackhole flips. Only forceRelay is on.
	m.SetForceRelay(true)
	if !m.ForceRelay() {
		t.Fatal("ForceRelay() returned false after SetForceRelay(true)")
	}

	// addr is nil — caller doesn't even know the peer's direct UDP
	// endpoint yet. This mirrors the real compat-mode caller, where
	// peers maps only get populated after the first relay reply.
	frame := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	out, err := m.WriteFrame(peerID, nil, frame, routing.CounterTarget{})
	if err != nil {
		t.Fatalf("WriteFrame with forceRelay should not error on fresh peer: %v", err)
	}
	if !out.WasRelay {
		t.Fatal("expected relay-wrapped send under forceRelay, got direct")
	}

	got := sock.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 send, got %d", len(got))
	}
	if !addrsEqual(got[0].dst, beacon) {
		t.Fatalf("dst: got %v want beacon %v", got[0].dst, beacon)
	}
	wire := got[0].frame
	if len(wire) != 1+4+4+len(frame) {
		t.Fatalf("wire len=%d want %d", len(wire), 1+4+4+len(frame))
	}
	if wire[0] != protocol.BeaconMsgRelay {
		t.Fatalf("wire[0]=0x%02x want 0x%02x (BeaconMsgRelay)", wire[0], protocol.BeaconMsgRelay)
	}
	if got := binary.BigEndian.Uint32(wire[1:5]); got != ourID {
		t.Fatalf("sender nodeID=0x%08x want 0x%08x", got, ourID)
	}
	if got := binary.BigEndian.Uint32(wire[5:9]); got != peerID {
		t.Fatalf("dst nodeID=0x%08x want 0x%08x", got, peerID)
	}
	if !equalBytes(wire[9:], frame) {
		t.Fatalf("payload mismatch: got %x want %x", wire[9:], frame)
	}
}

func TestWriteFrame_NoAddressNoBeacon(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetLocalNodeIDFn(func() uint32 { return 1 })
	sock := &fakeSocket{}
	m.SetSocket(sock)
	_, err := m.WriteFrame(7, nil, []byte{1, 2, 3}, routing.CounterTarget{})
	if !errors.Is(err, routing.ErrNoAddress) {
		t.Fatalf("expected ErrNoAddress, got %v", err)
	}
}

func TestWriteFrame_BumpsCounters(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetLocalNodeIDFn(func() uint32 { return 1 })
	sock := &fakeSocket{}
	m.SetSocket(sock)
	var pkts, bytes uint64
	dst := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4000}
	frame := []byte{0xAA, 0xBB, 0xCC}
	if _, err := m.WriteFrame(2, dst, frame, routing.CounterTarget{
		PktsSent:  &pkts,
		BytesSent: &bytes,
	}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if pkts != 1 {
		t.Fatalf("pkts=%d want 1", pkts)
	}
	if bytes != uint64(len(frame)) {
		t.Fatalf("bytes=%d want %d", bytes, len(frame))
	}
}

// ----------------------------------------------------------------------------
// 7. NAT punch — RegisterWithBeacon, RequestHolePunch, HandlePunchCommand
// ----------------------------------------------------------------------------

func TestRegisterWithBeacon_NoBeaconNoOp(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetLocalNodeIDFn(func() uint32 { return 1 })
	sock := &fakeSocket{}
	m.SetSocket(sock)
	if err := m.RegisterWithBeacon(); err != nil {
		t.Fatalf("RegisterWithBeacon (no beacon): %v", err)
	}
	if got := sock.snapshot(); len(got) != 0 {
		t.Fatalf("no beacon configured → no send; got %d", len(got))
	}
}

func TestRegisterWithBeacon_SendsDiscover(t *testing.T) {
	t.Parallel()
	m := routing.New()
	const ourID uint32 = 0xBADF00D
	m.SetLocalNodeIDFn(func() uint32 { return ourID })
	beacon := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 9001}
	m.SetBeaconAddrUDP(beacon)
	sock := &fakeSocket{}
	m.SetSocket(sock)

	if err := m.RegisterWithBeacon(); err != nil {
		t.Fatalf("RegisterWithBeacon: %v", err)
	}
	got := sock.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 send, got %d", len(got))
	}
	if !addrsEqual(got[0].dst, beacon) {
		t.Fatalf("dst: got %v want %v", got[0].dst, beacon)
	}
	wire := got[0].frame
	if len(wire) != 5 {
		t.Fatalf("discover frame len=%d want 5", len(wire))
	}
	if wire[0] != protocol.BeaconMsgDiscover {
		t.Fatalf("wire[0]=0x%02x want 0x%02x (BeaconMsgDiscover)", wire[0], protocol.BeaconMsgDiscover)
	}
	if got := binary.BigEndian.Uint32(wire[1:5]); got != ourID {
		t.Fatalf("nodeID=0x%08x want 0x%08x", got, ourID)
	}
}

func TestRequestHolePunch_SendsPunchRequest(t *testing.T) {
	t.Parallel()
	m := routing.New()
	const ourID uint32 = 0xA5A5A5A5
	const targetID uint32 = 0x5A5A5A5A
	m.SetLocalNodeIDFn(func() uint32 { return ourID })
	beacon := &net.UDPAddr{IP: net.ParseIP("198.51.100.30"), Port: 9001}
	m.SetBeaconAddrUDP(beacon)
	sock := &fakeSocket{}
	m.SetSocket(sock)

	if err := m.RequestHolePunch(targetID); err != nil {
		t.Fatalf("RequestHolePunch: %v", err)
	}
	got := sock.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 send, got %d", len(got))
	}
	if !addrsEqual(got[0].dst, beacon) {
		t.Fatalf("dst should be beacon: got %v want %v", got[0].dst, beacon)
	}
	wire := got[0].frame
	if len(wire) != 9 {
		t.Fatalf("punch-request frame len=%d want 9", len(wire))
	}
	if wire[0] != protocol.BeaconMsgPunchRequest {
		t.Fatalf("wire[0]=0x%02x want 0x%02x (BeaconMsgPunchRequest)", wire[0], protocol.BeaconMsgPunchRequest)
	}
	if v := binary.BigEndian.Uint32(wire[1:5]); v != ourID {
		t.Fatalf("our nodeID=0x%08x want 0x%08x", v, ourID)
	}
	if v := binary.BigEndian.Uint32(wire[5:9]); v != targetID {
		t.Fatalf("target nodeID=0x%08x want 0x%08x", v, targetID)
	}
}

func TestRequestHolePunch_NoBeaconNoOp(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetLocalNodeIDFn(func() uint32 { return 1 })
	sock := &fakeSocket{}
	m.SetSocket(sock)
	if err := m.RequestHolePunch(99); err != nil {
		t.Fatalf("RequestHolePunch (no beacon): %v", err)
	}
	if got := sock.snapshot(); len(got) != 0 {
		t.Fatalf("no beacon → no send; got %d", len(got))
	}
}

// ----------------------------------------------------------------------------
// 8. HandlePunchCommand — dispatches/sends punch packets, drops bad bytes
// ----------------------------------------------------------------------------

func TestHandlePunchCommand_SendsPunchPackets(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetLocalNodeIDFn(func() uint32 { return 1 })
	sock := &fakeSocket{}
	m.SetSocket(sock)

	// Format: [iplen(1)][IP(4 or 16)][port(2)]
	target := net.ParseIP("203.0.113.50").To4()
	data := make([]byte, 1+4+2)
	data[0] = 4
	copy(data[1:5], target)
	binary.BigEndian.PutUint16(data[5:7], 4444)
	m.HandlePunchCommand(data)

	got := sock.snapshot()
	// Implementation sends 3 punch packets.
	if len(got) != 3 {
		t.Fatalf("expected 3 punch sends, got %d", len(got))
	}
	wantDst := &net.UDPAddr{IP: target, Port: 4444}
	for i, s := range got {
		if !addrsEqual(s.dst, wantDst) {
			t.Fatalf("punch %d dst: got %v want %v", i, s.dst, wantDst)
		}
		if len(s.frame) != 4 {
			t.Fatalf("punch %d frame len=%d want 4", i, len(s.frame))
		}
		if !equalBytes(s.frame, protocol.TunnelMagicPunch[:]) {
			t.Fatalf("punch %d magic mismatch: got %x want %x", i, s.frame, protocol.TunnelMagicPunch[:])
		}
	}
}

func TestHandlePunchCommand_BadBytesNoPanicNoSend(t *testing.T) {
	t.Parallel()
	m := routing.New()
	m.SetLocalNodeIDFn(func() uint32 { return 1 })
	sock := &fakeSocket{}
	m.SetSocket(sock)

	cases := [][]byte{
		nil,                            // empty
		{},                             // empty
		{0x05},                         // bad iplen
		{0x04, 1, 2, 3},                // truncated IPv4 (no port)
		{0x10, 1, 2, 3, 4, 5, 6, 7, 8}, // claims IPv6 but payload too short
	}
	for i, c := range cases {
		// Should not panic, should not send.
		m.HandlePunchCommand(c)
		if got := sock.snapshot(); len(got) != 0 {
			t.Fatalf("case %d: expected 0 sends for bad bytes, got %d", i, len(got))
		}
	}
}

// ----------------------------------------------------------------------------
// MarkRelayActivatedIfHadCrypto — relay-deliver dispatch surface
// ----------------------------------------------------------------------------

func TestMarkRelayActivatedIfHadCrypto_NewPeer(t *testing.T) {
	t.Parallel()
	m := routing.New()
	admitted, newly, alias := m.MarkRelayActivatedIfHadCrypto(123, true)
	if !admitted || !newly || !alias {
		t.Fatalf("new peer with crypto: admitted=%v newly=%v alias=%v", admitted, newly, alias)
	}
	if !m.IsRelayPeer(123) {
		t.Fatal("peer should be in relay after activation")
	}
}

func TestMarkRelayActivatedIfHadCrypto_NoCrypto(t *testing.T) {
	t.Parallel()
	m := routing.New()
	admitted, newly, alias := m.MarkRelayActivatedIfHadCrypto(123, false)
	if !admitted {
		t.Fatal("no-crypto path should still be admitted (caller drops/queues separately)")
	}
	if newly || alias {
		t.Fatalf("no-crypto must not newly-activate or alias: newly=%v alias=%v", newly, alias)
	}
	if m.IsRelayPeer(123) {
		t.Fatal("no-crypto path should not flip peer to relay")
	}
}

// ----------------------------------------------------------------------------
// FetchBeaconList / discovery helpers (registry mock)
// ----------------------------------------------------------------------------

func TestFetchBeaconList_NilClient(t *testing.T) {
	t.Parallel()
	if _, err := routing.FetchBeaconList(nil); err == nil {
		t.Fatal("expected error on nil client")
	}
}

func TestFetchBeaconList_HappyPath(t *testing.T) {
	t.Parallel()
	lister := &fakeBeaconLister{
		resp: map[string]interface{}{
			"beacons": []interface{}{
				map[string]interface{}{"addr": "203.0.113.10:9001"},
				map[string]interface{}{"addr": "10.0.0.5:9001"}, // RFC1918 → filtered
				map[string]interface{}{"addr": ""},              // empty → filtered
				map[string]interface{}{"other": "k"},            // missing → filtered
				map[string]interface{}{"addr": "198.51.100.20:9001"},
			},
		},
	}
	got, err := routing.FetchBeaconList(lister)
	if err != nil {
		t.Fatalf("FetchBeaconList: %v", err)
	}
	// 10.0.0.5 must be dropped, sorted ascending.
	want := []string{"198.51.100.20:9001", "203.0.113.10:9001"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d, got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestFetchBeaconList_SendError(t *testing.T) {
	t.Parallel()
	lister := &fakeBeaconLister{err: errors.New("net down")}
	if _, err := routing.FetchBeaconList(lister); err == nil {
		t.Fatal("expected error from underlying Send")
	}
}

func TestFetchBeaconList_NoBeaconsKey(t *testing.T) {
	t.Parallel()
	lister := &fakeBeaconLister{resp: map[string]interface{}{"other": "x"}}
	got, err := routing.FetchBeaconList(lister)
	if err != nil {
		t.Fatalf("FetchBeaconList: %v", err)
	}
	if got != nil {
		t.Fatalf("missing beacons key → nil; got %v", got)
	}
}

// ----------------------------------------------------------------------------
// ParseBeaconList / FilterUnreachable / IsUnreachableBeaconHost
// ----------------------------------------------------------------------------

func TestParseBeaconList(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a:1", []string{"a:1"}},
		{"a:1,b:2,c:3", []string{"a:1", "b:2", "c:3"}},
		{" a:1 , , b:2 ", []string{"a:1", "b:2"}},
	}
	for _, c := range cases {
		got := routing.ParseBeaconList(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("ParseBeaconList(%q): got %v want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("ParseBeaconList(%q)[%d]: got %q want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestIsUnreachableBeaconHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.5.5", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"0.0.0.0", true},
		{"203.0.113.1", false},
		{"8.8.8.8", false},
		{"beacon.example.com", false}, // hostnames pass through
	}
	for _, c := range cases {
		if got := routing.IsUnreachableBeaconHost(c.host); got != c.want {
			t.Fatalf("IsUnreachableBeaconHost(%q)=%v want %v", c.host, got, c.want)
		}
	}
}

func TestMergeBeaconLists(t *testing.T) {
	t.Parallel()
	got := routing.MergeBeaconLists(
		[]string{"boot:1", "boot:2"},
		[]string{"boot:1", "disc:3", "", "disc:4"},
	)
	want := []string{"boot:1", "boot:2", "disc:3", "disc:4"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestFirstBeacon(t *testing.T) {
	t.Parallel()
	if got := routing.FirstBeacon(""); got != "" {
		t.Fatalf("FirstBeacon(\"\")=%q want \"\"", got)
	}
	if got := routing.FirstBeacon("a:1,b:2"); got != "a:1" {
		t.Fatalf("FirstBeacon=%q want a:1", got)
	}
}

// ----------------------------------------------------------------------------
// DiscoverEndpoint — happy path against an in-process UDP "beacon"
// ----------------------------------------------------------------------------

func TestDiscoverEndpoint_RoundTrip(t *testing.T) {
	t.Parallel()
	// Set up a fake beacon that answers MsgDiscover with a hard-coded reply.
	beaconConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen beacon: %v", err)
	}
	defer beaconConn.Close()
	beaconAddr := beaconConn.LocalAddr().(*net.UDPAddr)

	// Beacon goroutine: read one discover, send a discover-reply.
	beaconDone := make(chan struct{})
	go func() {
		defer close(beaconDone)
		buf := make([]byte, 64)
		_ = beaconConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, src, err := beaconConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 5 || buf[0] != protocol.BeaconMsgDiscover {
			return
		}
		// Build [reply][iplen=4][ip][port]
		reply := []byte{
			protocol.BeaconMsgDiscoverReply,
			4,
			198, 51, 100, 99,
			0x10, 0x00, // port 4096
		}
		_, _ = beaconConn.WriteToUDP(reply, src)
	}()

	// Client conn the daemon would otherwise repurpose for the tunnel.
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientConn.Close()

	got, err := routing.DiscoverEndpoint(beaconAddr.String(), 0xDEADBEEF, clientConn, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("DiscoverEndpoint: %v", err)
	}
	if got.Port != 4096 {
		t.Fatalf("port: got %d want 4096", got.Port)
	}
	if !got.IP.Equal(net.IPv4(198, 51, 100, 99)) {
		t.Fatalf("ip: got %v want 198.51.100.99", got.IP)
	}
	<-beaconDone
}

func TestDiscoverEndpoint_BadResolve(t *testing.T) {
	t.Parallel()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	_, err = routing.DiscoverEndpoint("not a host:port", 1, conn, time.Now().Add(time.Second))
	if err == nil {
		t.Fatal("expected resolve error")
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func addrsEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

// Sanity: ensure t.TempDir cleanup leaves no residual file (defensive).
func TestBeaconCache_TempDirCleansUp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id := filepath.Join(dir, "id.json")
	if err := routing.SaveBeaconCache(id, []string{"203.0.113.99:9001"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(routing.BeaconCachePath(id)); err != nil {
		t.Fatalf("cache file missing right after save: %v", err)
	}
}
