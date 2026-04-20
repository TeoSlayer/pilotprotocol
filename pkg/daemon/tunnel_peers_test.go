package daemon

import (
	"net"
	"testing"
)

func mustUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return a
}

func TestAddPeerStoresEndpointUnderLock(t *testing.T) {
	tm := NewTunnelManager()
	addr := mustUDPAddr(t, "127.0.0.1:5001")
	tm.AddPeer(42, addr)

	tm.mu.RLock()
	got, ok := tm.peers[42]
	tm.mu.RUnlock()
	if !ok {
		t.Fatalf("peer 42 missing after AddPeer")
	}
	if got.String() != addr.String() {
		t.Fatalf("peers[42] = %v, want %v", got, addr)
	}
}

func TestAddPeerOverwritesExistingEndpoint(t *testing.T) {
	tm := NewTunnelManager()
	a1 := mustUDPAddr(t, "127.0.0.1:5001")
	a2 := mustUDPAddr(t, "127.0.0.1:5002")
	tm.AddPeer(42, a1)
	tm.AddPeer(42, a2)

	tm.mu.RLock()
	got := tm.peers[42]
	tm.mu.RUnlock()
	if got.String() != a2.String() {
		t.Fatalf("overwrite failed: got %v want %v", got, a2)
	}
}

func TestRemovePeerDropsBothPeerAndCryptoEntries(t *testing.T) {
	tm := NewTunnelManager()
	tm.AddPeer(7, mustUDPAddr(t, "127.0.0.1:5003"))
	tm.mu.Lock()
	tm.crypto[7] = &peerCrypto{}
	tm.mu.Unlock()

	tm.RemovePeer(7)

	tm.mu.RLock()
	_, peerOK := tm.peers[7]
	_, cryptoOK := tm.crypto[7]
	tm.mu.RUnlock()
	if peerOK {
		t.Fatalf("peer 7 still in peers map after RemovePeer")
	}
	if cryptoOK {
		t.Fatalf("crypto for peer 7 still present after RemovePeer")
	}
}

func TestRemovePeerOnNonexistentIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	tm.AddPeer(1, mustUDPAddr(t, "127.0.0.1:5004"))

	tm.RemovePeer(999) // does not exist

	tm.mu.RLock()
	count := len(tm.peers)
	tm.mu.RUnlock()
	if count != 1 {
		t.Fatalf("unexpected peer count %d after RemovePeer of missing key", count)
	}
}

func TestHasPeerReportsPresence(t *testing.T) {
	tm := NewTunnelManager()
	if tm.HasPeer(5) {
		t.Fatalf("fresh TM: HasPeer(5) = true")
	}
	tm.AddPeer(5, mustUDPAddr(t, "127.0.0.1:5005"))
	if !tm.HasPeer(5) {
		t.Fatalf("after AddPeer: HasPeer(5) = false")
	}
	tm.RemovePeer(5)
	if tm.HasPeer(5) {
		t.Fatalf("after RemovePeer: HasPeer(5) = true")
	}
}

func TestHasCryptoReflectsCryptoMap(t *testing.T) {
	tm := NewTunnelManager()
	if tm.HasCrypto(1) {
		t.Fatalf("fresh: HasCrypto(1) = true")
	}
	tm.mu.Lock()
	tm.crypto[1] = &peerCrypto{}
	tm.mu.Unlock()
	if !tm.HasCrypto(1) {
		t.Fatalf("after insert: HasCrypto(1) = false")
	}
}

func TestIsEncryptedRequiresReadyFlag(t *testing.T) {
	tm := NewTunnelManager()
	// No crypto at all
	if tm.IsEncrypted(1) {
		t.Fatalf("no crypto: IsEncrypted(1) should be false")
	}

	// Crypto present but not ready
	tm.mu.Lock()
	tm.crypto[1] = &peerCrypto{ready: false}
	tm.mu.Unlock()
	if tm.IsEncrypted(1) {
		t.Fatalf("crypto.ready=false: IsEncrypted(1) should be false")
	}

	// Crypto ready
	tm.mu.Lock()
	tm.crypto[1].ready = true
	tm.mu.Unlock()
	if !tm.IsEncrypted(1) {
		t.Fatalf("crypto.ready=true: IsEncrypted(1) should be true")
	}
}

func TestPeerCountReflectsAddsAndRemoves(t *testing.T) {
	tm := NewTunnelManager()
	if n := tm.PeerCount(); n != 0 {
		t.Fatalf("fresh PeerCount = %d, want 0", n)
	}
	tm.AddPeer(1, mustUDPAddr(t, "127.0.0.1:5006"))
	tm.AddPeer(2, mustUDPAddr(t, "127.0.0.1:5007"))
	tm.AddPeer(3, mustUDPAddr(t, "127.0.0.1:5008"))
	if n := tm.PeerCount(); n != 3 {
		t.Fatalf("after 3 AddPeer: PeerCount = %d, want 3", n)
	}
	tm.RemovePeer(2)
	if n := tm.PeerCount(); n != 2 {
		t.Fatalf("after RemovePeer(2): PeerCount = %d, want 2", n)
	}
}

func TestPeerListEmptyReturnsNilSlice(t *testing.T) {
	tm := NewTunnelManager()
	got := tm.PeerList()
	if len(got) != 0 {
		t.Fatalf("empty TM PeerList length = %d, want 0", len(got))
	}
}

func TestPeerListReportsEndpointEncryptedAuthenticatedRelay(t *testing.T) {
	tm := NewTunnelManager()
	tm.AddPeer(10, mustUDPAddr(t, "127.0.0.1:6010"))
	tm.AddPeer(20, mustUDPAddr(t, "127.0.0.1:6020"))
	tm.AddPeer(30, mustUDPAddr(t, "127.0.0.1:6030"))

	// peer 10: no crypto, no relay → Encrypted=false, Authenticated=false, Relay=false
	// peer 20: crypto ready+authenticated, no relay
	// peer 30: no crypto, relay
	tm.mu.Lock()
	tm.crypto[20] = &peerCrypto{ready: true, authenticated: true}
	tm.relayPeers[30] = true
	tm.mu.Unlock()

	list := tm.PeerList()
	if len(list) != 3 {
		t.Fatalf("PeerList length = %d, want 3", len(list))
	}
	byID := map[uint32]PeerInfo{}
	for _, p := range list {
		byID[p.NodeID] = p
	}

	p10 := byID[10]
	if p10.Endpoint != "127.0.0.1:6010" || p10.Encrypted || p10.Authenticated || p10.Relay {
		t.Fatalf("peer 10 wrong: %+v", p10)
	}

	p20 := byID[20]
	if p20.Endpoint != "127.0.0.1:6020" || !p20.Encrypted || !p20.Authenticated || p20.Relay {
		t.Fatalf("peer 20 wrong: %+v", p20)
	}

	p30 := byID[30]
	if p30.Endpoint != "127.0.0.1:6030" || p30.Encrypted || p30.Authenticated || !p30.Relay {
		t.Fatalf("peer 30 wrong: %+v", p30)
	}
}

func TestAddPeerWithEncryptionTriggersKeyExchange(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}

	// Need a UDP socket so writeFrame doesn't nil-deref. Bind to loopback :0.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()
	tm.conn = conn

	// Peer endpoint points to a different loopback port that nobody listens on
	// (UDP send to that port is fine — just gets dropped).
	peerAddr := mustUDPAddr(t, "127.0.0.1:1")
	before := tm.PktsSent
	tm.AddPeer(99, peerAddr)

	if !tm.HasPeer(99) {
		t.Fatalf("peer 99 missing after AddPeer")
	}
	if tm.PktsSent == before {
		t.Fatalf("expected PktsSent to increment after encrypt-branch key exchange (before=%d, after=%d)", before, tm.PktsSent)
	}
}
