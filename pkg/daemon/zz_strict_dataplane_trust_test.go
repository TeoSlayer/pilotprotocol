// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

func wireTrustGate(d *Daemon) {
	d.tunnels.SetTrustGate(d.admitDataPlanePeer)
	d.tunnels.SetPeerTrustFn(d.isTrustedPeer)
}

func newStrictBusDaemon(t *testing.T, client *registry.Client) (*Daemon, *net.UDPConn) {
	t.Helper()
	d := &Daemon{
		nodeID:       42,
		tunnels:      NewTunnelManager(),
		ports:        NewPortManager(),
		resolveCache: make(map[uint32]*resolveEntry),
		epCache:      make(map[uint32]*endpointEntry),
		netPolicies:  make(map[uint16][]uint16),
		managed:      make(map[uint16]*ManagedEngine),
		memberTags:   make(map[uint16][]string),
		synTokens:    DefaultSYNRateLimit,
		synLastFill:  time.Now(),
		perSrcSYN:    make(map[uint32]*srcSYNBucket),
		stopCh:       make(chan struct{}),
	}
	d.regConn.Store(client)
	d.ipc = NewIPCServer("", d)
	d.bus = newInProcessBus(d.NodeID)
	d.tunnels.SetEventBus(d.bus)
	wireTrustGate(d)
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	t.Cleanup(func() {
		peer.Close()
		d.tunnels.Close()
	})
	return d, peer
}

func buildAuthKXFrame(t *testing.T, peerNodeID uint32) (data []byte, peerPub ed25519.PublicKey, peerPriv ed25519.PrivateKey, peerX *ecdh.PrivateKey) {
	t.Helper()
	var err error
	peerPub, peerPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	curve := ecdh.X25519()
	peerX, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519 keygen: %v", err)
	}
	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(challenge[4:8], peerNodeID)
	copy(challenge[8:40], peerX.PublicKey().Bytes())
	sig := ed25519.Sign(peerPriv, challenge)

	data = make([]byte, 132)
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:36], peerX.PublicKey().Bytes())
	copy(data[36:68], peerPub)
	copy(data[68:132], sig)
	return data, peerPub, peerPriv, peerX
}

func TestStrictDataPlaneTrustOffAuthKeyExchangeStillEstablishes(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()

	d, peer := newPacketDaemon(t, client)
	d.config.Public = false
	d.config.StrictDataPlaneTrust = false
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	wireTrustGate(d)

	const peerNodeID = uint32(0x1001)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	data, peerPub, _, _ := buildAuthKXFrame(t, peerNodeID)
	d.tunnels.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return peerPub, nil
	})
	d.tunnels.AddPeer(peerNodeID, peerAddr)
	readOneFrame(t, peer)

	d.tunnels.handleAuthKeyExchange(data, peerAddr, false)

	if !d.tunnels.HasCrypto(peerNodeID) {
		t.Fatalf("strict=false must preserve current behavior: untrusted auth KX should still establish crypto")
	}
	if f := readOneFrame(t, peer); f == nil {
		t.Fatalf("strict=false: expected reciprocal key-exchange reply frame")
	}
}

func TestStrictDataPlaneTrustOnAuthKeyExchangeDropsUntrusted(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()

	d, peer := newStrictBusDaemon(t, client)
	d.config.Public = false
	d.config.StrictDataPlaneTrust = true
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}

	sub, unsub := d.bus.Subscribe("tunnel.established")
	defer unsub()

	const peerNodeID = uint32(0x1002)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	data, peerPub, _, _ := buildAuthKXFrame(t, peerNodeID)
	d.tunnels.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return peerPub, nil
	})
	d.tunnels.AddPeer(peerNodeID, peerAddr)
	readOneFrame(t, peer)

	d.tunnels.handleAuthKeyExchange(data, peerAddr, false)

	if d.tunnels.HasCrypto(peerNodeID) {
		t.Fatalf("strict=true + private + untrusted: no crypto should be installed")
	}
	if f := readOneFrame(t, peer); f != nil {
		t.Fatalf("strict=true + private + untrusted: no reply frame expected, got %x", f)
	}
	select {
	case ev := <-sub:
		t.Fatalf("strict=true + private + untrusted: no tunnel.established event expected, got %+v", ev)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestStrictDataPlaneTrustOnAuthKeyExchangeAllowsTrustedPeer(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": true}
	})
	defer cleanup()

	d, peer := newPacketDaemon(t, client)
	d.config.Public = false
	d.config.StrictDataPlaneTrust = true
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	wireTrustGate(d)

	const peerNodeID = uint32(0x1003)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	data, peerPub, _, _ := buildAuthKXFrame(t, peerNodeID)
	d.tunnels.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return peerPub, nil
	})
	d.tunnels.AddPeer(peerNodeID, peerAddr)
	readOneFrame(t, peer)

	d.tunnels.handleAuthKeyExchange(data, peerAddr, false)

	if !d.tunnels.HasCrypto(peerNodeID) {
		t.Fatalf("strict=true but trusted peer: crypto should still be established")
	}
	if f := readOneFrame(t, peer); f == nil {
		t.Fatalf("strict=true but trusted peer: expected reciprocal key-exchange reply")
	}
}

func TestStrictDataPlaneTrustOnUnauthKeyExchangeDropsUntrusted(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()

	d, peer := newPacketDaemon(t, client)
	d.config.Public = false
	d.config.StrictDataPlaneTrust = true
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	wireTrustGate(d)

	const peerNodeID = uint32(0x1004)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	data := make([]byte, 36)
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:36], peerPriv.PublicKey().Bytes())

	d.tunnels.handleKeyExchange(data, peerAddr, false)

	if d.tunnels.HasCrypto(peerNodeID) {
		t.Fatalf("strict=true + private + untrusted: no crypto should be installed via unauth KX")
	}
	if f := readOneFrame(t, peer); f != nil {
		t.Fatalf("strict=true + private + untrusted: no reply frame expected, got %x", f)
	}
}

func TestStrictDataPlaneTrustOnControlPingDropsUntrusted(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()

	d, peer := newPacketDaemon(t, client)
	d.config.Public = false
	d.config.StrictDataPlaneTrust = true
	wireTrustGate(d)

	const peerNodeID = uint32(0x2001)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	d.tunnels.AddPeer(peerNodeID, peerAddr)

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: peerNodeID},
		Dst:      protocol.Addr{Node: d.NodeID()},
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Seq:      1,
	}
	d.handleControlPacket(pkt)

	if f := readOneFrame(t, peer); f != nil {
		t.Fatalf("strict=true + private + untrusted: no pong expected, got %x", f)
	}
}

func TestStrictDataPlaneTrustOffControlPingStillReplies(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()

	d, peer := newPacketDaemon(t, client)
	d.config.Public = false
	d.config.StrictDataPlaneTrust = false
	wireTrustGate(d)

	const peerNodeID = uint32(0x2002)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	d.tunnels.AddPeer(peerNodeID, peerAddr)

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: peerNodeID},
		Dst:      protocol.Addr{Node: d.NodeID()},
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Seq:      1,
	}
	d.handleControlPacket(pkt)

	if f := readOneFrame(t, peer); f == nil {
		t.Fatalf("strict=false: expected pong reply (current behavior preserved)")
	}
}

func TestStrictDataPlaneTrustOnControlPingAllowsTrustedPeer(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": true}
	})
	defer cleanup()

	d, peer := newPacketDaemon(t, client)
	d.config.Public = false
	d.config.StrictDataPlaneTrust = true
	wireTrustGate(d)

	const peerNodeID = uint32(0x2003)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	d.tunnels.AddPeer(peerNodeID, peerAddr)

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: peerNodeID},
		Dst:      protocol.Addr{Node: d.NodeID()},
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Seq:      1,
	}
	d.handleControlPacket(pkt)

	if f := readOneFrame(t, peer); f == nil {
		t.Fatalf("strict=true but trusted peer: expected pong reply")
	}
}

func TestSynRejectedEventOmitsPeerPII(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()

	d, peer := newPacketDaemon(t, client)
	d.config.Public = false
	d.bus = newInProcessBus(d.NodeID)

	sub, unsub := d.bus.Subscribe("syn.rejected")
	defer unsub()

	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNodeID = uint32(3001)
	d.tunnels.AddPeer(peerNodeID, peerAddr)
	if _, err := d.ports.Bind(5678); err != nil {
		t.Fatalf("bind: %v", err)
	}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: peerNodeID},
		Dst:      protocol.Addr{Node: d.NodeID()},
		SrcPort:  3000,
		DstPort:  5678,
		Seq:      100,
	}
	d.handleStreamPacket(pkt)

	select {
	case ev := <-sub:
		if _, ok := ev.Payload["src_addr"]; ok {
			t.Errorf("syn.rejected event must not carry src_addr, got %+v", ev.Payload)
		}
		if _, ok := ev.Payload["src_node_id"]; ok {
			t.Errorf("syn.rejected event must not carry src_node_id, got %+v", ev.Payload)
		}
		if _, ok := ev.Payload["dst_port"]; !ok {
			t.Errorf("syn.rejected event should still carry dst_port, got %+v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected syn.rejected event")
	}
}

func TestDatagramRejectedEventOmitsPeerPII(t *testing.T) {
	t.Parallel()
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"trusted": false}
	})
	defer cleanup()

	d, _ := newPacketDaemon(t, client)
	d.config.Public = false
	d.bus = newInProcessBus(d.NodeID)

	sub, unsub := d.bus.Subscribe("datagram.rejected")
	defer unsub()

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Node: 3002},
		Dst:      protocol.Addr{Node: d.NodeID()},
		SrcPort:  100,
		DstPort:  200,
		Payload:  []byte("hello"),
	}
	d.handleDatagramPacket(pkt)

	select {
	case ev := <-sub:
		if _, ok := ev.Payload["src_addr"]; ok {
			t.Errorf("datagram.rejected event must not carry src_addr, got %+v", ev.Payload)
		}
		if _, ok := ev.Payload["src_node_id"]; ok {
			t.Errorf("datagram.rejected event must not carry src_node_id, got %+v", ev.Payload)
		}
		if _, ok := ev.Payload["dst_port"]; !ok {
			t.Errorf("datagram.rejected event should still carry dst_port, got %+v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected datagram.rejected event")
	}
}

func TestTunnelPeerAddedEventOmitsEndpoint(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	d.config.Public = true
	d.config.Encrypt = false
	d.bus = newInProcessBus(d.NodeID)

	sub, unsub := d.bus.Subscribe("tunnel.peer_added")
	defer unsub()

	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNodeID = uint32(4001)
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: peerNodeID},
		Dst:      protocol.Addr{Node: d.NodeID()},
		SrcPort:  100,
		DstPort:  9999,
	}
	d.handlePacket(pkt, peerAddr)

	select {
	case ev := <-sub:
		if _, ok := ev.Payload["endpoint"]; ok {
			t.Errorf("tunnel.peer_added event must not carry endpoint, got %+v", ev.Payload)
		}
		if _, ok := ev.Payload["peer_node_id"]; !ok {
			t.Errorf("tunnel.peer_added event should still carry peer_node_id, got %+v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected tunnel.peer_added event")
	}
}

func TestTunnelEstablishedEventScrubsPeerNodeIDForUntrustedPeer(t *testing.T) {
	t.Parallel()
	d, peer := newStrictBusDaemon(t, nil)
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	d.tunnels.SetPeerTrustFn(func(uint32) bool { return false })

	sub, unsub := d.bus.Subscribe("tunnel.established")
	defer unsub()

	const peerNodeID = uint32(5001)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	data, peerPub, _, _ := buildAuthKXFrame(t, peerNodeID)
	d.tunnels.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return peerPub, nil
	})
	d.tunnels.AddPeer(peerNodeID, peerAddr)

	d.tunnels.handleAuthKeyExchange(data, peerAddr, false)

	select {
	case ev := <-sub:
		if _, ok := ev.Payload["peer_node_id"]; ok {
			t.Errorf("tunnel.established for an untrusted peer must not carry peer_node_id, got %+v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected tunnel.established event")
	}
}

func TestTunnelEstablishedEventKeepsPeerNodeIDForTrustedPeer(t *testing.T) {
	t.Parallel()
	d, peer := newStrictBusDaemon(t, nil)
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	d.tunnels.SetPeerTrustFn(func(uint32) bool { return true })

	sub, unsub := d.bus.Subscribe("tunnel.established")
	defer unsub()

	const peerNodeID = uint32(5002)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	data, peerPub, _, _ := buildAuthKXFrame(t, peerNodeID)
	d.tunnels.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) {
		return peerPub, nil
	})
	d.tunnels.AddPeer(peerNodeID, peerAddr)

	d.tunnels.handleAuthKeyExchange(data, peerAddr, false)

	select {
	case ev := <-sub:
		if got, ok := ev.Payload["peer_node_id"]; !ok || got != peerNodeID {
			t.Errorf("tunnel.established for a trusted peer should carry peer_node_id, got %+v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected tunnel.established event")
	}
}

func TestSecurityNonceReplayEventHashesPeerID(t *testing.T) {
	t.Parallel()
	d, _ := newStrictBusDaemon(t, nil)
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}

	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	pc, err := d.tunnels.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	const peerNodeID = uint32(6001)
	d.tunnels.mu.Lock()
	d.tunnels.envelope.Install(peerNodeID, pc)
	d.tunnels.mu.Unlock()

	pc.ReplayMu.Lock()
	pc.MaxRecvNonce = 5
	bit := uint64(5) % replayWindowSize
	pc.ReplayBitmap[bit/64] |= 1 << (bit % 64)
	pc.ReplayMu.Unlock()

	sub, unsub := d.bus.Subscribe("security.nonce_replay")
	defer unsub()

	data := make([]byte, 4+12+16)
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:8], pc.NoncePrefix[:])
	binary.BigEndian.PutUint64(data[8:16], 5)

	d.tunnels.handleEncrypted(data, &net.UDPAddr{})

	select {
	case ev := <-sub:
		if _, ok := ev.Payload["peer_node_id"]; ok {
			t.Errorf("security.nonce_replay must not carry raw peer_node_id, got %+v", ev.Payload)
		}
		hash, ok := ev.Payload["peer_hash"].(string)
		if !ok || hash == "" {
			t.Errorf("security.nonce_replay should carry a non-empty peer_hash, got %+v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected security.nonce_replay event")
	}
}

func TestSecuritySrcSpoofedEventHashesPeerID(t *testing.T) {
	t.Parallel()
	d, _ := newStrictBusDaemon(t, nil)
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}

	curve := ecdh.X25519()
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	pc, err := d.tunnels.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	const peerNodeID = uint32(6002)
	d.tunnels.mu.Lock()
	d.tunnels.envelope.Install(peerNodeID, pc)
	d.tunnels.mu.Unlock()

	pkt := newPacket("spoofed-payload")
	pkt.Src.Node = 0x99999999
	plaintext, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	nonce := make([]byte, pc.AEAD.NonceSize())
	copy(nonce[0:4], pc.NoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], 1)
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, peerNodeID)
	ct := pc.AEAD.Seal(nil, nonce, plaintext, aad)

	data := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:16], nonce)
	copy(data[16:], ct)

	sub, unsub := d.bus.Subscribe("security.src_spoofed")
	defer unsub()

	d.tunnels.handleEncrypted(data, &net.UDPAddr{})

	select {
	case ev := <-sub:
		if _, ok := ev.Payload["authenticated_peer"]; ok {
			t.Errorf("security.src_spoofed must not carry raw authenticated_peer, got %+v", ev.Payload)
		}
		if _, ok := ev.Payload["claimed_src"]; ok {
			t.Errorf("security.src_spoofed must not carry raw claimed_src, got %+v", ev.Payload)
		}
		if h, ok := ev.Payload["authenticated_peer_hash"].(string); !ok || h == "" {
			t.Errorf("security.src_spoofed should carry authenticated_peer_hash, got %+v", ev.Payload)
		}
		if h, ok := ev.Payload["claimed_src_hash"].(string); !ok || h == "" {
			t.Errorf("security.src_spoofed should carry claimed_src_hash, got %+v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected security.src_spoofed event")
	}
}

func TestSecuritySynRateLimitedEventHashesSrcAddr(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	d.config.Public = true
	d.bus = newInProcessBus(d.NodeID)

	sub, unsub := d.bus.Subscribe("security.syn_rate_limited")
	defer unsub()

	d.synTokens = 0

	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNodeID = uint32(7001)
	d.tunnels.AddPeer(peerNodeID, peerAddr)
	if _, err := d.ports.Bind(5679); err != nil {
		t.Fatalf("bind: %v", err)
	}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: peerNodeID},
		Dst:      protocol.Addr{Node: d.NodeID()},
		SrcPort:  3000,
		DstPort:  5679,
		Seq:      100,
	}
	d.handleStreamPacket(pkt)

	select {
	case ev := <-sub:
		if _, ok := ev.Payload["src_addr"]; ok {
			t.Errorf("security.syn_rate_limited must not carry raw src_addr, got %+v", ev.Payload)
		}
		hash, ok := ev.Payload["src_addr_hash"].(string)
		if !ok || hash == "" || strings.Contains(hash, ".") {
			t.Errorf("security.syn_rate_limited should carry a hashed src_addr_hash, got %+v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected security.syn_rate_limited event")
	}
}
