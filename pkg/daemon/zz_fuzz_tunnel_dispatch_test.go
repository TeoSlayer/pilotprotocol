// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
)

// These targets cover the daemon's inbound wire surface: everything the
// readLoop reaches after udpio.Recv hands it a datagram. Each handler has
// its own recoverLayer boundary in production, which means a real panic
// would be swallowed and show up only as silently-dropped traffic. The
// targets therefore compare RecoveredPanicCount across the call so a caught
// panic still fails the test.

// fuzzTunnelManager builds a TunnelManager with encryption enabled, an
// identity installed, a bound socket, and a beacon address configured, so
// the relay-deliver and key-exchange branches are all reachable. Built once
// at *testing.F scope — per-iteration key generation would dominate.
func fuzzTunnelManager(tb testing.TB) *TunnelManager {
	tb.Helper()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		tb.Fatalf("EnableEncryption: %v", err)
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		tb.Fatalf("identity: %v", err)
	}
	tm.SetIdentity(id)
	tm.SetNodeID(7)
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		tb.Fatalf("Listen: %v", err)
	}
	if err := tm.SetBeaconAddr("127.0.0.1:1"); err != nil {
		tb.Fatalf("SetBeaconAddr: %v", err)
	}
	// Resolving node 1 to a real key exercises the registry-resolved branch
	// of handleAuthKeyExchange (signature verify against a known key);
	// every other node id takes the unresolved branch. Node 2 resolves to a
	// deliberately wrong-length key — the shape that panics an unguarded
	// ed25519.Verify.
	tm.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		switch nodeID {
		case 1:
			return id.PublicKey, nil
		case 2:
			return ed25519.PublicKey(make([]byte, 7)), nil
		}
		return nil, nil
	})
	tb.Cleanup(func() { tm.Close() })
	return tm
}

// drainRecv keeps the unbuffered recvCh from blocking the fuzz goroutine
// when an input decodes into a well-formed plaintext packet.
func drainRecv(tm *TunnelManager) func() {
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-tm.RecvCh():
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

func beaconFrame(msgType byte, body []byte) []byte {
	out := make([]byte, 1+len(body))
	out[0] = msgType
	copy(out[1:], body)
	return out
}

// FuzzTunnelBeaconMessage targets handleBeaconMessage — the branch the
// readLoop takes for any first byte < 0x10. Both the from-beacon and
// not-from-beacon source checks are exercised, since the beacon-source
// gate is the only thing standing between an off-path sender and
// handleRelayDeliver.
func FuzzTunnelBeaconMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{protocol.BeaconMsgDiscoverReply})
	f.Add([]byte{protocol.BeaconMsgPunchCommand})
	f.Add([]byte{protocol.BeaconMsgRelayDeliver})
	// Punch command with each IP-length encoding, plus a truncated one.
	f.Add(beaconFrame(protocol.BeaconMsgPunchCommand, []byte{4, 127, 0, 0, 1, 0x1F, 0x90}))
	f.Add(beaconFrame(protocol.BeaconMsgPunchCommand, []byte{16}))
	f.Add(beaconFrame(protocol.BeaconMsgPunchCommand, []byte{0xFF, 1, 2, 3}))
	// Relay-deliver carrying each inner tunnel magic.
	for _, magic := range [][4]byte{
		protocol.TunnelMagicAuthEx,
		protocol.TunnelMagicKeyEx,
		protocol.TunnelMagicSecure,
		protocol.TunnelMagic,
		protocol.TunnelMagicPunch,
	} {
		body := make([]byte, 4+4)
		binary.BigEndian.PutUint32(body[0:4], 1)
		copy(body[4:8], magic[:])
		f.Add(beaconFrame(protocol.BeaconMsgRelayDeliver, body))
	}
	for i := byte(0); i < 0x10; i++ {
		f.Add([]byte{i})
		f.Add([]byte{i, 0xFF, 0xFF, 0xFF, 0xFF})
	}

	tm := fuzzTunnelManager(f)
	stop := drainRecv(tm)
	f.Cleanup(stop)

	beaconAddr := tm.routing.BeaconAddr()
	offPath := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 3333}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			data = data[:65535]
		}
		before := RecoveredPanicCount()
		tm.handleBeaconMessage(data, beaconAddr)
		tm.handleBeaconMessage(data, offPath)
		if after := RecoveredPanicCount(); after != before {
			t.Fatalf("handleBeaconMessage recovered a panic on input %x", data)
		}
	})
}

// FuzzTunnelRelayDeliver targets handleRelayDeliver's inner-frame parser
// directly. This is the highest-value surface in the daemon: the beacon is
// explicitly not trusted, srcNodeID is attacker-chosen, and the inner frame
// is re-dispatched into the crypto handlers.
func FuzzTunnelRelayDeliver(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 4))
	f.Add(make([]byte, 5))
	f.Add(make([]byte, 8))
	for _, magic := range [][4]byte{
		protocol.TunnelMagicAuthEx,
		protocol.TunnelMagicKeyEx,
		protocol.TunnelMagicSecure,
		protocol.TunnelMagic,
	} {
		// srcNodeID + magic, with nothing after it.
		b := make([]byte, 4+4)
		binary.BigEndian.PutUint32(b[0:4], 1)
		copy(b[4:8], magic[:])
		f.Add(b)
		// srcNodeID + magic + a partial body.
		b2 := make([]byte, 4+4+16)
		binary.BigEndian.PutUint32(b2[0:4], 1)
		copy(b2[4:8], magic[:])
		f.Add(b2)
	}
	// A structurally complete PILA payload (unsigned, so it must be rejected).
	{
		b := make([]byte, 4+4+4+32+32+64)
		binary.BigEndian.PutUint32(b[0:4], 1)
		copy(b[4:8], protocol.TunnelMagicAuthEx[:])
		binary.BigEndian.PutUint32(b[8:12], 1)
		f.Add(b)
	}
	// A structurally complete PILK payload with a real X25519 point.
	{
		if k, err := ecdh.X25519().GenerateKey(rand.Reader); err == nil {
			b := make([]byte, 4+4+4+32)
			binary.BigEndian.PutUint32(b[0:4], 2)
			copy(b[4:8], protocol.TunnelMagicKeyEx[:])
			binary.BigEndian.PutUint32(b[8:12], 2)
			copy(b[12:44], k.PublicKey().Bytes())
			f.Add(b)
		}
	}

	tm := fuzzTunnelManager(f)
	stop := drainRecv(tm)
	f.Cleanup(stop)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			data = data[:65535]
		}
		before := RecoveredPanicCount()
		tm.handleRelayDeliver(data)
		if after := RecoveredPanicCount(); after != before {
			t.Fatalf("handleRelayDeliver recovered a panic on input %x", data)
		}
	})
}

// FuzzTunnelKeyExchange targets both key-exchange entry points as the
// readLoop calls them (magic already stripped), on the direct and relayed
// paths. The PILA path runs attacker bytes through an Ed25519 verify, which
// is exactly where the wrong-length-public-key panic class lives.
func FuzzTunnelKeyExchange(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 3))
	f.Add(make([]byte, 4))
	f.Add(make([]byte, 36))         // exact PILK size
	f.Add(make([]byte, 35))         // one short
	f.Add(make([]byte, 4+32+32+64)) // exact PILA size
	f.Add(make([]byte, 4+32+32+63)) // one short
	{
		b := make([]byte, 4+32+32+64)
		binary.BigEndian.PutUint32(b[0:4], 1)
		f.Add(b)
	}

	tm := fuzzTunnelManager(f)
	stop := drainRecv(tm)
	f.Cleanup(stop)
	from := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 3), Port: 9999}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			data = data[:4096]
		}
		before := RecoveredPanicCount()
		tm.handleAuthKeyExchange(data, from, false)
		tm.handleAuthKeyExchange(data, from, true)
		tm.handleKeyExchange(data, from, false)
		tm.handleKeyExchange(data, from, true)
		if after := RecoveredPanicCount(); after != before {
			t.Fatalf("key exchange handler recovered a panic on input %x", data)
		}
	})
}

// FuzzTunnelEncrypted targets handleEncrypted with the PILS magic stripped,
// mirroring the readLoop call. Covers the no-key, replay, outside-window,
// and AEAD-failure branches plus the post-decrypt Unmarshal.
func FuzzTunnelEncrypted(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 4+12+15))
	f.Add(make([]byte, 4+12+16))
	f.Add(make([]byte, 256))
	{
		b := make([]byte, 4+12+16)
		binary.BigEndian.PutUint32(b[0:4], 1)
		f.Add(b)
	}

	tm := fuzzTunnelManager(f)
	stop := drainRecv(tm)
	f.Cleanup(stop)
	from := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 4), Port: 8888}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			data = data[:65535]
		}
		before := RecoveredPanicCount()
		tm.handleEncrypted(data, from)
		if after := RecoveredPanicCount(); after != before {
			t.Fatalf("handleEncrypted recovered a panic on input %x", data)
		}
	})
}
