// SPDX-License-Identifier: AGPL-3.0-or-later

// End-to-end compat-mode regression test. Drives a real Daemon.Dial
// flow from a compat-mode (WSS-only) daemon to a UDP-mode peer
// attached to the same beacon. Verifies the SYN → SYN-ACK → ACK
// handshake completes through the WSS↔UDP bridge and that echo data
// flows in both directions.
//
// Without the routing.Manager.forceRelay fix landed alongside this
// test, the compat daemon's first SYN went out as a raw frame
// through the WSS pipe (since blackhole-detection hadn't flipped the
// peer to relay yet), the beacon dropped it as an unknown
// beacon-protocol packet, and the dial timed out. Pins that
// behavior so the regression can't sneak back in.

package tests

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	registry "github.com/TeoSlayer/pilotprotocol/pkg/registry/server"
)

// startBeaconWithWSS brings up a beacon with the compat WSS bridge
// enabled. pubKeyLookup is supplied by the caller (typically backed
// by the registry's LookupPublicKey, but kept as a parameter so the
// beacon can start before the registry).
func startBeaconWithWSS(t *testing.T, pubKeyLookup func(uint32) (ed25519.PublicKey, bool)) (b *beacon.Server, wssURL string) {
	t.Helper()
	b = beacon.New()
	if err := b.EnableCompatWSS("127.0.0.1:0", pubKeyLookup); err != nil {
		t.Fatalf("EnableCompatWSS: %v", err)
	}
	go func() { _ = b.ListenAndServe("127.0.0.1:0") }()
	select {
	case <-b.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to become ready")
	}
	t.Cleanup(func() {
		_ = b.CloseCompatWSS()
		_ = b.Close()
	})
	return b, "ws://" + b.WSSAddr() + "/v1/compat"
}

// startUDPDaemon brings up a regular (UDP-transport) daemon attached
// to the supplied beacon + registry, with Public=true so the echo
// service answers everyone.
func startUDPDaemon(t *testing.T, regAddr, beaconAddr, email string) *daemon.Daemon {
	t.Helper()
	tmp := shortTempDir(t)
	d := daemon.New(daemon.Config{
		RegistryAddr: regAddr,
		BeaconAddr:   beaconAddr,
		ListenAddr:   "127.0.0.1:0",
		SocketPath:   filepath.Join(tmp, "d.sock"),
		IdentityPath: filepath.Join(tmp, "id.json"),
		Email:        email,
		Public:       true,
		Encrypt:      true,
	})
	if err := d.Start(); err != nil {
		t.Fatalf("UDP daemon start: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop() })
	return d
}

// startCompatDaemon brings up a compat-mode daemon (WSS-only) pointed
// at the supplied beacon WSS URL.
func startCompatDaemon(t *testing.T, regAddr, beaconAddr, wssURL, email string) (*daemon.Daemon, string) {
	t.Helper()
	tmp := shortTempDir(t)
	sock := filepath.Join(tmp, "d.sock")
	d := daemon.New(daemon.Config{
		RegistryAddr:    regAddr,
		BeaconAddr:      beaconAddr, // routing still needs a UDP beacon address for relay-wrap targeting
		ListenAddr:      "127.0.0.1:0",
		SocketPath:      sock,
		IdentityPath:    filepath.Join(tmp, "id.json"),
		Email:           email,
		Public:          true,
		TransportMode:   "compat",
		CompatBeaconURL: wssURL,
		CompatTLSTrust:  "system", // ws:// bypasses TLS verification anyway
		Encrypt:         true,
	})
	if err := d.Start(); err != nil {
		t.Fatalf("compat daemon start: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop() })
	return d, sock
}

// TestCompatDaemonDialUDPPeerThroughWSS exercises the full compat-mode
// data path end-to-end: a compat daemon (WSS-only egress, simulates
// a managed claw whose UDP is firewall-blocked) dials a UDP-mode
// peer's echo service, sends bytes, and verifies the echoed reply.
//
// Asserts the routing.Manager.forceRelay fix actually wraps the first
// SYN in BeaconMsgRelay — pre-fix, this dial timed out because the
// raw frame was dropped at the beacon as unknown protocol.
func TestCompatDaemonDialUDPPeerThroughWSS(t *testing.T) {
	t.Parallel()

	// Two-step bootstrap: the beacon's WSS auth needs the registry's
	// pubkey lookup, but the registry's beacon-for-resolve is baked
	// at registry.New time, so the beacon must already have its
	// address. Break the cycle with a settable pubkey-lookup pointer:
	// build the beacon with a placeholder, build the registry against
	// the beacon, then swap the pointer to use the live registry.
	var regRef *registry.Server
	lookup := func(nodeID uint32) (ed25519.PublicKey, bool) {
		if regRef == nil {
			return nil, false
		}
		pk, ok := regRef.LookupPublicKey(nodeID)
		if !ok {
			return nil, false
		}
		return ed25519.PublicKey(pk), true
	}
	b, wssURL := startBeaconWithWSS(t, lookup)

	reg := registry.New(b.Addr().String())
	go func() { _ = reg.ListenAndServe("127.0.0.1:0") }()
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	t.Cleanup(func() { reg.Close() })
	regRef = reg

	udp := startUDPDaemon(t, reg.Addr().String(), b.Addr().String(), "udp@pilot.local")
	compat, compatSock := startCompatDaemon(t, reg.Addr().String(), b.Addr().String(), wssURL, "compat@pilot.local")

	// Wait for both to settle (compat needs the post-register WSS
	// dial to complete; UDP needs its Discover round-trip).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if udp.NodeID() != 0 && compat.NodeID() != 0 && b.WSSIsConnected(compat.NodeID()) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if udp.NodeID() == 0 {
		t.Fatalf("UDP daemon never registered")
	}
	if compat.NodeID() == 0 {
		t.Fatalf("compat daemon never registered")
	}
	if !b.WSSIsConnected(compat.NodeID()) {
		t.Fatalf("compat daemon %d not WSS-connected on the beacon", compat.NodeID())
	}

	// Drive the dial through the compat daemon's IPC, exactly like a
	// real pilotctl ping/echo would.
	drv, err := driver.Connect(compatSock)
	if err != nil {
		t.Fatalf("driver.Connect: %v", err)
	}
	defer drv.Close()

	udpAddr := protocol.Addr{Network: 0, Node: udp.NodeID()}
	conn, err := drv.DialAddrTimeout(udpAddr, protocol.PortEcho, 10*time.Second)
	if err != nil {
		t.Fatalf("compat dial UDP peer's echo: %v (compat=%d → udp=%d)", err, compat.NodeID(), udp.NodeID())
	}
	defer conn.Close()

	msg := []byte("compat-mode is alive")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read echoed reply: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("echo mismatch: got %q want %q", buf[:n], msg)
	}
}
