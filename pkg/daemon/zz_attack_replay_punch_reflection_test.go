// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// Adversarial replay for the beacon-punch reflection finding (PPA-005).
//
// The attack: a daemon that acts on any BeaconMsgPunchCommand it receives
// is an open UDP reflector — the command carries an attacker-chosen
// target IP:port and the daemon obligingly sends punch packets there. The
// fix binds punch commands (and relay deliveries) to the configured
// beacon endpoint.
//
// These tests drive tm.handleBeaconMessage — the exact function the L2
// readLoop dispatches into — with attacker bytes from attacker-chosen
// source addresses, and assert the reflection target receives nothing.
// Everything is local: sockets bind 127.0.0.1:0.

// punchCommandFor builds the on-wire BeaconMsgPunchCommand that names an
// attacker-chosen reflection target.
func punchCommandFor(target *net.UDPAddr) []byte {
	ip4 := target.IP.To4()
	data := make([]byte, 1+1+len(ip4)+2)
	data[0] = protocol.BeaconMsgPunchCommand
	data[1] = byte(len(ip4))
	copy(data[2:2+len(ip4)], ip4)
	binary.BigEndian.PutUint16(data[2+len(ip4):], uint16(target.Port))
	return data
}

// drainCount reports how many datagrams landed on conn within window.
func drainCount(t *testing.T, conn *net.UDPConn, window time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(window)
	buf := make([]byte, 64)
	n := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return n
		}
		conn.SetReadDeadline(time.Now().Add(remaining))
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			return n
		}
		n++
	}
}

// newReflectionRig returns a listening tunnel manager with a configured
// beacon address, plus a socket standing in for the reflection victim.
func newReflectionRig(t *testing.T) (*TunnelManager, *net.UDPAddr, *net.UDPConn) {
	t.Helper()
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { tm.Close() })

	// A real local socket standing in for the beacon, so the configured
	// beacon address is one nothing else can accidentally occupy.
	beaconSock := mustListenUDP(t)
	t.Cleanup(func() { beaconSock.Close() })
	beaconAddr := beaconSock.LocalAddr().(*net.UDPAddr)
	tm.SetBeaconAddr(beaconAddr.String())

	target := mustListenUDP(t)
	t.Cleanup(func() { target.Close() })

	return tm, beaconAddr, target
}

// TestAttackReplay_PunchReflectionFromForgedSources replays the forged
// punch command from every source an off-path attacker can actually
// choose: an unrelated host, the beacon's IP on a different port (the
// classic "close enough" bypass), and a different IP on the beacon's
// port. None may produce a packet at the reflection target.
func TestAttackReplay_PunchReflectionFromForgedSources(t *testing.T) {
	t.Parallel()
	tm, beaconAddr, target := newReflectionRig(t)
	targetAddr := target.LocalAddr().(*net.UDPAddr)

	sources := map[string]*net.UDPAddr{
		"unrelated_host":       {IP: net.ParseIP("127.0.0.1"), Port: 6666},
		"beacon_ip_wrong_port": {IP: beaconAddr.IP, Port: beaconAddr.Port + 1},
		"beacon_port_other_ip": {IP: net.ParseIP("127.0.0.2"), Port: beaconAddr.Port},
		"port_zero":            {IP: beaconAddr.IP, Port: 0},
	}

	for name, src := range sources {
		tm.handleBeaconMessage(punchCommandFor(targetAddr), src)
		if got := drainCount(t, target, 200*time.Millisecond); got != 0 {
			t.Fatalf("ATTACK SUCCEEDED (%s): daemon reflected %d punch packets at an attacker-chosen target", name, got)
		}
	}
}

// TestAttackReplay_PunchReflectionEmitsWhenSourceIsTheBeacon is the
// control that proves the assertions above are meaningful: with the
// source set to the configured beacon endpoint, the daemon does emit
// punch packets. If this ever stops firing, the negative tests are
// vacuous.
func TestAttackReplay_PunchReflectionEmitsWhenSourceIsTheBeacon(t *testing.T) {
	t.Parallel()
	tm, beaconAddr, target := newReflectionRig(t)
	targetAddr := target.LocalAddr().(*net.UDPAddr)

	tm.handleBeaconMessage(punchCommandFor(targetAddr), beaconAddr)

	if got := drainCount(t, target, 500*time.Millisecond); got == 0 {
		t.Fatal("control failed: no punch emitted even from the configured beacon — the negative tests above prove nothing")
	}
}

// TestAttackReplay_PunchReflectionAmplificationSpray is the volumetric
// form: a single forged source sprays punch commands to drive the
// daemon into flooding a third party. The reflector must stay silent no
// matter how many commands arrive.
func TestAttackReplay_PunchReflectionAmplificationSpray(t *testing.T) {
	t.Parallel()
	tm, _, target := newReflectionRig(t)
	targetAddr := target.LocalAddr().(*net.UDPAddr)

	data := punchCommandFor(targetAddr)
	spoofed := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7777}
	for i := 0; i < 256; i++ {
		tm.handleBeaconMessage(data, spoofed)
	}

	if got := drainCount(t, target, 500*time.Millisecond); got != 0 {
		t.Fatalf("ATTACK SUCCEEDED: 256 forged punch commands produced %d reflected packets", got)
	}
}

// TestAttackReplay_PunchReflectionWithNoBeaconConfigured covers the
// fail-closed case: a daemon that has not yet learned a beacon address
// must reject punch commands outright rather than treating "no beacon
// configured" as "anything goes".
func TestAttackReplay_PunchReflectionWithNoBeaconConfigured(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()

	target := mustListenUDP(t)
	defer target.Close()
	targetAddr := target.LocalAddr().(*net.UDPAddr)

	spoofed := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8888}
	tm.handleBeaconMessage(punchCommandFor(targetAddr), spoofed)
	tm.handleBeaconMessage(punchCommandFor(targetAddr), nil)

	if got := drainCount(t, target, 200*time.Millisecond); got != 0 {
		t.Fatalf("ATTACK SUCCEEDED: daemon with no beacon configured reflected %d punch packets", got)
	}
}

// TestAttackReplay_RelayDeliverInjectionFromForgedSource is the
// injection sibling: a forged BeaconMsgRelayDeliver naming an arbitrary
// srcNodeID must not reach the frame dispatcher and must not create peer
// or relay-peer state for a node ID the attacker invented.
func TestAttackReplay_RelayDeliverInjectionFromForgedSource(t *testing.T) {
	t.Parallel()
	tm, _, _ := newReflectionRig(t)

	const spoofedSrc = uint32(123456)
	data := append([]byte{protocol.BeaconMsgRelayDeliver}, plaintextRelayPayload(t, spoofedSrc, "injected")...)
	spoofed := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	tm.handleBeaconMessage(data, spoofed)

	tm.mu.RLock()
	_, peerExists := tm.peers[spoofedSrc]
	tm.mu.RUnlock()
	if peerExists {
		t.Fatalf("ATTACK SUCCEEDED: forged relay-deliver created peer state for node %d", spoofedSrc)
	}
	if tm.routing.IsRelayPeer(spoofedSrc) {
		t.Fatalf("ATTACK SUCCEEDED: forged relay-deliver marked node %d as a relay peer", spoofedSrc)
	}
}

// TestAttackReplay_MalformedPunchCommandFromBeacon checks the parser
// under the source gate: even from the legitimate beacon, a truncated or
// nonsense punch command must be dropped without panicking and without
// emitting anything.
func TestAttackReplay_MalformedPunchCommandFromBeacon(t *testing.T) {
	t.Parallel()
	tm, beaconAddr, target := newReflectionRig(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ATTACK SUCCEEDED: daemon panicked on a malformed punch command: %v", r)
		}
	}()

	payloads := [][]byte{
		{protocol.BeaconMsgPunchCommand},
		{protocol.BeaconMsgPunchCommand, 4},
		{protocol.BeaconMsgPunchCommand, 4, 1, 2},
		{protocol.BeaconMsgPunchCommand, 16, 1, 2, 3, 4},
		{protocol.BeaconMsgPunchCommand, 255, 1, 2, 3, 4, 5, 6},
		{protocol.BeaconMsgPunchCommand, 0},
		{protocol.BeaconMsgPunchCommand, 5, 1, 2, 3, 4, 5, 0, 80},
	}
	for _, p := range payloads {
		tm.handleBeaconMessage(p, beaconAddr)
	}

	if got := drainCount(t, target, 200*time.Millisecond); got != 0 {
		t.Fatalf("malformed punch commands produced %d packets at an unrelated socket", got)
	}
}

// TestAttackReplay_CompatModeDisablesPunchSourceCheck is a
// characterization test, not a pass/fail on an attack: handleBeaconMessage
// computes fromBeacon as `ForceRelay() || IsFromBeacon(from)`, so in
// compat mode (ConnectCompat sets ForceRelay) the source check is
// disabled entirely.
//
// This is not remotely reachable today — compat mode replaces the UDP
// socket with a WSS pipe that terminates at the beacon, so the only
// frames reaching this function already came from the beacon. It is
// pinned here so that any future change re-enabling a UDP read path
// alongside ForceRelay trips this test and gets re-reviewed.
func TestAttackReplay_CompatModeDisablesPunchSourceCheck(t *testing.T) {
	t.Parallel()
	tm, _, target := newReflectionRig(t)
	targetAddr := target.LocalAddr().(*net.UDPAddr)

	tm.routing.SetForceRelay(true)

	spoofed := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}
	tm.handleBeaconMessage(punchCommandFor(targetAddr), spoofed)

	got := drainCount(t, target, 500*time.Millisecond)
	if got == 0 {
		t.Log("ForceRelay no longer bypasses the punch-command source check — the gate was tightened; " +
			"update this characterization test")
		return
	}
	t.Logf("characterized: with ForceRelay set (compat mode) the punch-command source check is bypassed "+
		"and %d punch packets were emitted to a source-chosen target; reachable only over the "+
		"beacon-terminated WSS pipe today", got)
}
