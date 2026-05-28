// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

// ---------------------------------------------------------------------------
// addrFamilyMismatch with a real bound UDP tunnel
// ---------------------------------------------------------------------------

// newBoundDaemon binds a TunnelManager to the given address and registers it
// on a fresh Daemon. Caller closes via tm.Close() (returned).
func newBoundDaemon(t *testing.T, addr string) *Daemon {
	t.Helper()
	d := New(Config{})
	if err := d.tunnels.Listen(addr); err != nil {
		t.Fatalf("tunnel listen %s: %v", addr, err)
	}
	t.Cleanup(func() { d.tunnels.Close() })
	return d
}

func TestAddrFamilyMismatchIPv4BoundSameFamily(t *testing.T) {
	t.Parallel()
	d := newBoundDaemon(t, "127.0.0.1:0")
	if d.addrFamilyMismatch("192.0.2.1:5") {
		t.Error("IPv4 local + IPv4 remote should match (no mismatch)")
	}
}

func TestAddrFamilyMismatchIPv4BoundDifferentFamily(t *testing.T) {
	t.Parallel()
	d := newBoundDaemon(t, "127.0.0.1:0")
	if !d.addrFamilyMismatch("[::1]:5") {
		t.Error("IPv4 local + IPv6 remote should be a mismatch")
	}
}

func TestAddrFamilyMismatchIPv6BoundDifferentFamily(t *testing.T) {
	t.Parallel()
	d := newBoundDaemon(t, "[::1]:0")
	if !d.addrFamilyMismatch("127.0.0.1:5") {
		t.Error("IPv6 local + IPv4 remote should be a mismatch")
	}
}

func TestAddrFamilyMismatchWildcardLocalAlwaysFalse(t *testing.T) {
	t.Parallel()
	// 0.0.0.0 is IsUnspecified → early-returns false regardless of remote.
	d := newBoundDaemon(t, "0.0.0.0:0")
	if d.addrFamilyMismatch("[::1]:5") {
		t.Error("unspecified IPv4 local should always be compatible")
	}
	if d.addrFamilyMismatch("192.0.2.1:5") {
		t.Error("unspecified IPv4 local with IPv4 remote should match")
	}
}

func TestAddrFamilyMismatchBadRemoteReturnsFalse(t *testing.T) {
	t.Parallel()
	d := newBoundDaemon(t, "127.0.0.1:0")
	// No colon → SplitHostPort fails → branch returns false.
	if d.addrFamilyMismatch("no-port-here") {
		t.Error("unparseable remote should return false")
	}
}

func TestAddrFamilyMismatchNonIPRemoteReturnsFalse(t *testing.T) {
	t.Parallel()
	d := newBoundDaemon(t, "127.0.0.1:0")
	// Hostname (not IP literal) after SplitHostPort → ParseIP returns nil → false.
	if d.addrFamilyMismatch("example.com:5") {
		t.Error("non-IP host should return false")
	}
}

// ---------------------------------------------------------------------------
// portInUse — direct coverage of all state-check branches
// ---------------------------------------------------------------------------

func TestPortInUseNoConnections(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.portInUse(7000) {
		t.Error("empty PortManager should report no port in use")
	}
}

func TestPortInUseEstablishedMatchingPortTrue(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	c := pm.NewConnection(7001, protocol.Addr{}, 9000)
	c.State = StateEstablished

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if !pm.portInUse(7001) {
		t.Error("established connection on port 7001 should report in-use")
	}
}

func TestPortInUseNonMatchingPortFalse(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	c := pm.NewConnection(7002, protocol.Addr{}, 9000)
	c.State = StateEstablished

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.portInUse(7003) {
		t.Error("port 7003 should be free (conn is on 7002)")
	}
}

func TestPortInUseClosedStateIgnored(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	c := pm.NewConnection(7004, protocol.Addr{}, 9000)
	c.State = StateClosed // default already, but be explicit

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.portInUse(7004) {
		t.Error("closed connection should not hold the port")
	}
}

func TestPortInUseTimeWaitStateIgnored(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	c := pm.NewConnection(7005, protocol.Addr{}, 9000)
	c.State = StateTimeWait

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.portInUse(7005) {
		t.Error("TIME_WAIT connection should not hold the port")
	}
}

func TestPortInUseMixedConnectionsOnlyActiveWins(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	// One closed, one established — port only reports in-use because of the
	// established one; closed one is effectively invisible for alloc purposes.
	c1 := pm.NewConnection(7006, protocol.Addr{}, 9000)
	c1.State = StateClosed
	c2 := pm.NewConnection(7006, protocol.Addr{}, 9001)
	c2.State = StateEstablished

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if !pm.portInUse(7006) {
		t.Error("mixed closed+established on same port should report in-use")
	}
}
