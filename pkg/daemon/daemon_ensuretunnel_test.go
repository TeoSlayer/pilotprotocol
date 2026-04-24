// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// --- ensureTunnel ---

func TestEnsureTunnelAlreadyHasPeerReturnsNilWithoutResolve(t *testing.T) {
	d := New(Config{})
	// regConn stays nil; if ensureTunnel reached resolve it would panic on d.regConn.Resolve.
	d.tunnels.AddPeer(42, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})

	if err := d.ensureTunnel(42); err != nil {
		t.Fatalf("ensureTunnel = %v, want nil for already-present peer", err)
	}
}

func TestEnsureTunnelResolveCacheHitAddsPeer(t *testing.T) {
	d := New(Config{})

	// Seed the resolve cache so Resolve() is skipped entirely.
	d.cacheResolve(7, map[string]interface{}{"real_addr": "127.0.0.1:55555"})

	if err := d.ensureTunnel(7); err != nil {
		t.Fatalf("ensureTunnel with cached resolve: %v", err)
	}
	if !d.tunnels.HasPeer(7) {
		t.Fatal("expected peer 7 to be added after cached resolve")
	}

	// Endpoint cache should be populated too (cacheEndpoint path).
	addr, ok := d.cachedEndpoint(7)
	if !ok || addr != "127.0.0.1:55555" {
		t.Fatalf("cachedEndpoint after ensureTunnel = (%q, %v), want (127.0.0.1:55555, true)", addr, ok)
	}
}

func TestEnsureTunnelResolveCacheHitMissingRealAddrErrors(t *testing.T) {
	d := New(Config{})
	d.cacheResolve(8, map[string]interface{}{"node_id": float64(8)}) // no real_addr key

	err := d.ensureTunnel(8)
	if err == nil {
		t.Fatal("expected error for response missing real_addr, got nil")
	}
	if !strings.Contains(err.Error(), "no real address") {
		t.Fatalf("error = %v, want 'no real address'", err)
	}
	if d.tunnels.HasPeer(8) {
		t.Fatal("peer must not be added on no-real_addr error")
	}
}

func TestEnsureTunnelResolveCacheHitEmptyRealAddrErrors(t *testing.T) {
	d := New(Config{})
	d.cacheResolve(9, map[string]interface{}{"real_addr": ""})

	err := d.ensureTunnel(9)
	if err == nil || !strings.Contains(err.Error(), "no real address") {
		t.Fatalf("err = %v, want 'no real address'", err)
	}
}

func TestEnsureTunnelRegistryFailsFallsBackToCachedEndpoint(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // closed client → Resolve errors

	d := New(Config{})
	d.regConn = rc

	// Prime the endpoint cache so the fallback branch activates.
	d.cacheEndpoint(123, "127.0.0.1:41414")

	if err := d.ensureTunnel(123); err != nil {
		t.Fatalf("ensureTunnel fallback path: %v", err)
	}
	if !d.tunnels.HasPeer(123) {
		t.Fatal("expected peer 123 to be added from cached endpoint fallback")
	}
}

func TestEnsureTunnelRegistryFailsNoCachedEndpointErrors(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // closed client → Resolve errors

	d := New(Config{})
	d.regConn = rc

	err := d.ensureTunnel(456)
	if err == nil {
		t.Fatal("expected error when registry fails and no cached endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "resolve node 456") {
		t.Fatalf("error = %v, want 'resolve node 456: ...'", err)
	}
	if d.tunnels.HasPeer(456) {
		t.Fatal("peer must not be added on error")
	}
}

func TestEnsureTunnelRegistryFailsCachedEndpointUnresolvableErrors(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close()

	d := New(Config{})
	d.regConn = rc

	// Invalid UDP address string — triggers net.ResolveUDPAddr error inside fallback.
	d.cacheEndpoint(321, "not a host:port")

	err := d.ensureTunnel(321)
	if err == nil {
		t.Fatal("expected error for malformed cached endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "resolve cached") {
		t.Fatalf("error = %v, want 'resolve cached ...'", err)
	}
}

func TestEnsureTunnelResolveCacheHitMalformedRealAddrErrors(t *testing.T) {
	d := New(Config{})
	d.cacheResolve(10, map[string]interface{}{"real_addr": "not a host:port"})

	err := d.ensureTunnel(10)
	if err == nil {
		t.Fatal("expected error for malformed real_addr, got nil")
	}
	if !strings.Contains(err.Error(), "resolve ") {
		t.Fatalf("error = %v, want 'resolve ...'", err)
	}
}

// --- DialConnection early-error paths ---

func TestDialConnectionEnsureTunnelFailurePropagates(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // closed client → Resolve errors

	d := New(Config{})
	d.regConn = rc

	dst := protocol.Addr{Network: 1, Node: 0xDEADBEEF}
	conn, err := d.DialConnection(dst, 80)
	if conn != nil {
		t.Fatalf("expected nil conn on ensureTunnel failure, got %+v", conn)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "resolve node") {
		t.Fatalf("err = %v, want 'resolve node ...'", err)
	}
}

func TestDialConnectionPortPolicyDenied(t *testing.T) {
	d := New(Config{})

	// Configure an explicit allowlist that does NOT include port 999 for network 5.
	d.netPolicyMu.Lock()
	d.netPolicies[5] = []uint16{80, 443}
	d.netPolicyMu.Unlock()

	dst := protocol.Addr{Network: 5, Node: 77}
	conn, err := d.DialConnection(dst, 999)
	if conn != nil {
		t.Fatalf("expected nil conn, got %+v", conn)
	}
	if err == nil {
		t.Fatal("expected port-policy denial error, got nil")
	}
	if !strings.Contains(err.Error(), "not allowed by network 5 policy") {
		t.Fatalf("err = %v, want 'not allowed by network 5 policy'", err)
	}
	// Tunnel must NOT have been touched on policy denial.
	if d.tunnels.HasPeer(77) {
		t.Fatal("policy-denied dial must not add tunnel peer")
	}
}

// Verify that when the policy allows the port but the port is outside the
// explicit allowlist set, the daemon still proceeds to ensureTunnel (and fails
// there, since we wired no registry). This guards against the two checks being
// merged/confused.
func TestDialConnectionAllowedPortStillHitsEnsureTunnel(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close() // make ensureTunnel fail quickly

	d := New(Config{})
	d.regConn = rc

	d.netPolicyMu.Lock()
	d.netPolicies[11] = []uint16{80}
	d.netPolicyMu.Unlock()

	dst := protocol.Addr{Network: 11, Node: 88}
	_, err := d.DialConnection(dst, 80)
	if err == nil {
		t.Fatal("expected ensureTunnel error (no regConn), got nil")
	}
	if strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("port 80 should be allowed, got policy denial: %v", err)
	}
}

// Regression: DialConnection must not block forever when ensureTunnel fails.
// Bound the total wall time; a previous refactor accidentally started the
// retry loop even on early error paths, which would hang.
func TestDialConnectionEnsureTunnelFailureBoundedLatency(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close()

	d := New(Config{})
	d.regConn = rc

	done := make(chan error, 1)
	go func() {
		_, err := d.DialConnection(protocol.Addr{Network: 2, Node: 5}, 22)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DialConnection hung on ensureTunnel failure")
	}
}

// Sanity: confirm Resolve on a closed client returns a non-nil error.
// All ensureTunnel fallback tests above depend on this.
func TestClosedRegistryClientReturnsErrorOnResolve(t *testing.T) {
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	rc.Close()

	if _, err := rc.Resolve(1, 2); err == nil {
		t.Fatal("expected error from closed registry client")
	}
}
