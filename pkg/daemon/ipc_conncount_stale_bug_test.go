// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestIPCConnCountIncludesClosedConns reproduces the
// "connCount returns stale closed connections, exhausting per-client quota"
// bug.
//
// Symptom: ipcConn.conns is a slice of connection IDs that grows on every
// trackConn call but is never pruned. connCount() returns len(c.conns),
// which includes connections that have already been closed. After
// MaxConnsPerIPCClient (4096) dial+close cycles on a single IPC connection,
// connCount() == 4096 even with ZERO active connections. Every subsequent
// dial attempt from that client is rejected with a quota error:
//
//	"dial: per-client connection quota (4096) reached"
//
// Real-world impact: a long-lived IPC client (e.g., a gateway, a service
// proxy) that handles thousands of short-lived connections (HTTP request
// each opens a new overlay connection) hits the quota after MaxConnsPerIPCClient
// dials even though all prior connections are already closed. The client
// must close and reconnect the IPC socket to recover.
//
// What v1.9.1's fix should change: connCount() must return only ACTIVE
// (non-closed, non-TimeWait) connections. Closed connection IDs must be
// removed from ipcConn.conns when their overlay connection is closed —
// both on the explicit-close path (handleClose / CmdClose) and on the
// remote-close path (startRecvPusher detecting RecvBuf closure after FIN).
//
// This test pins the CURRENT (buggy) behavior: track MaxConnsPerIPCClient
// connection IDs, then remove all of them from the port manager (simulating
// close), and observe that connCount() still returns MaxConnsPerIPCClient.
// After GREEN the test is flipped: connCount() must reflect only active
// connections, returning 0 when all tracked connections are closed.
func TestIPCConnCountIncludesClosedConns(t *testing.T) {
	// ipcConn requires a net.Conn for initialization; use a pipe pair.
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	ic := newIPCConn(serverConn)
	t.Cleanup(func() { ic.Close() })

	pm := NewPortManager()

	// Simulate MaxConnsPerIPCClient dial+close cycles: for each cycle
	// we allocate a real Connection in the port manager, track it in
	// the ipcConn, then remove it (simulating the connection being closed
	// and cleaned up via RemoveConnection).
	for i := 0; i < MaxConnsPerIPCClient; i++ {
		conn := pm.NewConnection(portForTest(i), protocol.Addr{}, 0)
		ic.trackConn(conn.ID)
		pm.RemoveConnection(conn.ID) // simulate close
	}

	got := ic.connCount()

	// CURRENT (buggy) behavior: connCount returns MaxConnsPerIPCClient even
	// though every tracked connection was removed from the port manager.
	// The slice is never pruned, so len(c.conns) reflects all-time tracked
	// count, not current active count.
	if got != MaxConnsPerIPCClient {
		// Anything other than MaxConnsPerIPCClient means the specific
		// len(c.conns) overflow path wasn't reproduced.
		if got == 0 {
			t.Fatalf("BUG NOT REPRODUCED: connCount returned 0 (fix may be in place); GREEN flips this")
		}
		t.Fatalf("unexpected connCount %d (expected %d from stale slice)", got, MaxConnsPerIPCClient)
	}
	t.Logf("connCount=%d with 0 active connections — stale entries block new dials", got)
}

// portForTest returns a port value for test connection allocation;
// ports 1..MaxConnsPerIPCClient are all in the valid uint16 range.
func portForTest(i int) uint16 {
	return uint16((i % 60000) + 1)
}
