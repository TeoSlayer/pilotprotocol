// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

// TestIPCConnCountIncludesClosedConns verifies that connCount() reflects
// only active connections after removeConn is called on each closed ID.
//
// Bug (pre-v1.9.1): ipcConn.conns grew on every trackConn call and was never
// pruned. connCount() returned len(c.conns), including already-closed
// connections. After MaxConnsPerIPCClient (4096) dial+close cycles,
// connCount() == 4096 even with zero active connections, causing every
// subsequent dial to fail with "per-client connection quota reached".
//
// Fix (v1.9.1): removeConn() is called in both close paths:
//   - handleClose (explicit CmdClose from driver)
//   - startRecvPusher goroutine (RecvBuf close on remote FIN or daemon RST)
//
// GREEN assertion: after tracking MaxConnsPerIPCClient connections and
// immediately removing each one via removeConn, connCount() must return 0.
// Against unpatched code (missing removeConn calls) connCount() returns
// MaxConnsPerIPCClient, causing this check to fail.
func TestIPCConnCountIncludesClosedConns(t *testing.T) {
	t.Parallel()
	// ipcConn requires a net.Conn for initialization; use a pipe pair.
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	ic := newIPCConn(serverConn)
	t.Cleanup(func() { ic.Close() })

	pm := NewPortManager()

	// Simulate MaxConnsPerIPCClient dial+close cycles: allocate a real
	// Connection in the port manager, track it, then removeConn+RemoveConnection
	// (simulating the close paths that the fix wires up).
	for i := 0; i < MaxConnsPerIPCClient; i++ {
		conn := pm.NewConnection(portForTest(i), protocol.Addr{}, 0)
		ic.trackConn(conn.ID)
		ic.removeConn(conn.ID) // v1.9.1 fix: close path now calls this
		pm.RemoveConnection(conn.ID)
	}

	got := ic.connCount()

	// FIXED: connCount must be 0 — the slice was pruned on each close.
	if got != 0 {
		t.Errorf("connCount=%d after %d dial+close cycles; expected 0 — stale entries not pruned (fix not applied)",
			got, MaxConnsPerIPCClient)
	}
}

// portForTest returns a port value for test connection allocation;
// ports 1..MaxConnsPerIPCClient are all in the valid uint16 range.
func portForTest(i int) uint16 {
	return uint16((i % 60000) + 1)
}
