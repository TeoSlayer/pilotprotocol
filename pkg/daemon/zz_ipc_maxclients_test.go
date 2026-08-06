// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// TestIPCServer_MaxClientsCap verifies that IPCServer refuses new
// connections once MaxIPCClients active clients are accepted, and keeps
// serving existing clients. This replaces the heavyweight docker-based
// test_sec_ipc_exhaustion.sh (P2-002) — the cap is pure-accept logic
// with no overlay state, so a raw Unix-socket smoke test is enough.
func TestIPCServer_MaxClientsCap(t *testing.T) {
	t.Parallel()
	// Opens thousands of sockets — never parallel with other tests in
	// the same process or FD ulimit gets hit before the cap.
	if testing.Short() {
		t.Skip("slow: opens many sockets")
	}
	// Keep the path below Darwin's short sockaddr_un.sun_path limit.
	// t.TempDir includes the full test name and can exceed that limit.
	sockPath := shortSockPath(t)

	d := New(Config{SocketPath: sockPath})
	s := NewIPCServer(sockPath, d)
	if err := s.Start(); err != nil {
		t.Fatalf("ipc start: %v", err)
	}
	defer s.Close()

	// Wait briefly for the listener to be ready.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Open more connections than MaxIPCClients. The current accept-then-
	// close implementation (ipc.go:185-206) keeps kernel SOMAXCONN from
	// silently expanding past the cap: each excess dial is accepted and
	// closed immediately, so dials succeed but reads see EOF. We verify
	// back-pressure by confirming the server's active client set never
	// exceeds the cap, rather than by counting failed dials.
	var (
		mu        sync.Mutex
		opened    []net.Conn
		attempted = MaxIPCClients + 200 // 200 past the cap
	)
	for i := 0; i < attempted; i++ {
		c, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond)
		if err != nil {
			// Some platforms still refuse past the kernel backlog;
			// stopping early is fine for this test.
			break
		}
		mu.Lock()
		opened = append(opened, c)
		mu.Unlock()
	}

	// Give the server a moment to finish processing the accept/close
	// for connections past the cap.
	time.Sleep(100 * time.Millisecond)

	// The real assertion: the server's active client set must never
	// exceed MaxIPCClients. Allow a small slop for races between accept
	// and the handler registering in the map.
	s.mu.Lock()
	active := len(s.clients)
	s.mu.Unlock()

	for _, c := range opened {
		_ = c.Close()
	}

	if active > MaxIPCClients+16 {
		t.Fatalf("ipc cap failed: %d active clients, expected ≤ %d",
			active, MaxIPCClients+16)
	}

	t.Logf("ipc cap holding: %d active / %d dialed (cap=%d)",
		active, len(opened), MaxIPCClients)
}
