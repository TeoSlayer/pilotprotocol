// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestListenPortWarnOnBindFailure regression-tests the log level for a
// listener bind failure. Previously this was Debug, so running pilot-gateway
// unprivileged would silently not proxy any ports while still reporting
// "mapped IP → addr". The fix bumps the failure log to Warn.
func TestListenPortWarnOnBindFailure(t *testing.T) {
	// Occupy 127.0.0.1:<ephemeral> so the gateway's listenPort can't bind it.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer blocker.Close()

	blockedPort := uint16(blocker.Addr().(*net.TCPAddr).Port)

	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	gw, err := New(Config{Subnet: "127.0.0.0/16", Ports: []uint16{blockedPort}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	gw.listenPort(net.ParseIP("127.0.0.1"), blockedPort, protocol.Addr{Network: 1, Node: 99})

	out := buf.String()
	if !strings.Contains(out, "gateway listen failed") {
		t.Fatalf("expected warn log for failed bind, got: %q", out)
	}

	gw.mu.Lock()
	n := len(gw.listeners)
	gw.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected 0 listeners after failed bind, got %d", n)
	}
}
